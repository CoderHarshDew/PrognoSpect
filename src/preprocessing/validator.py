import numpy as np
import pandas as pd
from src.core.evaluator import bind_var_and_evaluate, compile_expr
from src.preprocessing.result import SchemaResult, RuleResult
from src.core.logger import logger


def _build_column_group_index(feature_groups):
    col_to_group = {}

    for group_name, group_def in feature_groups.items():
        for col in group_def['features']:
            col_to_group[col] = group_name

    return col_to_group


def _validate_numeric_series(series, validation):
    sentinel = validation.get('sentinel', [])
    invalid = set()

    negative_count = 0
    inf_count = 0
    nan_count = 0

    if not validation['allow_negative']:
        negative_mask = (series < 0) & (~ series.isin(sentinel))
        invalid.update(np.flatnonzero(negative_mask))
        negative_count = int(negative_mask.sum())

    if not validation['allow_inf']:
        inf_mask = series.isin([np.inf, -np.inf])
        invalid.update(np.flatnonzero(inf_mask))
        inf_count = int(inf_mask.sum())

    if not validation['allow_nan']:
        nan_mask = series.isnull()
        invalid.update(np.flatnonzero(nan_mask))
        nan_count = int(nan_mask.sum())

    maximum = validation['maximum'] if validation['maximum'] is not None else np.inf

    out_of_range_mask = (~ series.between(validation['minimum'], maximum)) & (~ series.isin(sentinel))
    invalid.update(np.flatnonzero(out_of_range_mask))
    out_of_range_count = int(out_of_range_mask.sum())

    return invalid, negative_count, inf_count, nan_count, out_of_range_count


def _validate_non_numeric_series(df, col, col_def):
    validation = col_def.get('validation') or {}
    invalid = set()
    nan_count = 0

    if 'format' in col_def:
        parsed = pd.to_datetime(df[col], format=col_def['format'], errors='coerce')

        if not validation.get('allow_nan', True):
            nan_mask = parsed.isnull()
            invalid.update(np.flatnonzero(nan_mask))
            nan_count = int(nan_mask.sum())

        return invalid, nan_count

    if 'allow_nan' in validation and not validation['allow_nan']:
        nan_mask = df[col].isnull()
        invalid.update(np.flatnonzero(nan_mask))
        nan_count = int(nan_mask.sum())

    return invalid, nan_count


def validate_schema(df, schema_cfg):
    logger.info("Starting schema validation.")

    try:
        schema_result = SchemaResult()

        numeric_df = df.select_dtypes(include='number')
        col_to_group = _build_column_group_index(schema_cfg['feature_groups'])

        for col in numeric_df.columns:
            group_name = col_to_group.get(col)

            if group_name is None:
                logger.warning("Column '%s' is numeric but is not defined in any feature group; skipping.", col)
                continue

            validation = schema_cfg['feature_groups'][group_name]['template']['validation']

            invalid, negative_count, inf_count, nan_count, out_of_range_count = _validate_numeric_series(numeric_df[col], validation)

            schema_result.negative_count += negative_count
            schema_result.inf_count += inf_count
            schema_result.nan_count += nan_count
            schema_result.out_of_range_count += out_of_range_count
            schema_result.invalid[col] = invalid

            if len(invalid) > 0:
                logger.info("Schema '%s': Invalid Rows=%d | Negative=%d | NaN=%d | Inf=%d | OutOfRange=%d", col, len(invalid), negative_count, nan_count, inf_count, out_of_range_count)

        for col, col_def in schema_cfg.get('non_numeric_features', {}).items():
            invalid, nan_count = _validate_non_numeric_series(df, col, col_def)

            schema_result.nan_count += nan_count
            schema_result.invalid[col] = invalid

            if len(invalid) > 0:
                logger.info("Schema '%s': Invalid Rows=%d | NaN=%d", col, len(invalid), nan_count)

        logger.info("Schema validation completed. NaN=%d, Inf=%d, Negative=%d, OutOfRange=%d.", schema_result.nan_count, schema_result.inf_count, schema_result.negative_count, schema_result.out_of_range_count)

        return schema_result

    except Exception:
        logger.exception("Schema validation failed.")
        raise


def _resolve_rule_order(rules):
    rules_by_id = {rule['id']: rule for rule in rules}
    order = []
    visited = set()
    visiting = set()

    def visit(rule):
        rule_id = rule['id']

        if rule_id in visited:
            return

        if rule_id in visiting:
            raise ValueError(f"Circular dependency detected involving rule {rule_id}")

        visiting.add(rule_id)

        for dep_id in rule.get('depends_on', []):
            if dep_id not in rules_by_id:
                raise ValueError(f"Rule {rule_id} depends on unknown rule {dep_id}")

            visit(rules_by_id[dep_id])

        visiting.discard(rule_id)
        visited.add(rule_id)
        order.append(rule)

    for rule in rules:
        visit(rule)

    return order


def _evaluate_sentinel_rule(rule, context, index):
    sentinel_def = next(iter(rule['sentinel'].values()))

    condition_f = compile_expr(sentinel_def['expression'])
    applies = bind_var_and_evaluate(condition_f, **context)

    normal_f = compile_expr(rule['expression'])
    normal_valid = bind_var_and_evaluate(normal_f, **context)

    target_series = context[rule['target_column']]
    sentinel_valid = target_series == sentinel_def['value']

    valid = pd.Series(np.where(applies, sentinel_valid, normal_valid), index=index)

    return valid, None


def _evaluate_repair_rule(rule, context, working_df):
    repair_f = compile_expr(rule['repair_expression'])
    expected = bind_var_and_evaluate(repair_f, **context)
    expected = pd.Series(expected, index=working_df.index)

    tolerance = rule.get('tolerance', 0.0)
    actual = working_df[rule['target_column']]

    valid = pd.Series(np.isclose(actual, expected, atol=tolerance, equal_nan=False), index=working_df.index)

    return valid, expected


def _evaluate_standard_rule(rule, context):
    exp_f = compile_expr(rule['expression'])
    valid = bind_var_and_evaluate(exp_f, **context)

    return valid, None


def validate_rules(df, rules_cfg):
    logger.info("Starting rule validation.")

    try:
        rule_result = RuleResult()

        if not hasattr(rule_result, 'rows_to_drop'):
            rule_result.rows_to_drop = set()

        if not hasattr(rule_result, 'repairs'):
            rule_result.repairs = {}

        working_df = df.copy()
        ordered_rules = _resolve_rule_order(rules_cfg['rules'])

        for rule in ordered_rules:
            rule_result.violator_counts[rule['id']] = 0

            missing_columns = set(rule['columns']) - set(working_df.columns)

            if missing_columns:
                logger.error("Rule '%s' references missing columns: %s", rule['id'], missing_columns)
                raise ValueError(f"Rule {rule['id']} references missing columns: {missing_columns}")

            context = {column: working_df[column] for column in rule['columns']}

            if rule['id'] == 'R015':
                context['VALID_LABEL_SET'] = rules_cfg['VALID_LABEL_SET']

            if 'sentinel' in rule:
                valid, expected = _evaluate_sentinel_rule(rule, context, working_df.index)
            elif 'repair_expression' in rule:
                valid, expected = _evaluate_repair_rule(rule, context, working_df)
            else:
                valid, expected = _evaluate_standard_rule(rule, context)

            result = ~ valid

            violator_idx = set(np.flatnonzero(result))

            rule_result.violators[rule['id']] = violator_idx
            rule_result.violator_counts[rule['id']] = result.sum()

            if rule_result.violator_counts[rule['id']] > 0:
                logger.warning("Rule '%s' violated by %d rows. Columns=%s Expression='%s'", rule['id'], rule_result.violator_counts[rule['id']], rule['columns'], rule.get('expression') or rule.get('repair_expression'))

            scope = rule.get('scope', 'group')

            if scope == 'group' and violator_idx:
                rule_result.rows_to_drop.update(violator_idx)

            elif scope == 'column' and violator_idx:
                target_column = rule['target_column']
                idx_labels = working_df.index[list(violator_idx)]

                rule_result.repairs.setdefault(target_column, {})

                for pos, label in zip(violator_idx, idx_labels):
                    rule_result.repairs[target_column][pos] = expected.loc[label]

                working_df.loc[idx_labels, target_column] = expected.loc[idx_labels]

                logger.info("Rule '%s' repaired %d rows in column '%s'.", rule['id'], len(violator_idx), target_column)

        logger.info("Rule validation completed. Total rule violations: %d | Rows to drop: %d | Columns repaired: %d", sum(rule_result.violator_counts.values()), len(rule_result.rows_to_drop), len(rule_result.repairs))

        return rule_result

    except Exception:
        logger.exception("Rule validation failed.")
        raise


if __name__ == "__main__":
    pass