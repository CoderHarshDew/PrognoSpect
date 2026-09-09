# Imports
import numpy as np
import pandas as pd
from src.core.evaluator import bind_var_and_evaluate, compile_expr
from src.preprocessing.result import SchemaResult, RuleResult
from src.core.logger import logger


def validate_schema(df: pd.DataFrame, schema_cfg: dict) -> SchemaResult:
    """This function checks if the provided DataFrame is valid or not, and prints how many invalid values the DataFrame has per category.

    Example::

        -----------------\n
        Nan:  0\n
        Inf:  2775\n
        Negative:  2130864\n
        Out of range values:  2792151\n
        -----------------\n
        NOTE: These are number of cell values not rows

    Parameters:
        df (pd.DataFrame): The DataFrame to validate.
        schema_cfg (dict): The schema configuration file."""

    logger.info("Starting schema validation.")

    try:
        schema_result = SchemaResult()

        numeric_df = df.select_dtypes(include='number')

        for col in numeric_df.columns:
            for feature_grp in schema_cfg['feature_groups']:
                if col in schema_cfg['feature_groups'][feature_grp]['features']:

                    col_validation = schema_cfg['feature_groups'][feature_grp]['template']['validation']
                    invalid = set()

                    negative_count = 0
                    inf_count = 0
                    nan_count = 0
                    out_of_range_count = 0

                    if not col_validation['allow_negative']:
                        negative_mask = (numeric_df[col] < 0) & (~ numeric_df[col].isin(col_validation['sentinel']))
                        invalid.update(np.flatnonzero(negative_mask))

                        negative_count = negative_mask.sum()
                        schema_result.negative_count += negative_count

                    if not col_validation['allow_inf']:
                        inf_mask = numeric_df[col].isin([np.inf, -np.inf])
                        invalid.update(np.flatnonzero(inf_mask))

                        inf_count = inf_mask.sum()
                        schema_result.inf_count += inf_count

                    if not col_validation['allow_nan']:
                        nan_mask = numeric_df[col].isnull()
                        invalid.update(np.flatnonzero(nan_mask))

                        nan_count = nan_mask.sum()
                        schema_result.nan_count += nan_count

                    out_of_range_mask = (~ numeric_df[col].between(
                        col_validation['minimum'],
                        col_validation['maximum'] if col_validation['maximum'] is not None else np.inf
                    )) & (~numeric_df[col].isin(col_validation["sentinel"]))

                    invalid.update(np.flatnonzero(out_of_range_mask))

                    out_of_range_count = out_of_range_mask.sum()
                    schema_result.out_of_range_count += out_of_range_count

                    schema_result.invalid[col] = invalid

                    if len(invalid) > 0:
                        logger.info(
                            "Schema '%s': Invalid Rows=%d | Negative=%d | NaN=%d | Inf=%d | OutOfRange=%d",
                            col,
                            len(invalid),
                            negative_count,
                            nan_count,
                            inf_count,
                            out_of_range_count,
                        )

        port_validation = schema_cfg['features']['Destination Port']['validation']

        invalid_dp = set()

        negative_count = 0
        inf_count = 0
        nan_count = 0
        out_of_range_count = 0

        if not port_validation['allow_negative']:
            negative_dp_mask = (numeric_df['Destination Port'] < 0) & (~ numeric_df['Destination Port'].isin(port_validation['sentinel']))
            invalid_dp.update(np.flatnonzero(negative_dp_mask))

            negative_count = negative_dp_mask.sum()
            schema_result.negative_count += negative_count

        if not port_validation['allow_inf']:
            inf_dp_mask = numeric_df['Destination Port'].isin([np.inf, -np.inf])
            invalid_dp.update(np.flatnonzero(inf_dp_mask))

            inf_count = inf_dp_mask.sum()
            schema_result.inf_count += inf_count

        if not port_validation['allow_nan']:
            nan_dp_mask = numeric_df['Destination Port'].isnull()
            invalid_dp.update(np.flatnonzero(nan_dp_mask))

            nan_count = nan_dp_mask.sum()
            schema_result.nan_count += nan_count

        out_of_range_dp_mask = ~ numeric_df['Destination Port'].between(
            port_validation['minimum'],
            port_validation['maximum'] if port_validation['maximum'] is not None else np.inf
        )

        invalid_dp.update(np.flatnonzero(out_of_range_dp_mask))

        out_of_range_count = out_of_range_dp_mask.sum()
        schema_result.out_of_range_count += out_of_range_count

        schema_result.invalid['Destination Port'] = invalid_dp

        if len(invalid_dp) > 0:
            logger.info(
                "Schema 'Destination Port': Invalid Rows=%d | Negative=%d | NaN=%d | Inf=%d | OutOfRange=%d",
                len(invalid_dp),
                negative_count,
                nan_count,
                inf_count,
                out_of_range_count,
            )

        schema_result.invalid['Label'] = set()

        logger.info(
            "Schema validation completed. NaN=%d, Inf=%d, Negative=%d, OutOfRange=%d.",
            schema_result.nan_count,
            schema_result.inf_count,
            schema_result.negative_count,
            schema_result.out_of_range_count,
        )

        return schema_result

    except Exception:
        logger.exception("Schema validation failed.")
        raise

def validate_rules(df: pd.DataFrame, rules_cfg: dict) -> RuleResult:
    """This function checks if the provided DataFrame follows the right rules, counts numer of times a rule has been violated, and returns the value.

    Parameters:
        df (pd.DataFrame): The DataFrame to validate.
        rules_cfg (dict): The rules configuration file.

    Returns:
        Rule violation count as a dict"""

    logger.info("Starting rule validation.")

    try:
        rule_result = RuleResult()

        for rule in rules_cfg['rules']:
            rule_result.violator_counts[rule['id']] = 0

            missing_columns = set(rule['columns']) - set(df.columns)

            if missing_columns:
                logger.error(
                    "Rule '%s' references missing columns: %s",
                    rule['id'],
                    missing_columns
                )
                raise ValueError(
                    f"Rule {rule['id']} references missing columns: {missing_columns}"
                )

            exp_f = compile_expr(rule['expression'])

            context = {
                column: df[column]
                for column in rule['columns']
            }

            if rule['id'] == 'R019':
                context['VALID_LABEL_SET'] = rules_cfg['VALID_LABEL_SET']

            result = ~ bind_var_and_evaluate(exp_f, **context)

            rule_result.violators[rule['id']] = set(np.flatnonzero(result))
            rule_result.violator_counts[rule['id']] = result.sum()

            if rule_result.violator_counts[rule['id']] > 0:
                logger.warning(
                    "Rule '%s' violated by %d rows. Columns=%s Expression='%s'",
                    rule['id'],
                    rule_result.violator_counts[rule['id']],
                    rule['columns'],
                    rule['expression']
                )

        logger.info(
            "Rule validation completed. Total rule violations: %d",
            sum(rule_result.violator_counts.values())
        )

        return rule_result

    except Exception:
        logger.exception("Rule validation failed.")
        raise

if __name__ == "__main__":
    pass