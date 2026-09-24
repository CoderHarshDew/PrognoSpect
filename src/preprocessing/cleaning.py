import pandas as pd
from src.core.evaluator import bind_var_and_evaluate, compile_expr
from src.preprocessing.result import ValidationResult
from src.core.logger import logger


def initial_cleanup(df: pd.DataFrame, cleaning_cfg: dict, schema_cfg: dict):
    """Performs initial cleanup which includes:

    - Removing leading/trailing whitespaces.
    - Fixes unknown characters in the Labels.
    - Drops columns defined to drop.
    - Drops duplicate rows.
    - Resets index."""

    input_rows = len(df)

    logger.info("Starting initial cleanup. Rows: %d | Columns: %d", input_rows, len(df.columns))

    df.columns = df.columns.str.strip()

    rows_before_dedup = len(df)
    df.drop_duplicates(inplace=True)

    logger.debug("Dropped %d duplicate row(s).", rows_before_dedup - len(df))

    df = df.drop(columns=cleaning_cfg['columns_to_drop'])

    logger.debug("Dropped %d configured column(s): %s", len(cleaning_cfg['columns_to_drop']), cleaning_cfg['columns_to_drop'])

    header = df.columns

    header_rows = (df.astype(str) == header).all(axis=1)

    rows_before_header_drop = len(df)
    df = df.loc[~header_rows].copy()

    logger.debug("Dropped %d embedded header row(s).", rows_before_header_drop - len(df))

    non_numeric_cols = schema_cfg['non_numeric_col']

    feature_cols = df.columns.drop(non_numeric_cols)

    df[feature_cols] = df[feature_cols].apply(
        pd.to_numeric,
        errors="coerce"
    )

    df = df.reset_index(drop=True)

    logger.info("Performed initial cleanup on the dataset. Rows: %d -> %d | Columns: %d", input_rows, len(df), len(df.columns))

    return df

def clean(validation_result: ValidationResult, df: pd.DataFrame, cleaning_cfg: dict) -> pd.DataFrame:
    """Cleans a DataFrame based on preprocessing result and a cleaning configuration.

    :param validation_result: Validation result of DataFrame, detailing invalid entries to clean.
    :param df: The DataFrame to clean.
    :param cleaning_cfg: The configuration file defining cleaning rules.
    :return: Cleaned DataFrame
    """

    logger.info("Starting clean. Input rows: %d | Repairable column(s): %d", len(df), len(cleaning_cfg['repairable']))

    df2 = df.drop(index=validation_result.non_repairable)
    logger.info('Dropped non repairable invalid data from the dataset.')

    for col in cleaning_cfg['repairable']:
        logger.debug("Began computing repairable column %s of Dataset.", col)
        formula = cleaning_cfg['formulas'][cleaning_cfg['repairable'][col]['formula']]

        missing_columns = set(formula['requires']) - set(df2.columns)

        if missing_columns:
            logger.error("Column %s of dataset has following missing requirements: %s", col, missing_columns)
            raise ValueError(f"Computing column: {col}\nRequires missing columns: {missing_columns}")

        expr = compile_expr(formula['expression'])

        context = {
            col: df2[col]
            for col in formula['requires']
        }

        rows = list(validation_result.repairable)

        result = bind_var_and_evaluate(expr, **context)
        df2.loc[rows, col] = result.loc[rows]

        logger.debug("Repaired %d row(s) in column %s.", len(rows), col)

    logger.info("Clean completed. Output rows: %d", len(df2))

    return df2

if __name__ == "__main__":
    pass