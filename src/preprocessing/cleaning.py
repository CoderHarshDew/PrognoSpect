import pandas as pd
from src.core.evaluator import bind_var_and_evaluate, compile_expr
from src.preprocessing.result import ValidationResult
from src.core.logger import logger


def initial_cleanup(df: pd.DataFrame, cleaning_cfg: dict):
    """Performs initial cleanup which includes:

    - Removing leading/trailing whitespaces.
    - Fixes unknown characters in the Labels.
    - Drops columns defined to drop.
    - Drops duplicate rows.
    - Resets index."""

    df.columns = df.columns.str.strip()
    df["Label"] = (
        df["Label"]
        .str.replace("\uFFFD", "-", regex=False)
    )
    df.drop_duplicates(inplace=True)
    df = df.reset_index(drop=True)

    df = df.drop(columns=cleaning_cfg['columns_to_drop'])

    logger.info('Performed initial cleanup on the dataset.')

    return df

def clean(validation_result: ValidationResult, df: pd.DataFrame, cleaning_cfg: dict) -> pd.DataFrame:
    """Cleans a DataFrame based on preprocessing result and a cleaning configuration.

    :param validation_result: Validation result of DataFrame, detailing invalid entries to clean.
    :param df: The DataFrame to clean.
    :param cleaning_cfg: The configuration file defining cleaning rules.
    :return: Cleaned DataFrame
    """

    df2 = df.drop(index=validation_result.non_repairable)
    logger.info('Dropped non repairable invalid data from the dataset.')

    for col in cleaning_cfg['repairable']:
        logger.info(f'Began computing repairable column {col} of Dataset.')
        formula = cleaning_cfg['formulas'][cleaning_cfg['repairable'][col]['formula']]

        missing_columns = set(formula['requires']) - set(df2.columns)

        if missing_columns:
            logger.error(f"Column {col} of dataset has following missing requirements: {missing_columns}")
            raise ValueError(f"Computing column: {col}\nRequires missing columns: {missing_columns}")

        expr = compile_expr(formula['expression'])

        context = {
            col: df2[col]
            for col in formula['requires']
        }

        rows = list(validation_result.repairable)

        result = bind_var_and_evaluate(expr, **context)
        df2.loc[rows, col] = result.loc[rows]

    return df2

if __name__ == "__main__":
    pass