# Imports

import pandas as pd
from src.core.logger import logger
from src.preprocessing.result import ValidationResult
from src.preprocessing.validator import validate_schema, validate_rules
from src.preprocessing.cleaning import clean


class PreprocessingPipeline:

    def __init__(self, schema_cfg: dict, rules_cfg: dict, cleaning_cfg: dict):
        """A class for preprocessing work."""
        self.schema_cfg = schema_cfg
        self.rules_cfg = rules_cfg
        self.cleaning_cfg = cleaning_cfg

        self.schema_result = dict()
        self.rules_result = dict()
        self.validation_result = dict()

        logger.info('Initialized preprocessing pipeline.')

    def validate(self, df: pd.DataFrame):
        """Perform complete  validation of the dataset, rule based and schema based, store all results."""

        self.schema_result[f"schema_result_{len(self.schema_result) + 1}"] = validate_schema(df, self.schema_cfg)

        self.rules_result[f'rules_result_{len(self.rules_result) + 1}'] = validate_rules(df, self.rules_cfg)

        self.validation_result[f"validation_result_{len(self.validation_result) + 1}"] = ValidationResult(
            self.schema_result[f"schema_result_{len(self.schema_result)}"],
            self.rules_result[f"rules_result_{len(self.rules_result)}"],
            self.cleaning_cfg,
            self.rules_cfg
        )
        logger.info('Combined the result of schema and rule based validations.')

        return self.validation_result[f"validation_result_{len(self.validation_result)}"], self.rules_result[f'rules_result_{len(self.rules_result)}'], self.schema_result[f"schema_result_{len(self.schema_result)}"]

    def clean(self, df: pd.DataFrame):
        df_cleaned = clean(self.validation_result[f"validation_result_{len(self.validation_result)}"], df, self.cleaning_cfg)
        logger.info('Cleaned the dataset.')
        return df_cleaned
