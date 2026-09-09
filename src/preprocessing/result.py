

class SchemaResult:

    def __init__(self):

        self.invalid = dict()
        self.nan_count = 0
        self.negative_count = 0
        self.inf_count = 0
        self.out_of_range_count = 0


    def __str__(self):
        return f"Schema Validation Result\n-----------------\nNaN:  {self.nan_count}\nInf:  {self.inf_count}\nNegative:  {self.negative_count}\nOut of range values:  {self.out_of_range_count}\n-----------------\nNOTE: These are number of cell values not rows."


class RuleResult:

    def __init__(self):

        self.violators = dict()
        self.violator_counts = dict()

    def __str__(self):
        res = ""
        for rule in  self.violators:
            res += f"{rule}: {self.violator_counts[rule]}\n"

        return res


class ValidationResult:

    def __init__(self, schema_result: SchemaResult, rule_result: RuleResult, cleaning_cfg: dict, rules_cfg: dict):

        self.repairable = set()
        self.non_repairable = set()
        self.repairable_count = None
        self.non_repairable_count  = None

        self.nan_count = schema_result.nan_count
        self.negative_count = schema_result.negative_count
        self.inf_count = schema_result.inf_count
        self.out_of_range_count = schema_result.out_of_range_count

        self.violator_counts = rule_result.violator_counts

        self._categorize(schema_result, rule_result, cleaning_cfg, rules_cfg)

    def _categorize(self, schema_result: SchemaResult, rule_result: RuleResult, cleaning_cfg: dict, rules_cfg: dict):
        """Categorizes invalid rows as repairable and non-repairable."""

        r = set()
        t = set()

        for col in  cleaning_cfg['repairable']:
            r.update(schema_result.invalid[col])

        for col in set(cleaning_cfg['non_repairable']) - set(cleaning_cfg['columns_to_drop']):

            t.update(schema_result.invalid[col])

        for rule in rules_cfg['non_repairable_column_related_rules']:
            t.update(rule_result.violators[rule])

        if rules_cfg['repairable_column_related_rules'] is not None:
            for rule in rules_cfg['repairable_column_related_rules']:
                r.update(rule_result.violators[rule])

        self.repairable = r - t
        self.non_repairable = t

        self.repairable_count = len(self.repairable)
        self.non_repairable_count = len(self.non_repairable)

    def __str__(self):
        res = "Validation Result\n"
        res += "----------------------\n"
        res += f"Repairable: {self.repairable_count}\n"
        res += f"Non-repairable: {self.non_repairable_count}\n"
        res += f"NaN*: {self.nan_count}\n"
        res += f"Inf*: {self.inf_count}\n"
        res += f"Negative*: {self.negative_count}\n"
        res += f"Out Of range*: {self.out_of_range_count}\n"
        res += f"Rule violators: {self.violator_counts}\n"
        res += "----------------------\n"
        res += "NOTE: those marked with * are showing individual cell value count, not row.\n"
        res += "Just so you know, a single row can have multiple NaN, Inf, Negative etc. values."

        return res


if __name__ == "__main__":
    pass