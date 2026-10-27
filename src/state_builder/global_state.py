def get_flow_count(window_df):
    return float(len(window_df))


def get_unique_counts(window_df, columns):
    return {f"unique_{col}": float(window_df[col].nunique()) for col in columns}


def get_protocol_distribution(window_df, protocol_column, protocol_values):
    ratios = window_df[protocol_column].value_counts(normalize=True)
    return {f"protocol_{value}_ratio": float(ratios.get(value, 0.0)) for value in protocol_values}


def get_stat_features(window_df, columns, stat_name, fill_value):
    values = getattr(window_df[columns], stat_name)().fillna(fill_value)
    return {f"{stat_name}_{col}": float(values[col]) for col in columns}


def create_global_state(window_df, config):
    global_config = config["global_state"]
    fill_value = config["cleaning"]["nan_fill_value"]
    state = {}
    if global_config["include_flow_count"]:
        state["flow_count"] = get_flow_count(window_df)
    state.update(get_unique_counts(window_df, global_config["unique_count_columns"]))
    state.update(get_protocol_distribution(window_df, config["columns"]["protocol"], global_config["protocol_values"]))
    for stat_name in ["sum", "mean", "std", "max"]:
        state.update(get_stat_features(window_df, global_config[f"{stat_name}_columns"], stat_name, fill_value))
    return state