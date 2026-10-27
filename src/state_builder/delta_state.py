import pandas as pd


def get_previous_part(previous_state, name):
    return None if previous_state is None else previous_state[name]


def get_global_delta(current_global, previous_global, fill_value):
    if previous_global is None:
        return {f"delta_{key}": fill_value for key in current_global}
    return {f"delta_{key}": value - previous_global[key] for key, value in current_global.items()}


def get_host_delta(current_host, previous_host, fill_value, pad_value):
    features = current_host["features"]
    if previous_host is None:
        return pd.DataFrame(fill_value, index=features.index, columns=features.columns).add_prefix("delta_")
    previous = previous_host["features"].reindex(features.index, fill_value=0.0)
    delta = (features - previous).add_prefix("delta_")
    is_padding = pd.Series(current_host["mask"], index=features.index) == 0
    delta.loc[is_padding] = pad_value
    return delta


def calculate_delta(current_state, previous_state, config):
    delta_config = config["delta_state"]
    if not delta_config["enabled"]:
        return {}
    fill_value = delta_config["first_window_fill"]
    delta = {}
    if "global" in delta_config["apply_to"]:
        delta["global"] = get_global_delta(current_state["global"], get_previous_part(previous_state, "global"), fill_value)
    if "host" in delta_config["apply_to"]:
        delta["host"] = get_host_delta(current_state["host"], get_previous_part(previous_state, "host"), fill_value, config["host_state"]["pad_value"])
    return delta