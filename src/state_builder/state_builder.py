import numpy as np
import pandas as pd

from .global_state import create_global_state
from .host_state import create_host_state
from .graph_state import create_graph_state
from .delta_state import calculate_delta
from .label_builder import get_window_label


def get_numeric_columns(flows_df, config):
    columns = config["columns"]
    non_numeric = [columns["flow_id"], columns["src_ip"], columns["dst_ip"], columns["timestamp"], columns["label"]]
    return [col for col in flows_df.columns if col not in non_numeric]


def parse_timestamps(flows_df, config):
    timestamp_column = config["columns"]["timestamp"]
    timestamps = pd.to_datetime(flows_df[timestamp_column], format=config["window"]["timestamp_format"], errors="coerce")
    valid_flows = flows_df.assign(**{timestamp_column: timestamps}).dropna(subset=[timestamp_column]).copy()
    if valid_flows.empty:
        raise ValueError("No valid timestamps found, check window.timestamp_format in config")
    return valid_flows


def clean_numeric_columns(flows_df, config):
    numeric_columns = get_numeric_columns(flows_df, config)
    flows_df[numeric_columns] = flows_df[numeric_columns].apply(pd.to_numeric, errors="coerce")
    if config["cleaning"]["replace_inf_with_nan"]:
        flows_df[numeric_columns] = flows_df[numeric_columns].replace([np.inf, -np.inf], np.nan)
    flows_df[numeric_columns] = flows_df[numeric_columns].fillna(config["cleaning"]["nan_fill_value"])
    return flows_df


def add_window_start(flows_df, config):
    flows_df["window_start"] = flows_df[config["columns"]["timestamp"]].dt.floor(f"{config['window']['size_seconds']}s")
    return flows_df


def prepare_flows(flows_df, config):
    flows_df = parse_timestamps(flows_df, config)
    flows_df = clean_numeric_columns(flows_df, config)
    return add_window_start(flows_df, config)


def build_window(window_start, window_df, previous_state, config):
    features_df = window_df.drop(columns=[config["columns"]["label"]])
    state = {"global": create_global_state(features_df, config), "host": create_host_state(features_df, config)}
    state["graph"] = create_graph_state(features_df, state["host"]["hosts"], config)
    state["delta"] = calculate_delta(state, previous_state, config)
    return {"window_start": window_start, "state": state, "label": get_window_label(window_df, config)}


def build_states(flows_df, config):
    flows_df = prepare_flows(flows_df, config)
    results = []
    previous_state = None
    for window_start, window_df in flows_df.groupby("window_start"):
        result = build_window(window_start, window_df, previous_state, config)
        results.append(result)
        previous_state = result["state"]
    return results


def build_states_from_csv(csv_path, config):
    return build_states(pd.read_csv(csv_path, low_memory=False), config)