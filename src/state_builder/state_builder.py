import pandas as pd
from src.state_builder.global_state import create_global_state
from src.state_builder.host_state import create_host_state
from src.state_builder.graph_state import create_graph_state
from src.state_builder.label_builder import get_window_label
from src.state_builder.delta_state import calculate_delta

def build_states(df, config):
    cols = config["columns"]
    df[cols["timestamp"]] = pd.to_datetime(df[cols["timestamp"]])
    df = df.sort_values(cols["timestamp"])
    df["_window"] = df[cols["timestamp"]].dt.floor(config["window"]["size"])
    states = []
    previous_state = None
    for window_time, window_df in df.groupby("_window"):
        current_state = {"global": create_global_state(window_df, config), "host": create_host_state(window_df, config), "graph": create_graph_state(window_df, config)}
        delta = calculate_delta(current_state, previous_state, config)
        label = get_window_label(window_df, config)
        states.append({"window_time": window_time, "state": current_state, "delta": delta, "label": label})
        previous_state = current_state
    return states