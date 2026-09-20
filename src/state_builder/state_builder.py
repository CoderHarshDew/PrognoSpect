# state/state_builder.py

import pandas as pd

from src.state_builder.global_state import create_global_state
from src.state_builder.host_state import create_host_state
from src.state_builder.graph_state import create_graph_state
from src.state_builder.delta_state import calculate_delta


class StateBuilder:

    def __init__(self, window_size="1min"):

        self.window_size = window_size
        self.previous_state = None

    # DATA PREPARATION

    def prepare_data(self, df):

        df = df.copy()

        df.columns = (
            df.columns
            .str.strip()
            .str.lower()
            .str.replace(" ", "_")
        )

        df = df.rename(columns={

            "source_ip": "src_ip",
            "source_port": "src_port",

            "destination_ip": "dst_ip",
            "destination_port": "dst_port",

            "total_fwd_packets": "tot_fwd_pkts",
            "total_bwd_packets": "tot_bwd_pkts",

            "total_length_of_fwd_packets": "totlen_fwd_pkts",
            "total_length_of_bwd_packets": "totlen_bwd_pkts"

        })

        df["timestamp"] = pd.to_datetime(
            df["timestamp"],
            errors="coerce"
        )

        df = df.dropna(
            subset=["timestamp"]
        )

        df = df.sort_values(
            "timestamp"
        )

        return df

    # ONE STATE

    def build_state(self, window):

        global_state = create_global_state(
            window
        )

        host_state = create_host_state(
            window
        )

        graph_state = create_graph_state(
            window
        )

        current_state = {
            "global_state": global_state,
            "host_state": host_state,
            "graph_state": graph_state
        }

        delta_state = calculate_delta(
            current_state,
            self.previous_state
        )

        self.previous_state = current_state

        return {
            "X_t": global_state,
            "H_t": host_state,
            "G_t": graph_state,
            "delta_S_t": delta_state
        }

    # ALL STATES

    def build_all_states(self, df):

        # New dataset ke liye previous state reset
        self.previous_state = None

        df = self.prepare_data(
            df
        )

        df = df.set_index(
            "timestamp"
        )

        states = []

        # Dataset ko time windows mein divide karo
        for start_time, window in df.resample(
            self.window_size
        ):

            if window.empty:
                continue

            state = self.build_state(
                window
            )

            state["time"] = start_time

            states.append(
                state
            )

        return states