import pandas as pd
import numpy as np


class TemporalStateBuilder:

    def __init__(self, window_seconds=10):
        self.window_seconds = window_seconds
        self.previous_global = None
        self.previous_hosts = None
        self.previous_edges = None

    def normalize_columns(self, df):
        df = df.copy()
        df.columns = df.columns.str.strip()
        return df

    def find_column(self, df, possible_names):
        columns_lower = {col.lower(): col for col in df.columns}

        for name in possible_names:
            if name.lower() in columns_lower:
                return columns_lower[name.lower()]

        return None

    def prepare_timestamp(self, df):
        timestamp_col = self.find_column(df, ["Timestamp", "timestamp", "Time", "time"])

        if timestamp_col is None:
            raise ValueError("Timestamp column not found.")

        df[timestamp_col] = pd.to_datetime(df[timestamp_col], errors="coerce")
        df = df.dropna(subset=[timestamp_col])
        df = df.sort_values(timestamp_col)

        return df, timestamp_col

    def build_global_features(self, window):
        features = {}
        features["total_flows"] = len(window)

        src_col = self.find_column(window, ["Src IP", "Source IP", "Source"])
        dst_col = self.find_column(window, ["Dst IP", "Destination IP", "Destination"])
        dst_port_col = self.find_column(window, ["Dst Port", "Destination Port"])

        if src_col:
            features["unique_src_ips"] = window[src_col].nunique()
        else:
            features["unique_src_ips"] = 0

        if dst_col:
            features["unique_dst_ips"] = window[dst_col].nunique()
        else:
            features["unique_dst_ips"] = 0

        if dst_port_col:
            features["unique_dst_ports"] = window[dst_port_col].nunique()
        else:
            features["unique_dst_ports"] = 0

        duration_col = self.find_column(window, ["Flow Duration", "flow duration"])

        if duration_col:
            features["mean_flow_duration"] = pd.to_numeric(window[duration_col], errors="coerce").mean()
        else:
            features["mean_flow_duration"] = 0.0

        for key in features:
            value = features[key]

            if pd.isna(value):
                features[key] = 0.0

        return features

    def build_host_features(self, window):
        src_col = self.find_column(window, ["Src IP", "Source IP", "Source"])
        dst_col = self.find_column(window, ["Dst IP", "Destination IP", "Destination"])

        if src_col is None:
            return {}

        host_features = {}

        for host, group in window.groupby(src_col):
            data = {}
            data["out_flows"] = len(group)

            if dst_col:
                data["unique_destinations"] = group[dst_col].nunique()
            else:
                data["unique_destinations"] = 0

            dst_port_col = self.find_column(group, ["Dst Port", "Destination Port"])

            if dst_port_col:
                data["unique_dst_ports"] = group[dst_port_col].nunique()
            else:
                data["unique_dst_ports"] = 0

            duration_col = self.find_column(group, ["Flow Duration"])

            if duration_col:
                data["mean_duration"] = pd.to_numeric(group[duration_col], errors="coerce").mean()
            else:
                data["mean_duration"] = 0.0

            for key in data:
                if pd.isna(data[key]):
                    data[key] = 0.0

            host_features[str(host)] = data

        return host_features

    def build_graph(self, window):
        src_col = self.find_column(window, ["Src IP", "Source IP", "Source"])
        dst_col = self.find_column(window, ["Dst IP", "Destination IP", "Destination"])

        if src_col is None or dst_col is None:
            return {}

        graph = {}
        grouped = window.groupby([src_col, dst_col])

        for (src, dst), group in grouped:
            edge_key = (str(src), str(dst))
            edge = {}
            edge["flow_count"] = len(group)

            duration_col = self.find_column(group, ["Flow Duration"])

            if duration_col:
                edge["mean_duration"] = pd.to_numeric(group[duration_col], errors="coerce").mean()
            else:
                edge["mean_duration"] = 0.0

            for key in edge:
                if pd.isna(edge[key]):
                    edge[key] = 0.0

            graph[edge_key] = edge

        return graph

    def compute_delta(self, current, previous):
        if previous is None:
            return {key: 0.0 for key in current}

        delta = {}

        for key in current:
            current_value = current.get(key, 0.0)
            previous_value = previous.get(key, 0.0)

            try:
                delta[key] = current_value - previous_value
            except TypeError:
                delta[key] = 0.0

        return delta

    def build_state(self, window_time, window):
        X_t = self.build_global_features(window)
        H_t = self.build_host_features(window)
        G_t = self.build_graph(window)

        Delta_t = self.compute_delta(X_t, self.previous_global)

        state = {
            "timestamp": window_time,
            "global_features": X_t,
            "host_features": H_t,
            "graph": G_t,
            "delta": Delta_t
        }

        self.previous_global = X_t
        self.previous_hosts = H_t
        self.previous_edges = G_t

        return state

    def build_states(self, df):
        df, timestamp_col = self.prepare_timestamp(df)

        df["window_time"] = df[timestamp_col].dt.floor(f"{self.window_seconds}s")

        states = []
        grouped = df.groupby("window_time")

        for window_time, window in grouped:
            state = self.build_state(window_time, window)
            states.append(state)

        return states