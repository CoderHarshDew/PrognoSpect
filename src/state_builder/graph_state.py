import numpy as np
import pandas as pd


def build_edge_table(window_df, config):
    columns = config["columns"]
    graph_config = config["graph_state"]
    grouped = window_df.groupby([columns["src_ip"], columns["dst_ip"]])
    flow_counts = grouped.size()
    sums = grouped[graph_config["edge_sum_columns"]].sum().add_prefix("sum_")
    means = grouped[graph_config["edge_mean_columns"]].mean().add_prefix("mean_")
    ratios = grouped[graph_config["edge_flag_ratio_columns"]].sum().div(flow_counts, axis=0).add_prefix("ratio_")
    parts = [sums, means, ratios]
    if graph_config["include_edge_flow_count"]:
        parts.insert(0, flow_counts.rename("flow_count").to_frame())
    return pd.concat(parts, axis=1)


def keep_edges_between_nodes(edge_table, nodes):
    src_in_nodes = edge_table.index.get_level_values(0).isin(nodes)
    dst_in_nodes = edge_table.index.get_level_values(1).isin(nodes)
    return edge_table[src_in_nodes & dst_in_nodes]


def fill_edge_tensor(edge_table, nodes, max_nodes, fill_value):
    node_index = {node: i for i, node in enumerate(nodes)}
    src_idx = edge_table.index.get_level_values(0).map(node_index).to_numpy(dtype=int)
    dst_idx = edge_table.index.get_level_values(1).map(node_index).to_numpy(dtype=int)
    edge_features = np.full((max_nodes, max_nodes, edge_table.shape[1]), fill_value, dtype=float)
    adjacency = np.zeros((max_nodes, max_nodes), dtype=float)
    edge_features[src_idx, dst_idx] = edge_table.to_numpy()
    adjacency[src_idx, dst_idx] = 1.0
    return edge_features, adjacency


def make_undirected(edge_features, adjacency):
    reverse_features = edge_features.transpose(1, 0, 2)
    missing = (adjacency == 0) & (adjacency.T == 1)
    edge_features = np.where(missing[:, :, None], reverse_features, edge_features)
    adjacency = np.maximum(adjacency, adjacency.T)
    return edge_features, adjacency


def create_graph_state(window_df, hosts, config):
    graph_config = config["graph_state"]
    max_nodes = graph_config["max_nodes"]
    nodes = hosts[:max_nodes]
    edge_table = keep_edges_between_nodes(build_edge_table(window_df, config), nodes)
    edge_features, adjacency = fill_edge_tensor(edge_table, nodes, max_nodes, config["cleaning"]["nan_fill_value"])
    if graph_config["make_undirected"]:
        edge_features, adjacency = make_undirected(edge_features, adjacency)
    return {"nodes": nodes, "adjacency": adjacency, "edge_features": edge_features, "edge_feature_names": list(edge_table.columns)}