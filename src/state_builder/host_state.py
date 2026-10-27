import pandas as pd


def get_flow_counts(grouped, prefix):
    return grouped.size().rename(f"{prefix}_flow_count").to_frame()


def get_sum_features(grouped, columns, prefix):
    return grouped[columns].sum().add_prefix(f"{prefix}_sum_")


def get_mean_features(grouped, columns, prefix):
    return grouped[columns].mean().add_prefix(f"{prefix}_mean_")


def get_ratio_features(grouped, columns, flow_counts, prefix):
    return grouped[columns].sum().div(flow_counts, axis=0).add_prefix(f"{prefix}_ratio_")


def get_unique_features(grouped, host_config, peer_column, dst_port_column, prefix):
    features = pd.DataFrame(index=grouped.size().index)
    if host_config["unique_peer_count"]:
        features[f"{prefix}_unique_peers"] = grouped[peer_column].nunique()
    if host_config["unique_dst_port_count"]:
        features[f"{prefix}_unique_dst_ports"] = grouped[dst_port_column].nunique()
    return features


def get_direction_features(window_df, group_column, peer_column, prefix, config):
    host_config = config["host_state"]
    grouped = window_df.groupby(group_column)
    flow_counts = get_flow_counts(grouped, prefix)
    sums = get_sum_features(grouped, host_config["sum_columns"], prefix)
    means = get_mean_features(grouped, host_config["mean_columns"], prefix)
    ratios = get_ratio_features(grouped, host_config["flag_ratio_columns"], flow_counts[f"{prefix}_flow_count"], prefix)
    uniques = get_unique_features(grouped, host_config, peer_column, config["columns"]["dst_port"], prefix)
    return pd.concat([flow_counts, sums, means, ratios, uniques], axis=1)


def get_all_host_features(window_df, config):
    columns = config["columns"]
    out_features = get_direction_features(window_df, columns["src_ip"], columns["dst_ip"], "out", config)
    in_features = get_direction_features(window_df, columns["dst_ip"], columns["src_ip"], "in", config)
    return out_features.join(in_features, how="outer").fillna(config["cleaning"]["nan_fill_value"])


def get_host_score(features, select_top_by):
    return features[f"out_{select_top_by}"] + features[f"in_{select_top_by}"]


def select_top_hosts(features, max_hosts, select_top_by):
    features = features.sort_index()
    score = get_host_score(features, select_top_by)
    top_hosts = score.sort_values(ascending=False, kind="stable").head(max_hosts).index
    return features.loc[top_hosts]


def pad_hosts(features, max_hosts, pad_value):
    missing = max_hosts - len(features)
    if missing <= 0:
        return features
    padding = pd.DataFrame(pad_value, index=[f"pad_{i}" for i in range(missing)], columns=features.columns)
    return pd.concat([features, padding])


def create_host_state(window_df, config):
    host_config = config["host_state"]
    max_hosts = host_config["max_hosts"]
    features = get_all_host_features(window_df, config)
    top_features = select_top_hosts(features, max_hosts, host_config["select_top_by"])
    padded = pad_hosts(top_features, max_hosts, host_config["pad_value"])
    mask = [1.0] * len(top_features) + [0.0] * (max_hosts - len(top_features))
    return {"hosts": list(top_features.index), "features": padded, "mask": mask}