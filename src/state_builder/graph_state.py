def create_graph_state(window_df, config):
    cols = config["columns"]
    nodes = list(set(window_df[cols["src_ip"]]).union(set(window_df[cols["dst_ip"]])))
    edges = {}
    grouped = window_df.groupby([cols["src_ip"], cols["dst_ip"]])
    for (src, dst), edge_df in grouped:
        edges[(src, dst)] = {
            "flow_count": len(edge_df),
            "total_packets": edge_df[cols["fwd_packets"]].sum() + edge_df[cols["bwd_packets"]].sum(),
            "total_bytes": edge_df[cols["fwd_bytes"]].sum() + edge_df[cols["bwd_bytes"]].sum(),
        }
    return {"nodes": nodes, "edges": edges}