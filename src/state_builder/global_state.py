def create_global_state(window_df, config):
    cols = config["columns"]
    total_flows = len(window_df)
    unique_sources = window_df[cols["src_ip"]].nunique()
    unique_destinations = window_df[cols["dst_ip"]].nunique()
    total_packets = window_df[cols["fwd_packets"]].sum() + window_df[cols["bwd_packets"]].sum()
    total_bytes = window_df[cols["fwd_bytes"]].sum() + window_df[cols["bwd_bytes"]].sum()
    communication_pairs = window_df[[cols["src_ip"], cols["dst_ip"]]].drop_duplicates().shape[0]
    return {"total_flows": total_flows, "unique_sources": unique_sources, "unique_destinations": unique_destinations, "total_packets": total_packets, "total_bytes": total_bytes, "communication_pairs": communication_pairs}