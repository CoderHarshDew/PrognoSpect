def create_host_state(window_df, config):
    cols = config["columns"]
    host_state = {}
    outgoing = window_df.groupby(cols["src_ip"])
    incoming = window_df.groupby(cols["dst_ip"])
    hosts = set(window_df[cols["src_ip"]]).union(set(window_df[cols["dst_ip"]]))
    for host in hosts:
        out_df = outgoing.get_group(host) if host in outgoing.groups else window_df.iloc[0:0]
        in_df = incoming.get_group(host) if host in incoming.groups else window_df.iloc[0:0]
        host_state[host] = {
            "outgoing_flow_count": len(out_df),
            "incoming_flow_count": len(in_df),
            "unique_destinations": out_df[cols["dst_ip"]].nunique(),
            "unique_sources": in_df[cols["src_ip"]].nunique(),
            "packets_sent": out_df[cols["fwd_packets"]].sum() + out_df[cols["bwd_packets"]].sum(),
            "packets_received": in_df[cols["fwd_packets"]].sum() + in_df[cols["bwd_packets"]].sum(),
            "bytes_sent": out_df[cols["fwd_bytes"]].sum() + out_df[cols["bwd_bytes"]].sum(),
            "bytes_received": in_df[cols["fwd_bytes"]].sum() + in_df[cols["bwd_bytes"]].sum(),
        }
    return host_state