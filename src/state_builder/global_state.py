# state/global_state.py

def create_global_state(window):


    global_state = {

        # Is time window mein total flows
        "total_flows": len(window),

        # Kitne unique source IPs
        "unique_sources": window["src_ip"].nunique(),

        # Kitne unique destination IPs
        "unique_destinations": window["dst_ip"].nunique(),

        # Total packets
        "total_packets": (
            window["tot_fwd_pkts"].sum()
            + window["tot_bwd_pkts"].sum()
        ),

        # Total bytes
        "total_bytes": (
            window["totlen_fwd_pkts"].sum()
            + window["totlen_bwd_pkts"].sum()
        ),

        # Unique source-destination communication
        "communication_pairs": (
            window[["src_ip", "dst_ip"]]
            .drop_duplicates()
            .shape[0]
        )
    }

    return global_state