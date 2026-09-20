# state/graph_state.py

def create_graph_state(window):

    edges = []

    # Same source-destination pairs ko group karo
    grouped = window.groupby(
        ["src_ip", "dst_ip"]
    )

    # Har communication pair ke liye edge banao
    for (source, destination), group in grouped:

        edge = {

            # Source node
            "source": source,

            # Destination node
            "destination": destination,

            # Is pair ke beech kitne flows hue
            "flow_count": len(group),

            # Total packets
            "total_packets": (
                group["tot_fwd_pkts"].sum()
                + group["tot_bwd_pkts"].sum()
            ),

            # Total bytes
            "total_bytes": (
                group["totlen_fwd_pkts"].sum()
                + group["totlen_bwd_pkts"].sum()
            )
        }

        edges.append(edge)

    return edges