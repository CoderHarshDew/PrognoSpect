# state/host_state.py

def create_host_state(window):

    host_states = {}

    # Source aur destination dono ko host maana jayega
    hosts = set(window["src_ip"]).union(
        set(window["dst_ip"])
    )

    # Har host ka behaviour calculate karo
    for host in hosts:

        # Host se bahar jaane wala traffic
        outgoing = window[
            window["src_ip"] == host
        ]

        # Host par aane wala traffic
        incoming = window[
            window["dst_ip"] == host
        ]

        host_states[host] = {

            # Outgoing traffic
            "outgoing_flows": len(outgoing),

            # Incoming traffic
            "incoming_flows": len(incoming),

            # Host kitne different destinations se communicate kar raha hai
            "unique_destinations":
                outgoing["dst_ip"].nunique(),

            # Kitne different sources se traffic aa raha hai
            "unique_sources":
                incoming["src_ip"].nunique(),

            # Packets sent
            "packets_sent":
                outgoing["tot_fwd_pkts"].sum(),

            # Packets received
            "packets_received":
                incoming["tot_bwd_pkts"].sum(),

            # Bytes sent
            "bytes_sent":
                outgoing["totlen_fwd_pkts"].sum(),

            # Bytes received
            "bytes_received":
                incoming["totlen_bwd_pkts"].sum()
        }

    return host_states