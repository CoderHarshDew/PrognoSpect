# main.py

import os
import torch
import pandas as pd

from config import (
    DATASET_PATH,
    WINDOW_SECONDS,
    HIDDEN_DIM
)

from data_loader import (
    load_dataset,
    load_csv
)

from state_builder import (
    TemporalStateBuilder
)

from graph_encoder import (
    GraphEncoder
)


# MAIN

def main():

    print("\n")
    print("=" * 70)
    print("SIH 2026 - TEMPORAL STATE + GRAPH REPRESENTATION")
    print("=" * 70)


    # STEP 1: Find dataset files

    csv_files = load_dataset(
        DATASET_PATH
    )

    print(
        f"\nTotal CSV files found: "
        f"{len(csv_files)}"
    )


    # STEP 2: Load first CSV

    # IMPORTANT:
    # Initial testing ke liye sirf first file.
    #
    # Poora CICIDS2018 ek saath RAM mein load
    # nahi karna.

    first_file = csv_files[0]

    print("\n")
    print("=" * 70)
    print("LOADING FIRST FILE")
    print("=" * 70)

    df = load_csv(
        first_file
    )


    # STEP 3: Show dataset information

    print("\nDataset shape:")
    print(df.shape)

    print("\nColumns:")
    print(
        list(df.columns)
    )


    # STEP 4: Build temporal states

    print("\n")
    print("=" * 70)
    print("BUILDING TEMPORAL STATES")
    print("=" * 70)


    state_builder = TemporalStateBuilder(
        window_seconds=WINDOW_SECONDS
    )


    states = state_builder.build_states(
        df
    )


    print(
        f"\nTotal temporal states: "
        f"{len(states)}"
    )


    # STEP 5: Inspect first state

    if not states:

        print(
            "No temporal states generated."
        )

        return


    first_state = states[0]


    print("\n")
    print("=" * 70)
    print("FIRST TEMPORAL STATE")
    print("=" * 70)


    print(
        "\nTimestamp:"
    )

    print(
        first_state["timestamp"]
    )


    print(
        "\nGlobal Features X_t:"
    )

    for key, value in (
        first_state[
            "global_features"
        ].items()
    ):

        print(
            f"  {key}: {value}"
        )


    print(
        "\nNumber of Hosts H_t:"
    )

    print(
        len(
            first_state[
                "host_features"
            ]
        )
    )


    print(
        "\nNumber of Graph Edges G_t:"
    )

    print(
        len(
            first_state[
                "graph"
            ]
        )
    )


    print(
        "\nDelta S_t:"
    )

    for key, value in (
        first_state[
            "delta"
        ].items()
    ):

        print(
            f"  Δ{key}: {value}"
        )


    # STEP 6: Inspect graph

    print("\n")
    print("=" * 70)
    print("GRAPH EDGES")
    print("=" * 70)


    for i, (
        edge,
        features
    ) in enumerate(
        first_state[
            "graph"
        ].items()
    ):

        print(
            f"{edge[0]} -> {edge[1]}"
        )

        print(
            f"    {features}"
        )

        if i >= 9:

            break


    # ----------------------------------
    # STEP 7
    # Graph Encoder
    #
    # Initial stage:
    # demonstrate graph representation.
    # ----------------------------------

    print("\n")
    print("=" * 70)
    print("GRAPH ENCODER")
    print("=" * 70)


    graph = first_state[
        "graph"
    ]

    hosts = first_state[
        "host_features"
    ]


    if len(hosts) < 1:

        print(
            "No host features available."
        )

        return


    # Node feature preparation

    node_feature_names = [
        "out_flows",
        "unique_destinations",
        "unique_dst_ports",
        "mean_duration"
    ]


    node_features = []

    node_names = list(
        hosts.keys()
    )


    for host in node_names:

        feature_vector = []

        for feature_name in (
            node_feature_names
        ):

            value = hosts[
                host
            ].get(
                feature_name,
                0.0
            )

            feature_vector.append(
                float(value)
            )

        node_features.append(
            feature_vector
        )


    x = torch.tensor(
        node_features,
        dtype=torch.float32
    )


    # Node name → index

    node_to_index = {

        host: i

        for i, host in enumerate(
            node_names
        )
    }


    # Edge preparation

    edge_list = []
    edge_features = []


    for (
        (src, dst),
        features
    ) in graph.items():

        # Sirf wahi nodes rakho
        # jo H_t mein available hain

        if (
            src not in node_to_index
            or dst not in node_to_index
        ):

            continue


        src_index = (
            node_to_index[src]
        )

        dst_index = (
            node_to_index[dst]
        )


        edge_list.append(
            [
                src_index,
                dst_index
            ]
        )


        edge_features.append(
            [
                float(
                    features.get(
                        "flow_count",
                        0.0
                    )
                ),

                float(
                    features.get(
                        "mean_duration",
                        0.0
                    )
                )
            ]
        )


    if not edge_list:

        print(
            "No valid graph edges."
        )

        return


    # PyTorch Geometric format

    edge_index = torch.tensor(
        edge_list,
        dtype=torch.long
    ).t().contiguous()


    edge_attr = torch.tensor(
        edge_features,
        dtype=torch.float32
    )


    print(
        "\nNode feature shape:"
    )

    print(
        x.shape
    )


    print(
        "\nEdge index shape:"
    )

    print(
        edge_index.shape
    )


    print(
        "\nEdge feature shape:"
    )

    print(
        edge_attr.shape
    )


    # STEP 8: Graph Encoder

    node_dim = x.shape[1]

    edge_dim = edge_attr.shape[1]


    encoder = GraphEncoder(

        node_dim=node_dim,

        edge_dim=edge_dim,

        hidden_dim=HIDDEN_DIM
    )


    # Forward pass

    node_latent, edge_latent = (
        encoder(
            x,
            edge_index,
            edge_attr
        )
    )


    # STEP 9: Results

    print("\n")
    print("=" * 70)
    print("GRAPH ENCODER OUTPUT")
    print("=" * 70)


    print(
        "\nLatent Node Representation:"
    )

    print(
        node_latent.shape
    )


    print(
        "\nLatent Edge Representation:"
    )

    print(
        edge_latent.shape
    )


    print("\nExample node latent:")

    print(
        node_latent[0]
    )


    print("\nExample edge latent:")

    print(
        edge_latent[0]
    )


    print("\n")
    print("=" * 70)
    print("SUCCESS")
    print("=" * 70)

    print(
        "\nS_t = [X_t, H_t, G_t, ΔS_t]"
    )

    print(
        "Graph → latent node representation"
    )

    print(
        "Graph → latent edge representation"
    )

    print(
        "\nNo graph-to-one-vector compression."
    )


# ENTRY POINT

if __name__ == "__main__":

    main()