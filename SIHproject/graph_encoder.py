# graph_encoder.py

import torch
import torch.nn as nn

from torch_geometric.nn import GINEConv


class GraphEncoder(nn.Module):

    def __init__(
        self,
        node_dim,
        edge_dim,
        hidden_dim=64
    ):

        super().__init__()

        # First GNN layer

        mlp1 = nn.Sequential(

            nn.Linear(
                node_dim,
                hidden_dim
            ),

            nn.ReLU(),

            nn.Linear(
                hidden_dim,
                hidden_dim
            )
        )

        self.conv1 = GINEConv(
            mlp1,
            edge_dim=edge_dim
        )


        # Second GNN layer

        mlp2 = nn.Sequential(

            nn.Linear(
                hidden_dim,
                hidden_dim
            ),

            nn.ReLU(),

            nn.Linear(
                hidden_dim,
                hidden_dim
            )
        )

        self.conv2 = GINEConv(
            mlp2,
            edge_dim=edge_dim
        )


    def forward(
        self,
        x,
        edge_index,
        edge_attr
    ):

        # Node representation

        x = self.conv1(
            x,
            edge_index,
            edge_attr
        )

        x = torch.relu(x)


        # Second layer

        x = self.conv2(
            x,
            edge_index,
            edge_attr
        )

        x = torch.relu(x)


        # Important:
        #
        # x = latent node representation
        #
        # edge_attr = edge representation
        #
        # We DO NOT convert graph
        # into one vector.

        return x, edge_attr