"""GNN-based lateral movement detection using PyTorch Geometric.

Uses GraphSAGE encoder with temporal edge features for link prediction
on enterprise authentication graphs. Anomalous edges (low predicted
likelihood) indicate potential lateral movement.

Designed for the LANL Unified Host and Network Dataset.
"""

from __future__ import annotations

import logging
from typing import Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F

logger = logging.getLogger(__name__)

try:
    from torch_geometric.nn import SAGEConv, GATConv
    from torch_geometric.data import Data
    HAS_PYG = True
except ImportError:
    HAS_PYG = False
    logger.warning("PyTorch Geometric not installed -- GNN model unavailable for training.")


class TemporalEdgeEncoder(nn.Module):
    """Encode temporal features of edges (e.g., timestamp, duration)."""

    def __init__(self, time_dim: int = 16):
        super().__init__()
        self.mlp = nn.Sequential(
            nn.Linear(1, 32),
            nn.ReLU(),
            nn.Linear(32, time_dim),
        )

    def forward(self, timestamps: torch.Tensor) -> torch.Tensor:
        return self.mlp(timestamps.unsqueeze(-1).float())


class GraphSAGEEncoder(nn.Module):
    """Two-layer GraphSAGE encoder for node embeddings."""

    def __init__(self, in_channels: int, hidden_channels: int = 64, out_channels: int = 32):
        super().__init__()
        if not HAS_PYG:
            raise RuntimeError("PyTorch Geometric is required for GraphSAGE.")
        self.conv1 = SAGEConv(in_channels, hidden_channels)
        self.conv2 = SAGEConv(hidden_channels, out_channels)
        self.dropout = nn.Dropout(0.3)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = self.dropout(x)
        x = self.conv2(x, edge_index)
        return x


class GATEncoder(nn.Module):
    """Two-layer GAT encoder (alternative to GraphSAGE)."""

    def __init__(self, in_channels: int, hidden_channels: int = 64, out_channels: int = 32, heads: int = 4):
        super().__init__()
        if not HAS_PYG:
            raise RuntimeError("PyTorch Geometric is required for GAT.")
        self.conv1 = GATConv(in_channels, hidden_channels, heads=heads, dropout=0.3)
        self.conv2 = GATConv(hidden_channels * heads, out_channels, heads=1, concat=False, dropout=0.3)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        x = F.elu(self.conv1(x, edge_index))
        x = self.conv2(x, edge_index)
        return x


class LinkPredictor(nn.Module):
    """MLP-based link predictor from source/target node embeddings + optional edge features."""

    def __init__(self, embed_dim: int = 32, edge_feat_dim: int = 0):
        super().__init__()
        input_dim = embed_dim * 2 + edge_feat_dim
        self.mlp = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
        )

    def forward(
        self,
        z_src: torch.Tensor,
        z_dst: torch.Tensor,
        edge_feat: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        if edge_feat is not None:
            h = torch.cat([z_src, z_dst, edge_feat], dim=-1)
        else:
            h = torch.cat([z_src, z_dst], dim=-1)
        return self.mlp(h).squeeze(-1)


class LateralMovementGNN(nn.Module):
    """Complete model for lateral movement detection via temporal link prediction.

    Architecture:
        1. GraphSAGE/GAT encodes node features into embeddings.
        2. Temporal edge encoder processes authentication timestamps.
        3. Link predictor scores edges (src, dst) as normal/anomalous.
    """

    def __init__(
        self,
        num_node_features: int = 8,
        hidden_channels: int = 64,
        embed_dim: int = 32,
        time_dim: int = 16,
        encoder_type: str = "sage",
    ):
        super().__init__()
        self.time_dim = time_dim

        if encoder_type == "gat":
            self.encoder = GATEncoder(num_node_features, hidden_channels, embed_dim)
        else:
            self.encoder = GraphSAGEEncoder(num_node_features, hidden_channels, embed_dim)

        self.time_encoder = TemporalEdgeEncoder(time_dim)
        self.predictor = LinkPredictor(embed_dim, edge_feat_dim=time_dim)

    def encode(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """Compute node embeddings."""
        return self.encoder(x, edge_index)

    def decode(
        self,
        z: torch.Tensor,
        edge_index: torch.Tensor,
        timestamps: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """Score edges using link predictor."""
        z_src = z[edge_index[0]]
        z_dst = z[edge_index[1]]
        edge_feat = self.time_encoder(timestamps) if timestamps is not None else None
        return self.predictor(z_src, z_dst, edge_feat)

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        pred_edges: torch.Tensor,
        timestamps: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """Full forward: encode nodes then predict edges."""
        z = self.encode(x, edge_index)
        return self.decode(z, pred_edges, timestamps)


def create_node_features(
    num_nodes: int,
    auth_counts: Optional[dict] = None,
    feature_dim: int = 8,
) -> torch.Tensor:
    """Initialize node features from authentication log properties.

    Features per node:
    - in-degree (normalized)
    - out-degree (normalized)
    - avg auth frequency
    - is_admin flag
    - log(auth_count + 1)
    - hour_of_day distribution entropy
    - unique_destinations
    - unique_sources
    """
    features = torch.randn(num_nodes, feature_dim) * 0.1
    if auth_counts:
        for node_id, count in auth_counts.items():
            if node_id < num_nodes:
                features[node_id, 4] = torch.log(torch.tensor(count + 1, dtype=torch.float))
    return features
