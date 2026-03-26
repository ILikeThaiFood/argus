"""Training script for GNN lateral movement detection.

Usage:
    python -m ml.lateral_movement.train \
        --auth-path data/raw/auth.txt \
        --output-dir ml/models \
        --epochs 100 --device cpu
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Tuple

import numpy as np
import torch
import torch.nn.functional as F
from sklearn.metrics import average_precision_score, roc_auc_score

from .gnn_model import LateralMovementGNN, create_node_features

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

try:
    from torch_geometric.data import Data
    from torch_geometric.utils import negative_sampling
    HAS_PYG = True
except ImportError:
    HAS_PYG = False


def load_lanl_auth(path: str, max_lines: int = 500_000) -> Tuple[np.ndarray, np.ndarray, np.ndarray, int]:
    """Load LANL authentication dataset.

    Expected format: time,src_user@src_host,dst_user@dst_host,auth_type,logon_type,status
    Returns: edge_index, timestamps, labels, num_nodes
    """
    logger.info("Loading LANL auth data from %s …", path)
    node_map: dict[str, int] = {}
    edges_src, edges_dst, times, labels = [], [], [], []

    with open(path) as f:
        for i, line in enumerate(f):
            if i >= max_lines:
                break
            parts = line.strip().split(",")
            if len(parts) < 4:
                continue
            t = int(parts[0])
            src = parts[1].split("@")[0] if "@" in parts[1] else parts[1]
            dst = parts[2].split("@")[0] if "@" in parts[2] else parts[2]

            if src not in node_map:
                node_map[src] = len(node_map)
            if dst not in node_map:
                node_map[dst] = len(node_map)

            edges_src.append(node_map[src])
            edges_dst.append(node_map[dst])
            times.append(t)
            label = 0 if len(parts) < 6 or parts[-1].strip().lower() in ("success", "logonsuccess", "") else 1
            labels.append(label)

    num_nodes = len(node_map)
    edge_index = np.array([edges_src, edges_dst], dtype=np.int64)
    timestamps = np.array(times, dtype=np.float64)
    labels = np.array(labels, dtype=np.int64)

    logger.info("Loaded %d edges, %d nodes, %.2f%% anomalous", len(labels), num_nodes, labels.mean() * 100)
    return edge_index, timestamps, labels, num_nodes


def generate_synthetic_graph(num_nodes: int = 500, num_edges: int = 5000) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Generate synthetic auth graph for demo purposes."""
    np.random.seed(42)
    src = np.random.randint(0, num_nodes, size=num_edges)
    dst = np.random.randint(0, num_nodes, size=num_edges)
    timestamps = np.sort(np.random.uniform(0, 86400 * 90, size=num_edges))
    labels = np.zeros(num_edges, dtype=np.int64)
    anomaly_idx = np.random.choice(num_edges, size=int(num_edges * 0.02), replace=False)
    labels[anomaly_idx] = 1
    edge_index = np.array([src, dst], dtype=np.int64)
    return edge_index, timestamps, labels


def train_epoch(model, optimizer, data, train_mask):
    model.train()
    optimizer.zero_grad()

    pos_edges = data.edge_index[:, train_mask]
    neg_edges = negative_sampling(data.edge_index, num_nodes=data.num_nodes, num_neg_samples=pos_edges.size(1))

    pos_scores = model(data.x, data.edge_index, pos_edges, data.edge_attr[train_mask] if data.edge_attr is not None else None)
    neg_scores = model(data.x, data.edge_index, neg_edges)

    pos_loss = F.binary_cross_entropy_with_logits(pos_scores, torch.ones_like(pos_scores))
    neg_loss = F.binary_cross_entropy_with_logits(neg_scores, torch.zeros_like(neg_scores))
    loss = pos_loss + neg_loss

    loss.backward()
    optimizer.step()
    return loss.item()


@torch.no_grad()
def evaluate(model, data, test_mask):
    model.eval()
    pos_edges = data.edge_index[:, test_mask]
    neg_edges = negative_sampling(data.edge_index, num_nodes=data.num_nodes, num_neg_samples=pos_edges.size(1))

    pos_scores = torch.sigmoid(model(data.x, data.edge_index, pos_edges)).cpu().numpy()
    neg_scores = torch.sigmoid(model(data.x, data.edge_index, neg_edges)).cpu().numpy()

    y_true = np.concatenate([np.ones(len(pos_scores)), np.zeros(len(neg_scores))])
    y_score = np.concatenate([pos_scores, neg_scores])

    ap = average_precision_score(y_true, y_score)
    auc = roc_auc_score(y_true, y_score)
    return ap, auc


def main():
    parser = argparse.ArgumentParser(description="Train ARGUS GNN lateral movement detector")
    parser.add_argument("--auth-path", type=str, help="Path to LANL auth.txt")
    parser.add_argument("--output-dir", type=str, default="ml/models")
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--lr", type=float, default=0.001)
    parser.add_argument("--device", type=str, default="cpu")
    parser.add_argument("--encoder", type=str, default="sage", choices=["sage", "gat"])
    args = parser.parse_args()

    if not HAS_PYG:
        logger.error("PyTorch Geometric is required. Install with: pip install torch-geometric")
        return

    # Load or generate data
    if args.auth_path and Path(args.auth_path).exists():
        edge_index, timestamps, labels, num_nodes = load_lanl_auth(args.auth_path)
    else:
        logger.info("No auth data found -- generating synthetic graph.")
        num_nodes = 500
        edge_index, timestamps, labels = generate_synthetic_graph(num_nodes)

    num_edges = edge_index.shape[1]
    node_features = create_node_features(num_nodes)

    # Temporal split: 80% train, 20% test
    split_idx = int(num_edges * 0.8)
    train_mask = torch.zeros(num_edges, dtype=torch.bool)
    train_mask[:split_idx] = True
    test_mask = ~train_mask

    # Build PyG data
    data = Data(
        x=node_features,
        edge_index=torch.tensor(edge_index, dtype=torch.long),
        edge_attr=torch.tensor(timestamps, dtype=torch.float),
        num_nodes=num_nodes,
    )
    data = data.to(args.device)
    train_mask = train_mask.to(args.device)
    test_mask = test_mask.to(args.device)

    model = LateralMovementGNN(
        num_node_features=node_features.shape[1],
        encoder_type=args.encoder,
    ).to(args.device)

    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)

    best_ap = 0.0
    for epoch in range(1, args.epochs + 1):
        loss = train_epoch(model, optimizer, data, train_mask)
        if epoch % 10 == 0 or epoch == 1:
            ap, auc = evaluate(model, data, test_mask)
            logger.info("Epoch %03d | Loss: %.4f | AP: %.4f | AUC: %.4f", epoch, loss, ap, auc)
            if ap > best_ap:
                best_ap = ap
                torch.save(model.state_dict(), Path(args.output_dir) / "gnn_lateral_movement.pt")

    logger.info("Best Average Precision: %.4f", best_ap)
    logger.info("Model saved to %s/gnn_lateral_movement.pt", args.output_dir)


if __name__ == "__main__":
    main()
