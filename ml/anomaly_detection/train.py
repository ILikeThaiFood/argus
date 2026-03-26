"""Training script for the hybrid anomaly detection pipeline.

Usage:
    python -m ml.anomaly_detection.train \
        --cicids-path data/raw/CICIDS2017.csv \
        --unsw-path data/raw/UNSW-NB15.csv \
        --output-dir ml/models \
        --epochs 50 --device cpu
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from .ensemble import AnomalyDetectionEnsemble, NETWORK_FLOW_FEATURES
from .lstm_autoencoder import TrainConfig

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def _load_cicids(path: str) -> tuple[np.ndarray, np.ndarray]:
    """Load and preprocess CICIDS2017 dataset."""
    logger.info("Loading CICIDS2017 from %s …", path)
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()

    label_col = "Label" if "Label" in df.columns else df.columns[-1]
    df["is_attack"] = (df[label_col].str.strip() != "BENIGN").astype(int)

    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if "is_attack" in numeric_cols:
        numeric_cols.remove("is_attack")

    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan).fillna(0)

    X = df[numeric_cols].values.astype(np.float32)
    y = df["is_attack"].values.astype(int)
    logger.info("CICIDS2017: %d samples, %d features, attack ratio %.2f%%",
                len(y), X.shape[1], y.mean() * 100)
    return X, y


def _load_unsw(path: str) -> tuple[np.ndarray, np.ndarray]:
    """Load and preprocess UNSW-NB15 dataset."""
    logger.info("Loading UNSW-NB15 from %s …", path)
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()

    label_col = "label" if "label" in df.columns else "Label"
    y = df[label_col].values.astype(int) if label_col in df.columns else np.zeros(len(df), dtype=int)

    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    for col in [label_col, "id"]:
        if col in numeric_cols:
            numeric_cols.remove(col)

    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan).fillna(0)

    X = df[numeric_cols].values.astype(np.float32)
    logger.info("UNSW-NB15: %d samples, %d features, attack ratio %.2f%%",
                len(y), X.shape[1], y.mean() * 100)
    return X, y


def _harmonize_features(X1: np.ndarray, X2: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Pad/truncate both datasets to the same feature count."""
    max_feats = max(X1.shape[1], X2.shape[1])
    if X1.shape[1] < max_feats:
        X1 = np.hstack([X1, np.zeros((X1.shape[0], max_feats - X1.shape[1]), dtype=np.float32)])
    if X2.shape[1] < max_feats:
        X2 = np.hstack([X2, np.zeros((X2.shape[0], max_feats - X2.shape[1]), dtype=np.float32)])
    return X1, X2


def main() -> None:
    parser = argparse.ArgumentParser(description="Train ARGUS hybrid anomaly detection pipeline")
    parser.add_argument("--cicids-path", type=str, help="Path to CICIDS2017 CSV")
    parser.add_argument("--unsw-path", type=str, help="Path to UNSW-NB15 CSV")
    parser.add_argument("--output-dir", type=str, default="ml/models")
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--seq-len", type=int, default=10)
    parser.add_argument("--device", type=str, default="cpu")
    parser.add_argument("--test-size", type=float, default=0.2)
    args = parser.parse_args()

    # Load datasets
    datasets_X, datasets_y = [], []
    if args.cicids_path:
        X, y = _load_cicids(args.cicids_path)
        datasets_X.append(X)
        datasets_y.append(y)
    if args.unsw_path:
        X, y = _load_unsw(args.unsw_path)
        datasets_X.append(X)
        datasets_y.append(y)

    if not datasets_X:
        logger.info("No datasets provided -- generating synthetic data for demo.")
        np.random.seed(42)
        n_samples = 10000
        n_features = 50
        X_benign = np.random.randn(int(n_samples * 0.8), n_features).astype(np.float32)
        X_attack = np.random.randn(int(n_samples * 0.2), n_features).astype(np.float32) + 2.0
        X = np.vstack([X_benign, X_attack])
        y = np.array([0] * len(X_benign) + [1] * len(X_attack), dtype=int)
        datasets_X.append(X)
        datasets_y.append(y)

    # Harmonize and concatenate
    if len(datasets_X) == 2:
        datasets_X[0], datasets_X[1] = _harmonize_features(datasets_X[0], datasets_X[1])

    X_all = np.vstack(datasets_X)
    y_all = np.concatenate(datasets_y)
    input_dim = X_all.shape[1]

    logger.info("Combined dataset: %d samples, %d features", len(y_all), input_dim)

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X_all, y_all, test_size=args.test_size, random_state=42, stratify=y_all,
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train, y_train, test_size=0.15, random_state=42, stratify=y_train,
    )

    logger.info("Train: %d | Val: %d | Test: %d", len(y_train), len(y_val), len(y_test))

    # Train ensemble
    ensemble = AnomalyDetectionEnsemble(
        input_dim=input_dim,
        seq_len=args.seq_len,
        device=args.device,
    )
    lstm_config = TrainConfig(
        epochs=args.epochs,
        batch_size=args.batch_size,
        device=args.device,
    )
    metrics = ensemble.fit(X_train, y_train, X_val, y_val, lstm_config=lstm_config)

    # Evaluate
    y_pred = ensemble.predict(X_test)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    logger.info("=== Cross-Dataset Evaluation ===")
    logger.info("Precision: %.4f", precision)
    logger.info("Recall:    %.4f", recall)
    logger.info("F1-Score:  %.4f", f1)
    logger.info("\nClassification Report:\n%s", classification_report(y_test, y_pred, zero_division=0))
    logger.info("Confusion Matrix:\n%s", confusion_matrix(y_test, y_pred))

    # Save
    output_dir = Path(args.output_dir)
    ensemble.save(output_dir)
    logger.info("Models saved to %s", output_dir)


if __name__ == "__main__":
    main()
