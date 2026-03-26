"""
Hybrid anomaly detection ensemble combining LSTM-AE, Isolation Forest, and XGBoost.

Pipeline:
    1. LSTM-AE produces reconstruction errors and latent representations.
    2. Isolation Forest provides unsupervised anomaly scores.
    3. XGBoost performs final supervised classification using combined features.
    4. SHAP provides post-hoc explainability for XGBoost predictions.

Designed for network-flow features compatible with CICIDS2017 / UNSW-NB15.
"""

from __future__ import annotations

import logging
import pickle
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import shap
import xgboost as xgb
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .lstm_autoencoder import (
    LSTMAutoencoder,
    TrainConfig,
    compute_reconstruction_error,
    get_latent_representations,
    load_model as load_lstm_model,
    save_model as save_lstm_model,
    train_lstm_autoencoder,
)

logger = logging.getLogger(__name__)

# Feature names shared across the pipeline -- a superset of fields found in
# both CICIDS2017 and UNSW-NB15 after harmonisation.
NETWORK_FLOW_FEATURES: List[str] = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "flow_packets_per_sec",
    "flow_bytes_per_sec",
    "fwd_iat_mean",
    "bwd_iat_mean",
    "active_mean",
    "idle_mean",
]


class AnomalyDetectionEnsemble:
    """Hybrid anomaly detection ensemble.

    The ensemble chains three models:
    * **LSTM-AE** -- learns temporal patterns in network flows and outputs
      per-sample reconstruction error plus a 16-d latent vector.
    * **Isolation Forest** -- provides an unsupervised anomaly score from the
      combined feature set.
    * **XGBoost** -- final binary classifier consuming original features,
      reconstruction error, latent representation, and IsoForest score.

    SHAP is used to explain XGBoost predictions.
    """

    def __init__(
        self,
        input_dim: int = 50,
        seq_len: int = 10,
        isoforest_contamination: float = 0.1,
        xgb_params: Optional[Dict[str, Any]] = None,
        smote: bool = True,
        device: str = "cpu",
    ):
        self.input_dim = input_dim
        self.seq_len = seq_len
        self.device = device
        self.smote = smote

        # Sub-models
        self.lstm_ae = LSTMAutoencoder(input_dim, seq_len)
        self.scaler = StandardScaler()

        self.isoforest = IsolationForest(
            n_estimators=200,
            contamination=isoforest_contamination,
            random_state=42,
            n_jobs=-1,
        )

        default_xgb_params: Dict[str, Any] = {
            "n_estimators": 300,
            "max_depth": 8,
            "learning_rate": 0.05,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "reg_alpha": 0.1,
            "reg_lambda": 1.0,
            "scale_pos_weight": 1.0,
            "use_label_encoder": False,
            "eval_metric": "logloss",
            "random_state": 42,
            "n_jobs": -1,
        }
        if xgb_params:
            default_xgb_params.update(xgb_params)
        self.xgb_clf = xgb.XGBClassifier(**default_xgb_params)

        self.explainer: Optional[shap.TreeExplainer] = None
        self._feature_names: Optional[List[str]] = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_meta_features(
        self,
        X_flat: np.ndarray,
        X_seq: "torch.Tensor",  # noqa: F821
    ) -> np.ndarray:
        """Build augmented feature matrix for the downstream classifiers.

        The meta-features comprise:
        * Original (flattened) features -- scaled.
        * LSTM-AE reconstruction error (1-d).
        * LSTM-AE latent representation (16-d).
        * Isolation Forest anomaly score (1-d).
        """
        import torch  # local import to keep module importable without torch

        recon_error = compute_reconstruction_error(
            self.lstm_ae, X_seq, device=self.device
        ).reshape(-1, 1)

        latent = get_latent_representations(
            self.lstm_ae, X_seq, device=self.device
        )

        iso_scores = self.isoforest.decision_function(X_flat).reshape(-1, 1)

        meta = np.hstack([X_flat, recon_error, latent, iso_scores])
        return meta

    def _prepare_sequences(
        self, X: np.ndarray
    ) -> "torch.Tensor":
        """Reshape flat feature matrix into sequences for the LSTM-AE.

        If the number of samples is not divisible by ``seq_len`` the trailing
        samples are dropped (they are still used in the flat path).  For
        non-divisible counts we pad with the last sample.
        """
        import torch

        n_samples = X.shape[0]
        remainder = n_samples % self.seq_len
        if remainder != 0:
            pad_count = self.seq_len - remainder
            padding = np.tile(X[-1:], (pad_count, 1))
            X_padded = np.vstack([X, padding])
        else:
            X_padded = X

        n_seqs = X_padded.shape[0] // self.seq_len
        X_seq = X_padded.reshape(n_seqs, self.seq_len, -1)
        # We need per-sample sequences -- use a sliding window instead
        # Revert to per-sample: replicate each sample as a length-1 repeated seq
        X_seq_per_sample = np.stack(
            [X[max(0, i - self.seq_len + 1): i + 1] for i in range(n_samples)],
            axis=0,
        )
        # Pad short windows at the beginning
        padded_seqs = []
        for i in range(n_samples):
            start = max(0, i - self.seq_len + 1)
            window = X[start: i + 1]
            if len(window) < self.seq_len:
                pad = np.tile(window[0:1], (self.seq_len - len(window), 1))
                window = np.vstack([pad, window])
            padded_seqs.append(window)
        X_seq_per_sample = np.array(padded_seqs)

        return torch.tensor(X_seq_per_sample, dtype=torch.float32)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        lstm_config: Optional[TrainConfig] = None,
    ) -> Dict[str, Any]:
        """Train the full ensemble pipeline.

        Args:
            X_train: Training features ``(N, input_dim)``.
            y_train: Binary labels ``(N,)`` -- 0 = benign, 1 = malicious.
            X_val: Optional validation features.
            y_val: Optional validation labels.
            lstm_config: LSTM-AE training hyperparameters.

        Returns:
            Dictionary of training metrics from each stage.
        """
        import torch

        logger.info("Step 1/3: Training LSTM-Autoencoder ...")
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val) if X_val is not None else None

        train_seq = self._prepare_sequences(X_train_scaled)
        val_seq = self._prepare_sequences(X_val_scaled) if X_val_scaled is not None else None

        if lstm_config is None:
            lstm_config = TrainConfig(device=self.device)
        lstm_metrics = train_lstm_autoencoder(
            self.lstm_ae, train_seq, val_seq, lstm_config
        )

        logger.info("Step 2/3: Training Isolation Forest ...")
        self.isoforest.fit(X_train_scaled)

        logger.info("Step 3/3: Training XGBoost classifier ...")
        meta_train = self._build_meta_features(X_train_scaled, train_seq)

        # Build feature names for the augmented matrix
        base_names = NETWORK_FLOW_FEATURES[: self.input_dim]
        if len(base_names) < self.input_dim:
            base_names += [f"feat_{i}" for i in range(len(base_names), self.input_dim)]
        latent_names = [f"latent_{i}" for i in range(16)]
        self._feature_names = base_names + ["recon_error"] + latent_names + ["isoforest_score"]

        y_fit = y_train
        X_fit = meta_train
        if self.smote:
            unique, counts = np.unique(y_train, return_counts=True)
            if len(unique) == 2 and min(counts) >= 6:
                smote = SMOTE(random_state=42, k_neighbors=min(5, min(counts) - 1))
                X_fit, y_fit = smote.fit_resample(meta_train, y_train)
                logger.info(
                    "SMOTE resampling: %d -> %d samples", len(y_train), len(y_fit)
                )

        self.xgb_clf.fit(
            X_fit,
            y_fit,
            eval_set=(
                [(self._build_meta_features(X_val_scaled, val_seq), y_val)]
                if X_val is not None and y_val is not None
                else None
            ),
            verbose=False,
        )

        # Prepare SHAP explainer
        self.explainer = shap.TreeExplainer(self.xgb_clf)

        return {
            "lstm_metrics": lstm_metrics,
            "xgb_best_score": (
                self.xgb_clf.best_score if hasattr(self.xgb_clf, "best_score") else None
            ),
        }

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict binary labels for new samples.

        Args:
            X: Feature matrix ``(N, input_dim)`` (unscaled).

        Returns:
            Binary predictions ``(N,)``.
        """
        meta = self._transform(X)
        return self.xgb_clf.predict(meta)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return class probabilities.

        Args:
            X: Feature matrix ``(N, input_dim)`` (unscaled).

        Returns:
            Probability matrix ``(N, 2)``.
        """
        meta = self._transform(X)
        return self.xgb_clf.predict_proba(meta)

    def explain(
        self, X: np.ndarray, max_display: int = 20
    ) -> Tuple[np.ndarray, List[str]]:
        """Compute SHAP values for predictions.

        Args:
            X: Feature matrix ``(N, input_dim)`` (unscaled).
            max_display: Ignored here, useful when plotting externally.

        Returns:
            Tuple of ``(shap_values, feature_names)``.
        """
        if self.explainer is None:
            self.explainer = shap.TreeExplainer(self.xgb_clf)

        meta = self._transform(X)
        shap_values = self.explainer.shap_values(meta)
        feature_names = self._feature_names or [
            f"f{i}" for i in range(meta.shape[1])
        ]
        return shap_values, feature_names

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, directory: str | Path) -> None:
        """Save all sub-models to *directory*."""
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)

        save_lstm_model(self.lstm_ae, directory / "lstm_autoencoder.pt")

        with open(directory / "isoforest.pkl", "wb") as f:
            pickle.dump(self.isoforest, f)

        with open(directory / "xgb_classifier.pkl", "wb") as f:
            pickle.dump(self.xgb_clf, f)

        with open(directory / "scaler.pkl", "wb") as f:
            pickle.dump(self.scaler, f)

        with open(directory / "meta.pkl", "wb") as f:
            pickle.dump(
                {
                    "input_dim": self.input_dim,
                    "seq_len": self.seq_len,
                    "feature_names": self._feature_names,
                },
                f,
            )

        logger.info("Ensemble saved to %s", directory)

    @classmethod
    def load(cls, directory: str | Path, device: str = "cpu") -> "AnomalyDetectionEnsemble":
        """Load a persisted ensemble."""
        directory = Path(directory)

        with open(directory / "meta.pkl", "rb") as f:
            meta = pickle.load(f)

        ensemble = cls(
            input_dim=meta["input_dim"],
            seq_len=meta["seq_len"],
            device=device,
        )
        ensemble._feature_names = meta.get("feature_names")

        ensemble.lstm_ae = load_lstm_model(
            directory / "lstm_autoencoder.pt", device=device
        )

        with open(directory / "isoforest.pkl", "rb") as f:
            ensemble.isoforest = pickle.load(f)

        with open(directory / "xgb_classifier.pkl", "rb") as f:
            ensemble.xgb_clf = pickle.load(f)

        with open(directory / "scaler.pkl", "rb") as f:
            ensemble.scaler = pickle.load(f)

        ensemble.explainer = shap.TreeExplainer(ensemble.xgb_clf)
        return ensemble

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _transform(self, X: np.ndarray) -> np.ndarray:
        """Scale input and build meta-features."""
        X_scaled = self.scaler.transform(X)
        seq = self._prepare_sequences(X_scaled)
        return self._build_meta_features(X_scaled, seq)
