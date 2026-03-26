"""
LSTM-Autoencoder for temporal anomaly detection in network flow data.

This module implements a PyTorch LSTM-Autoencoder designed to learn normal
network traffic patterns and detect anomalies via reconstruction error.
Designed for features from CICIDS2017 / UNSW-NB15 datasets (duration, bytes,
packets, flags, etc.).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

class LSTMEncoder(nn.Module):
    """Three-layer LSTM encoder: input_dim -> 64 -> 32 -> 16."""

    def __init__(self, input_dim: int, dropout: float = 0.2):
        super().__init__()
        self.lstm1 = nn.LSTM(input_dim, 64, batch_first=True)
        self.dropout1 = nn.Dropout(dropout)
        self.lstm2 = nn.LSTM(64, 32, batch_first=True)
        self.dropout2 = nn.Dropout(dropout)
        self.lstm3 = nn.LSTM(32, 16, batch_first=True)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """Encode input sequence.

        Args:
            x: Tensor of shape ``(batch, seq_len, input_dim)``.

        Returns:
            Tuple of ``(last_hidden_output, latent_representation)``.
            ``latent_representation`` has shape ``(batch, 16)``.
        """
        out, _ = self.lstm1(x)
        out = self.dropout1(out)
        out, _ = self.lstm2(out)
        out = self.dropout2(out)
        out, (hidden, _) = self.lstm3(out)
        # hidden shape: (1, batch, 16) -> squeeze to (batch, 16)
        latent = hidden.squeeze(0)
        return out, latent


class LSTMDecoder(nn.Module):
    """Three-layer LSTM decoder mirroring the encoder: 16 -> 32 -> 64 -> input_dim."""

    def __init__(self, input_dim: int, seq_len: int, dropout: float = 0.2):
        super().__init__()
        self.seq_len = seq_len
        self.lstm1 = nn.LSTM(16, 32, batch_first=True)
        self.dropout1 = nn.Dropout(dropout)
        self.lstm2 = nn.LSTM(32, 64, batch_first=True)
        self.dropout2 = nn.Dropout(dropout)
        self.lstm3 = nn.LSTM(64, 64, batch_first=True)
        self.output_layer = nn.Linear(64, input_dim)

    def forward(self, latent: torch.Tensor) -> torch.Tensor:
        """Decode latent representation back to sequence.

        Args:
            latent: Tensor of shape ``(batch, 16)``.

        Returns:
            Reconstructed sequence of shape ``(batch, seq_len, input_dim)``.
        """
        # Repeat latent vector across the time dimension
        repeated = latent.unsqueeze(1).repeat(1, self.seq_len, 1)
        out, _ = self.lstm1(repeated)
        out = self.dropout1(out)
        out, _ = self.lstm2(out)
        out = self.dropout2(out)
        out, _ = self.lstm3(out)
        reconstruction = self.output_layer(out)
        return reconstruction


class LSTMAutoencoder(nn.Module):
    """LSTM-Autoencoder for temporal anomaly detection.

    The model encodes a sequence of network-flow feature vectors into a
    low-dimensional latent space and attempts to reconstruct the original
    sequence.  Anomalies produce high reconstruction error.
    """

    def __init__(self, input_dim: int, seq_len: int, dropout: float = 0.2):
        super().__init__()
        self.input_dim = input_dim
        self.seq_len = seq_len
        self.encoder = LSTMEncoder(input_dim, dropout)
        self.decoder = LSTMDecoder(input_dim, seq_len, dropout)

    def forward(
        self, x: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """Forward pass.

        Args:
            x: Input tensor of shape ``(batch, seq_len, input_dim)``.

        Returns:
            ``(reconstruction, latent)`` where *reconstruction* has the same
            shape as *x* and *latent* has shape ``(batch, 16)``.
        """
        _, latent = self.encoder(x)
        reconstruction = self.decoder(latent)
        return reconstruction, latent


# ---------------------------------------------------------------------------
# Anomaly scoring
# ---------------------------------------------------------------------------

def compute_reconstruction_error(
    model: LSTMAutoencoder,
    data: torch.Tensor,
    device: torch.device | str = "cpu",
    batch_size: int = 256,
) -> np.ndarray:
    """Compute per-sample mean reconstruction error (MSE).

    Args:
        model: Trained :class:`LSTMAutoencoder`.
        data: Tensor of shape ``(N, seq_len, input_dim)``.
        device: Target device.
        batch_size: Inference batch size.

    Returns:
        1-D numpy array of reconstruction errors with length *N*.
    """
    model.eval()
    model.to(device)
    errors: list[np.ndarray] = []
    loader = DataLoader(TensorDataset(data), batch_size=batch_size, shuffle=False)

    with torch.no_grad():
        for (batch,) in loader:
            batch = batch.to(device)
            reconstruction, _ = model(batch)
            mse = ((batch - reconstruction) ** 2).mean(dim=(1, 2))
            errors.append(mse.cpu().numpy())

    return np.concatenate(errors)


def get_latent_representations(
    model: LSTMAutoencoder,
    data: torch.Tensor,
    device: torch.device | str = "cpu",
    batch_size: int = 256,
) -> np.ndarray:
    """Extract latent representations from the encoder.

    Args:
        model: Trained :class:`LSTMAutoencoder`.
        data: Tensor ``(N, seq_len, input_dim)``.
        device: Target device.
        batch_size: Inference batch size.

    Returns:
        Numpy array of shape ``(N, 16)``.
    """
    model.eval()
    model.to(device)
    latents: list[np.ndarray] = []
    loader = DataLoader(TensorDataset(data), batch_size=batch_size, shuffle=False)

    with torch.no_grad():
        for (batch,) in loader:
            batch = batch.to(device)
            _, latent = model(batch)
            latents.append(latent.cpu().numpy())

    return np.concatenate(latents)


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

@dataclass
class TrainConfig:
    """Hyperparameters for LSTM-AE training."""

    epochs: int = 50
    batch_size: int = 128
    learning_rate: float = 1e-3
    weight_decay: float = 1e-5
    patience: int = 7
    device: str = "cpu"


def train_lstm_autoencoder(
    model: LSTMAutoencoder,
    train_data: torch.Tensor,
    val_data: Optional[torch.Tensor] = None,
    config: Optional[TrainConfig] = None,
) -> dict:
    """Train the LSTM-Autoencoder with early stopping.

    Args:
        model: An :class:`LSTMAutoencoder` instance.
        train_data: Tensor ``(N_train, seq_len, input_dim)``.
        val_data: Optional validation tensor.
        config: Training hyperparameters.

    Returns:
        Dictionary with ``train_losses``, ``val_losses``, and ``best_epoch``.
    """
    if config is None:
        config = TrainConfig()

    device = torch.device(config.device)
    model.to(device)

    optimizer = torch.optim.Adam(
        model.parameters(), lr=config.learning_rate, weight_decay=config.weight_decay
    )
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="min", factor=0.5, patience=3, verbose=False
    )
    criterion = nn.MSELoss()

    train_loader = DataLoader(
        TensorDataset(train_data),
        batch_size=config.batch_size,
        shuffle=True,
        drop_last=False,
    )
    val_loader: Optional[DataLoader] = None
    if val_data is not None:
        val_loader = DataLoader(
            TensorDataset(val_data),
            batch_size=config.batch_size,
            shuffle=False,
        )

    train_losses: list[float] = []
    val_losses: list[float] = []
    best_val_loss = float("inf")
    best_state = None
    best_epoch = 0
    patience_counter = 0

    for epoch in range(1, config.epochs + 1):
        # --- Train ---
        model.train()
        epoch_loss = 0.0
        for (batch,) in train_loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            reconstruction, _ = model(batch)
            loss = criterion(reconstruction, batch)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            epoch_loss += loss.item() * batch.size(0)

        avg_train_loss = epoch_loss / len(train_data)
        train_losses.append(avg_train_loss)

        # --- Validate ---
        avg_val_loss = avg_train_loss  # fallback when no val set
        if val_loader is not None:
            model.eval()
            val_epoch_loss = 0.0
            with torch.no_grad():
                for (batch,) in val_loader:
                    batch = batch.to(device)
                    reconstruction, _ = model(batch)
                    loss = criterion(reconstruction, batch)
                    val_epoch_loss += loss.item() * batch.size(0)
            avg_val_loss = val_epoch_loss / len(val_data)
            val_losses.append(avg_val_loss)

        scheduler.step(avg_val_loss)

        logger.info(
            "Epoch %03d/%03d  train_loss=%.6f  val_loss=%.6f",
            epoch,
            config.epochs,
            avg_train_loss,
            avg_val_loss,
        )

        # Early stopping
        if avg_val_loss < best_val_loss:
            best_val_loss = avg_val_loss
            best_epoch = epoch
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= config.patience:
                logger.info("Early stopping at epoch %d", epoch)
                break

    # Restore best weights
    if best_state is not None:
        model.load_state_dict(best_state)

    return {
        "train_losses": train_losses,
        "val_losses": val_losses,
        "best_epoch": best_epoch,
        "best_val_loss": best_val_loss,
    }


def save_model(model: LSTMAutoencoder, path: str | Path) -> None:
    """Persist model weights and architecture metadata."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "state_dict": model.state_dict(),
            "input_dim": model.input_dim,
            "seq_len": model.seq_len,
        },
        path,
    )
    logger.info("Model saved to %s", path)


def load_model(path: str | Path, device: str = "cpu") -> LSTMAutoencoder:
    """Load a saved LSTM-Autoencoder."""
    checkpoint = torch.load(path, map_location=device, weights_only=False)
    model = LSTMAutoencoder(
        input_dim=checkpoint["input_dim"],
        seq_len=checkpoint["seq_len"],
    )
    model.load_state_dict(checkpoint["state_dict"])
    model.to(device)
    model.eval()
    return model
