"""1D-CNN over the first N packets' SPLT sequence (CLAUDE.md §4, Build Order step 3).

Chosen over LSTM: better accuracy per unit of inference cost, given the latency budget.
Input is the (size, direction, iat) sequence from features.splt.raw_sequence.

Kept deliberately small — this is a latency-budgeted streaming detector, not a research net.
"""
from __future__ import annotations

import numpy as np

try:
    import torch
    import torch.nn as nn
    _TORCH = True
except Exception:  # torch optional; baseline still works without it
    _TORCH = False


if _TORCH:

    class _Net(nn.Module):
        def __init__(self, channels: int = 3, n_packets: int = 20) -> None:
            super().__init__()
            self.features = nn.Sequential(
                nn.Conv1d(channels, 32, kernel_size=3, padding=1),
                nn.ReLU(),
                nn.Conv1d(32, 64, kernel_size=3, padding=1),
                nn.ReLU(),
                nn.AdaptiveAvgPool1d(1),
            )
            self.head = nn.Sequential(nn.Flatten(), nn.Linear(64, 32), nn.ReLU())
            self.classifier = nn.Linear(32, 1)

        def embed(self, x):
            return self.head(self.features(x))

        def forward(self, x):
            return self.classifier(self.embed(x)).squeeze(-1)


class SequenceCNN:
    """1D-CNN classifier over SPLT sequences. Standardises inputs channel-wise."""

    def __init__(self, n_packets: int = 20, channels: int = 3,
                 epochs: int = 12, lr: float = 1e-3, seed: int = 0) -> None:
        if not _TORCH:
            raise RuntimeError("torch not available; SequenceCNN cannot be used")
        self.n_packets = n_packets
        self.channels = channels  # (size, direction, iat)
        self.epochs = epochs
        self.lr = lr
        self.seed = seed
        self.net = None
        self._mean = None
        self._std = None

    # sequences: list of [(size, direction, iat), ...] each length n_packets
    def _to_tensor(self, sequences: list[list[tuple]]):
        arr = np.asarray(sequences, dtype=np.float32)          # (B, N, C)
        arr = np.transpose(arr, (0, 2, 1))                     # (B, C, N)
        if self._mean is None:
            self._mean = arr.mean(axis=(0, 2), keepdims=True)
            self._std = arr.std(axis=(0, 2), keepdims=True) + 1e-6
        arr = (arr - self._mean) / self._std
        return torch.tensor(arr, dtype=torch.float32)

    def fit(self, sequences: list[list[tuple]], y) -> "SequenceCNN":
        torch.manual_seed(self.seed)
        X = self._to_tensor(sequences)
        yt = torch.tensor(np.asarray(y, dtype=np.float32))
        self.net = _Net(self.channels, self.n_packets)
        opt = torch.optim.Adam(self.net.parameters(), lr=self.lr)
        # class imbalance: weight positives up (traffic is ~99.9% benign in reality)
        pos_weight = torch.tensor([(len(yt) - yt.sum()) / (yt.sum() + 1e-6)])
        loss_fn = torch.nn.BCEWithLogitsLoss(pos_weight=pos_weight)
        self.net.train()
        for _ in range(self.epochs):
            opt.zero_grad()
            logits = self.net(X)
            loss = loss_fn(logits, yt)
            loss.backward()
            opt.step()
        return self

    def predict_proba(self, sequences: list[list[tuple]]) -> np.ndarray:
        self.net.eval()
        with torch.no_grad():
            logits = self.net(self._to_tensor(sequences))
            return torch.sigmoid(logits).numpy()

    def embed(self, sequences: list[list[tuple]]) -> np.ndarray:
        """Penultimate-layer embedding, for fusion into the GBM (Build Order step 4)."""
        self.net.eval()
        with torch.no_grad():
            return self.net.embed(self._to_tensor(sequences)).numpy()
