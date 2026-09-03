"""1D-CNN over the first N packets' SPLT sequence (CLAUDE.md §4, Build Order step 3).

Chosen over LSTM: better accuracy per unit of inference cost, given the latency budget.
Do not start this before the baseline reports an honest number.

STUB.
"""
from __future__ import annotations


class SequenceCNN:
    def __init__(self, n_packets: int = 20, channels: int = 3) -> None:
        self.n_packets = n_packets
        self.channels = channels  # (size, direction, iat)
        self.model = None

    def fit(self, sequences, y) -> "SequenceCNN":
        raise NotImplementedError("1D-CNN — Build Order step 3")

    def predict_proba(self, sequences):
        raise NotImplementedError

    def embed(self, sequences):
        """Penultimate-layer embedding, for fusion into the GBM (Build Order step 4)."""
        raise NotImplementedError
