"""Optional baselines (spec section 29).

These are *baselines*, not the production detector.  They exist so evaluation
can show that the full per-flow + behavioural + temporal detector adds value
over a naive threshold, and to document -- honestly -- why classical
Threshold Random Walk (TRW) is not usable under strict one-way observation.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Set, Tuple


@dataclass
class FanoutThresholdBaseline:
    """Fires when a source touches more than ``max_pairs`` distinct
    (dst_ip, dst_port) pairs within the tracking window.

    No ML, no small-flow gating -- which is exactly why it over-fires on benign
    high fan-out.  That contrast is the point.
    """

    window_seconds: float = 60.0
    max_pairs: int = 20
    _events: Dict[str, list] = field(default_factory=lambda: defaultdict(list))

    def process(self, src_ip: str, ts: float, dst_ip: str, dst_port: int) -> bool:
        evs = self._events[src_ip]
        evs.append((ts, dst_ip, dst_port))
        w_start = ts - self.window_seconds
        # prune
        while evs and evs[0][0] < w_start:
            evs.pop(0)
        pairs: Set[Tuple[str, int]] = {(d, p) for _, d, p in evs}
        return len(pairs) > self.max_pairs


class TRWResearchBaseline:
    """Classical Threshold Random Walk (Jung et al. 2004).

    TRW's sequential hypothesis test needs the *outcome* of each connection
    (success vs failure), which is unavailable under strict one-way passive
    observation.  We therefore refuse to run it unless outcomes are genuinely
    supplied, and we never fabricate them (spec sections 5, 37).
    """

    def __init__(self, theta0: float = 0.8, theta1: float = 0.2,
                 eta0: float = 100.0, eta1: float = 0.01) -> None:
        # Likelihood-ratio bounds; standard TRW parameterisation.
        self.theta0 = theta0
        self.theta1 = theta1
        self.eta0 = eta0
        self.eta1 = eta1
        self._lr: Dict[str, float] = defaultdict(lambda: 1.0)

    def update(self, src_ip: str, connection_success: "bool | None") -> str:
        """Update the per-source likelihood ratio with one connection outcome.

        ``connection_success`` MUST come from genuinely observed reverse-path
        information.  ``None`` (the strict one-way case) raises -- we do not
        guess outcomes.
        """
        if connection_success is None:
            raise ValueError(
                "TRW requires observed connection outcomes, which are not "
                "available under strict one-way observation. This baseline is "
                "for offline research only and must not fabricate outcomes."
            )
        if connection_success:
            ratio = self.theta1 / self.theta0
        else:
            ratio = (1 - self.theta1) / (1 - self.theta0)
        self._lr[src_ip] *= ratio
        if self._lr[src_ip] >= self.eta0:
            return "scanner"
        if self._lr[src_ip] <= self.eta1:
            return "benign"
        return "pending"
