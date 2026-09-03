"""Source-level streaming behavioural state.

For every source IP we keep *bounded* state summarising its recent
observed-direction activity: fan-out (unique destination hosts / ports /
pairs), flow-size statistics, per-flow scan-score aggregates, and a notion of
temporal *persistence* across windows.  This is the layer the research
(Ring et al. 2018; Safaei Pour & Bou-Harb 2019) identifies as essential --
a scan is a *sequence* of flows, not one suspicious flow (spec sections 5, 8, 10).

Boundedness (spec section 21):

* Inactive sources are expired after a TTL.
* The total number of tracked sources is capped (LRU eviction).
* Per-source event history is capped to a rolling temporal horizon *and* a
  hard event-count cap.
* Unique-destination tracking uses capped sets; beyond the cap we keep counting
  approximately rather than growing without bound.
"""

from __future__ import annotations

import math
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple


def _entropy_from_counts(counts: Dict[object, int]) -> float:
    """Shannon entropy (bits) of a categorical distribution given raw counts."""
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    h = 0.0
    for c in counts.values():
        if c <= 0:
            continue
        p = c / total
        h -= p * math.log2(p)
    return h


@dataclass
class _Event:
    ts: float
    dst_ip: str
    dst_port: int
    packet_count: float
    byte_count: float
    scan_score: float


@dataclass
class WindowFeatures:
    """Behavioural features computed over the current rolling window."""

    window_seconds: float
    observed_flows: int          # flows retained over the accumulation horizon
    recent_window_flows: int     # flows within the last window_seconds (burst view)
    unique_destination_hosts: int
    unique_destination_ports: int
    unique_destination_pairs: int
    attempts_per_second: float
    destination_host_entropy: float
    destination_port_entropy: float
    destination_pair_entropy: float
    mean_packet_count: float
    mean_byte_count: float
    small_flow_ratio: float
    scan_like_flow_ratio: float
    mean_flow_scan_score: float
    max_flow_scan_score: float
    persistence: int
    ports_per_host: float
    # Fan-out restricted to scan-like flows (score >= threshold). This is the
    # discriminator that survives camouflage: benign flows mixed in are not
    # scan-like and therefore do not inflate these counts.
    scan_like_hosts: int = 0
    scan_like_ports: int = 0
    scan_like_pairs: int = 0


@dataclass
class SourceState:
    """Bounded per-source behavioural state."""

    src_ip: str
    window_seconds: float = 60.0
    history_horizon: float = 600.0  # keep events at least this long for persistence
    max_events: int = 5000
    max_unique_tracked: int = 4096
    small_flow_packet_threshold: float = 3.0
    scan_like_score_threshold: float = 0.5

    last_seen: float = 0.0
    events: Deque[_Event] = field(default_factory=deque)
    # Windows (bucketed by window_seconds) in which this source looked suspicious.
    active_windows: "OrderedDict[int, bool]" = field(default_factory=OrderedDict)
    _dropped_events: int = 0

    def update(self, ev: _Event, suspicious_window: bool = False) -> None:
        self.last_seen = max(self.last_seen, ev.ts)
        self.events.append(ev)
        # Hard cap on retained events.
        while len(self.events) > self.max_events:
            self.events.popleft()
            self._dropped_events += 1
        self._evict_old(ev.ts)

    def mark_window(self, ts: float) -> None:
        wid = int(ts // self.window_seconds)
        self.active_windows[wid] = True
        self.active_windows.move_to_end(wid)
        # Bound persistence memory to windows inside the history horizon.
        min_wid = int((ts - self.history_horizon) // self.window_seconds)
        while self.active_windows:
            oldest = next(iter(self.active_windows))
            if oldest < min_wid:
                self.active_windows.popitem(last=False)
            else:
                break

    def _evict_old(self, now: float) -> None:
        horizon = now - self.history_horizon
        while self.events and self.events[0].ts < horizon:
            self.events.popleft()

    def window_features(self, now: float) -> WindowFeatures:
        """Compute behavioural features for this source.

        Fan-out / diversity / ratios are accumulated over the *retained
        history* (bounded by ``history_horizon`` and ``max_events``) so that
        slow scans -- a few probes per window -- accumulate evidence across
        windows (Ring et al. 2018; Safaei Pour & Bou-Harb 2019).  The recent
        ``window_seconds`` is used only for the burst view (rate and
        ``recent_window_flows``).
        """
        w_start = now - self.window_seconds
        host_counts: Dict[str, int] = {}
        port_counts: Dict[int, int] = {}
        pair_counts: Dict[Tuple[str, int], int] = {}
        sl_hosts: set = set()
        sl_ports: set = set()
        sl_pairs: set = set()
        n = 0
        recent = 0
        small = 0
        scan_like = 0
        sum_pkts = 0.0
        sum_bytes = 0.0
        sum_score = 0.0
        max_score = 0.0
        for ev in self.events:
            n += 1
            if ev.ts >= w_start:
                recent += 1
            if len(host_counts) < self.max_unique_tracked or ev.dst_ip in host_counts:
                host_counts[ev.dst_ip] = host_counts.get(ev.dst_ip, 0) + 1
            if len(port_counts) < self.max_unique_tracked or ev.dst_port in port_counts:
                port_counts[ev.dst_port] = port_counts.get(ev.dst_port, 0) + 1
            key = (ev.dst_ip, ev.dst_port)
            if len(pair_counts) < self.max_unique_tracked or key in pair_counts:
                pair_counts[key] = pair_counts.get(key, 0) + 1
            sum_pkts += ev.packet_count
            sum_bytes += ev.byte_count
            sum_score += ev.scan_score
            max_score = max(max_score, ev.scan_score)
            if ev.packet_count <= self.small_flow_packet_threshold:
                small += 1
            if ev.scan_score >= self.scan_like_score_threshold:
                scan_like += 1
                if len(sl_pairs) < self.max_unique_tracked:
                    sl_hosts.add(ev.dst_ip)
                    sl_ports.add(ev.dst_port)
                    sl_pairs.add((ev.dst_ip, ev.dst_port))

        uniq_hosts = len(host_counts)
        uniq_ports = len(port_counts)
        rate = recent / self.window_seconds if self.window_seconds > 0 else 0.0
        persistence = len(self.active_windows)
        return WindowFeatures(
            window_seconds=self.window_seconds,
            observed_flows=n,
            recent_window_flows=recent,
            unique_destination_hosts=uniq_hosts,
            unique_destination_ports=uniq_ports,
            unique_destination_pairs=len(pair_counts),
            attempts_per_second=rate,
            destination_host_entropy=_entropy_from_counts(host_counts),
            destination_port_entropy=_entropy_from_counts(port_counts),
            destination_pair_entropy=_entropy_from_counts(pair_counts),
            mean_packet_count=(sum_pkts / n) if n else 0.0,
            mean_byte_count=(sum_bytes / n) if n else 0.0,
            small_flow_ratio=(small / n) if n else 0.0,
            scan_like_flow_ratio=(scan_like / n) if n else 0.0,
            mean_flow_scan_score=(sum_score / n) if n else 0.0,
            max_flow_scan_score=max_score,
            persistence=persistence,
            ports_per_host=(uniq_ports / uniq_hosts) if uniq_hosts else 0.0,
            scan_like_hosts=len(sl_hosts),
            scan_like_ports=len(sl_ports),
            scan_like_pairs=len(sl_pairs),
        )


class BehaviorTracker:
    """Holds per-source state with TTL expiry and a bounded source cap."""

    def __init__(
        self,
        window_seconds: float = 60.0,
        state_ttl: float = 600.0,
        history_horizon: Optional[float] = None,
        max_sources: int = 100_000,
        max_events: int = 5000,
        small_flow_packet_threshold: float = 3.0,
        scan_like_score_threshold: float = 0.5,
    ) -> None:
        self.window_seconds = window_seconds
        self.state_ttl = state_ttl
        self.history_horizon = history_horizon if history_horizon is not None else state_ttl
        self.max_sources = max_sources
        self.max_events = max_events
        self.small_flow_packet_threshold = small_flow_packet_threshold
        self.scan_like_score_threshold = scan_like_score_threshold
        self._sources: "OrderedDict[str, SourceState]" = OrderedDict()

    def __len__(self) -> int:
        return len(self._sources)

    @property
    def active_sources(self) -> int:
        return len(self._sources)

    def _get_state(self, src_ip: str) -> SourceState:
        st = self._sources.get(src_ip)
        if st is None:
            st = SourceState(
                src_ip=src_ip,
                window_seconds=self.window_seconds,
                history_horizon=self.history_horizon,
                max_events=self.max_events,
                small_flow_packet_threshold=self.small_flow_packet_threshold,
                scan_like_score_threshold=self.scan_like_score_threshold,
            )
            self._sources[src_ip] = st
            self._evict_sources_if_needed()
        self._sources.move_to_end(src_ip)
        return st

    def _evict_sources_if_needed(self) -> None:
        while len(self._sources) > self.max_sources:
            self._sources.popitem(last=False)  # drop least-recently-used

    def expire(self, now: float) -> int:
        """Remove sources whose last activity is older than the TTL.

        Returns the number of sources removed.
        """
        cutoff = now - self.state_ttl
        removed = 0
        for src_ip in list(self._sources.keys()):
            if self._sources[src_ip].last_seen < cutoff:
                del self._sources[src_ip]
                removed += 1
        return removed

    def observe(
        self,
        src_ip: str,
        ts: float,
        dst_ip: str,
        dst_port: int,
        packet_count: float,
        byte_count: float,
        scan_score: float,
    ) -> Tuple[SourceState, WindowFeatures]:
        """Record one flow for ``src_ip`` and return updated state + features."""
        st = self._get_state(src_ip)
        ev = _Event(
            ts=ts,
            dst_ip=dst_ip,
            dst_port=dst_port,
            packet_count=packet_count,
            byte_count=byte_count,
            scan_score=scan_score,
        )
        st.update(ev)
        feats = st.window_features(ts)
        return st, feats

    def total_retained_events(self) -> int:
        return sum(len(s.events) for s in self._sources.values())
