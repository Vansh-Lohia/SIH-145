import math

from recon_detector.behavior import BehaviorTracker, SourceState, _entropy_from_counts


def test_entropy_basic():
    assert _entropy_from_counts({}) == 0.0
    assert _entropy_from_counts({"a": 5}) == 0.0            # single category
    h = _entropy_from_counts({"a": 1, "b": 1})
    assert math.isclose(h, 1.0, abs_tol=1e-9)               # 2 equal -> 1 bit


def test_vertical_fanout_counts_and_entropy():
    tr = BehaviorTracker(window_seconds=60)
    src, dst = "1.1.1.1", "2.2.2.2"
    for i, port in enumerate(range(20, 40)):
        st, feats = tr.observe(src, ts=float(i) * 0.1, dst_ip=dst, dst_port=port,
                               packet_count=1, byte_count=0, scan_score=0.9)
    assert feats.unique_destination_hosts == 1
    assert feats.unique_destination_ports == 20
    assert feats.unique_destination_pairs == 20
    assert feats.destination_host_entropy == 0.0
    assert feats.destination_port_entropy > 4.0            # ~log2(20)
    assert feats.small_flow_ratio == 1.0
    assert feats.scan_like_flow_ratio == 1.0


def test_horizontal_fanout():
    tr = BehaviorTracker(window_seconds=60)
    src = "1.1.1.1"
    for i in range(25):
        st, feats = tr.observe(src, ts=float(i) * 0.1, dst_ip=f"10.0.0.{i}",
                               dst_port=445, packet_count=1, byte_count=0, scan_score=0.9)
    assert feats.unique_destination_hosts == 25
    assert feats.unique_destination_ports == 1
    assert feats.destination_port_entropy == 0.0


def test_recent_window_excludes_old_events_but_history_retains():
    tr = BehaviorTracker(window_seconds=10, state_ttl=600)
    src = "1.1.1.1"
    tr.observe(src, ts=0.0, dst_ip="2.2.2.2", dst_port=80,
               packet_count=1, byte_count=0, scan_score=0.5)
    st, feats = tr.observe(src, ts=100.0, dst_ip="2.2.2.2", dst_port=81,
                           packet_count=1, byte_count=0, scan_score=0.5)
    # Only one event lies in the recent 10s window ...
    assert feats.recent_window_flows == 1
    # ... but both are retained in the accumulation history (within the horizon).
    assert feats.observed_flows == 2


def test_history_horizon_evicts_beyond_ttl():
    tr = BehaviorTracker(window_seconds=10, state_ttl=50)
    src = "1.1.1.1"
    tr.observe(src, ts=0.0, dst_ip="2.2.2.2", dst_port=80,
               packet_count=1, byte_count=0, scan_score=0.5)
    st, feats = tr.observe(src, ts=100.0, dst_ip="2.2.2.2", dst_port=81,
                           packet_count=1, byte_count=0, scan_score=0.5)
    # first event is older than the history horizon (=ttl=50) -> evicted
    assert feats.observed_flows == 1


def test_persistence_across_windows():
    st = SourceState(src_ip="s", window_seconds=60, history_horizon=600)
    st.mark_window(10.0)     # window 0
    st.mark_window(70.0)     # window 1
    st.mark_window(130.0)    # window 2
    assert len(st.active_windows) == 3
    # a repeat in an already-marked window does not double count
    st.mark_window(75.0)     # still window 1
    assert len(st.active_windows) == 3


def test_state_ttl_expiry():
    tr = BehaviorTracker(window_seconds=60, state_ttl=600)
    tr.observe("old", ts=0.0, dst_ip="2.2.2.2", dst_port=80,
               packet_count=1, byte_count=0, scan_score=0.5)
    tr.observe("new", ts=1000.0, dst_ip="2.2.2.2", dst_port=80,
               packet_count=1, byte_count=0, scan_score=0.5)
    removed = tr.expire(now=1000.0)
    assert removed == 1
    assert tr.active_sources == 1


def test_bounded_sources_lru_eviction():
    tr = BehaviorTracker(max_sources=10)
    for i in range(50):
        tr.observe(f"src{i}", ts=float(i), dst_ip="2.2.2.2", dst_port=80,
                   packet_count=1, byte_count=0, scan_score=0.1)
    assert tr.active_sources <= 10


def test_bounded_events_per_source():
    st = SourceState(src_ip="s", window_seconds=60, history_horizon=10_000,
                     max_events=100)
    from recon_detector.behavior import _Event
    for i in range(500):
        st.update(_Event(ts=float(i), dst_ip="d", dst_port=i,
                         packet_count=1, byte_count=0, scan_score=0.5))
    assert len(st.events) <= 100
