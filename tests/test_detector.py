from recon_detector import DetectorConfig, ReconDetector
from recon_detector import synthetic
from recon_detector.schemas import DetectionResult


def _run(records):
    det = ReconDetector(config=DetectorConfig())
    results = [det.process(r) for r in records]
    return det, results


def _fired(results):
    return [r for r in results if r.detected]


def test_output_schema_shape():
    det, results = _run(synthetic.vertical_scan(n_ports=40))
    r = results[-1]
    assert isinstance(r, DetectionResult)
    d = r.to_dict()
    for key in ("detected", "threat_class", "scan_type", "score", "timestamp",
                "source", "evidence"):
        assert key in d
    ev = d["evidence"]
    for key in ("window_seconds", "observed_flows", "unique_destination_hosts",
                "unique_destination_ports", "unique_destination_pairs",
                "destination_port_entropy", "persistence", "scan_like_flow_ratio"):
        assert key in ev


def test_vertical_scan_detected():
    det, results = _run(synthetic.vertical_scan(n_ports=40))
    fired = _fired(results)
    assert fired, "vertical scan should be detected"
    assert fired[-1].scan_type == "vertical"
    assert fired[-1].threat_class == "reconnaissance_port_scan"


def test_horizontal_scan_detected():
    det, results = _run(synthetic.horizontal_scan(n_hosts=40))
    fired = _fired(results)
    assert fired
    assert fired[-1].scan_type == "horizontal"


def test_mixed_scan_detected():
    det, results = _run(synthetic.mixed_scan(n_hosts=12, n_ports=12))
    fired = _fired(results)
    assert fired
    assert fired[-1].scan_type == "mixed"


def test_benign_traffic_not_flagged():
    det, results = _run(synthetic.benign_traffic(n=300))
    assert not _fired(results)


def test_benign_high_fanout_not_flagged():
    det, results = _run(synthetic.benign_high_fanout(n=400))
    assert not _fired(results), "benign high fan-out must not be a scan"


def test_sparse_insufficient_evidence_not_flagged():
    det, results = _run(synthetic.sparse_traffic(n=5))
    assert not _fired(results)


def test_udp_scan_detected():
    det, results = _run(synthetic.udp_scan(n_ports=40))
    assert _fired(results)


def test_slow_vertical_scan_detected_via_persistence():
    # Spread across windows; detection should rely on persistence, not a burst.
    det, results = _run(synthetic.slow_vertical_scan(n_ports=24, gap=25.0))
    fired = _fired(results)
    assert fired, "slow vertical scan should eventually be detected"
    assert fired[-1].evidence["persistence"] >= 2


def test_repeated_persistent_scan_detected():
    det, results = _run(synthetic.repeated_persistent_scan())
    assert _fired(results)


def test_multi_source_low_rate_not_attributed_to_single_source():
    # Documented limitation: each source alone is below evidence thresholds.
    det, results = _run(synthetic.multi_source_low_rate(n_sources=10, per_source=3))
    assert not _fired(results)


def test_camouflaged_scan_detected():
    det, results = _run(synthetic.camouflaged_scan(n_ports=40, noise=200))
    assert _fired(results)


def test_score_is_bounded():
    det, results = _run(synthetic.mixed_scan(n_hosts=15, n_ports=15))
    for r in results:
        assert 0.0 <= r.score <= 1.0


def test_scan_type_unknown_when_below_evidence():
    # A single flow: not enough to classify.
    det = ReconDetector()
    r = det.process({"timestamp": 0, "src_ip": "a", "dst_ip": "b",
                     "dst_port": 80, "packet_count": 1, "byte_count": 0})
    assert r.scan_type == "unknown"
    assert not r.detected
