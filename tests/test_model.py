import numpy as np
import pytest

from recon_detector.features import (
    APPROVED_FEATURES,
    FORBIDDEN_SUBSTRINGS,
    assert_features_are_one_way,
    vectorize_record,
)
from recon_detector.model import HeuristicFlowScorer, MLFlowScorer, train_per_flow_model
from recon_detector.schemas import FlowRecord


def test_approved_features_are_one_way():
    # Must not raise.
    assert_features_are_one_way(APPROVED_FEATURES)


def test_forbidden_feature_rejected():
    with pytest.raises(ValueError):
        assert_features_are_one_way(["Total Backward Packets"])
    with pytest.raises(ValueError):
        assert_features_are_one_way(["Down/Up Ratio"])


def test_no_approved_feature_contains_forbidden_substring():
    for name in APPROVED_FEATURES:
        for bad in FORBIDDEN_SUBSTRINGS:
            assert bad.lower() not in name.lower()


def test_heuristic_scorer_bounds_and_ordering():
    s = HeuristicFlowScorer()
    scan = FlowRecord(timestamp=0, src_ip="a", dst_ip="b", dst_port=80,
                      packet_count=1, byte_count=0)
    benign = FlowRecord(timestamp=0, src_ip="a", dst_ip="b", dst_port=80,
                        packet_count=40, byte_count=40 * 800)
    sc_scan = s.score(scan)
    sc_benign = s.score(benign)
    assert 0.0 <= sc_benign <= sc_scan <= 1.0
    assert sc_scan > 0.8
    assert sc_benign < 0.3


def test_vectorize_uses_medians_for_missing():
    feats = ["Total Fwd Packets", "min_seg_size_forward"]
    row = vectorize_record(feats, explicit={}, packet_count=3, byte_count=6,
                           flow_duration=0.0, medians={"min_seg_size_forward": 20.0})
    assert row[0] == 3.0            # derived from packet_count
    assert row[1] == 20.0          # imputed from median


def test_ml_model_trains_and_scores_in_range():
    rng = np.random.default_rng(0)
    n = 400
    feats = list(APPROVED_FEATURES)
    # scan class: tiny flows; benign: bigger flows (col 0 = Total Fwd Packets)
    X = rng.random((n, len(feats)))
    y = np.zeros(n, dtype=int)
    X[: n // 2, 0] = rng.uniform(0, 1, n // 2)        # scan: few packets
    X[: n // 2, 1] = rng.uniform(0, 2, n // 2)        # scan: tiny bytes
    y[: n // 2] = 1
    X[n // 2 :, 0] = rng.uniform(20, 60, n - n // 2)  # benign: many packets
    X[n // 2 :, 1] = rng.uniform(500, 5000, n - n // 2)

    scorer = train_per_flow_model(X, y, feature_list=feats, n_estimators=25)
    scan_rec = FlowRecord(0, "a", "b", 80, packet_count=1, byte_count=0)
    benign_rec = FlowRecord(0, "a", "b", 80, packet_count=40, byte_count=40 * 800)
    assert 0.0 <= scorer.score(benign_rec) <= 1.0
    assert 0.0 <= scorer.score(scan_rec) <= 1.0
    assert scorer.scan_class_index in (0, 1)


def test_ml_model_save_load_roundtrip(tmp_path):
    rng = np.random.default_rng(1)
    feats = list(APPROVED_FEATURES)
    X = rng.random((100, len(feats)))
    y = (rng.random(100) > 0.5).astype(int)
    scorer = train_per_flow_model(X, y, feature_list=feats,
                                  medians={f: 1.0 for f in feats}, n_estimators=10)
    scorer.save(tmp_path)
    loaded = MLFlowScorer.load(tmp_path)
    assert loaded.feature_list == feats
    assert (tmp_path / "feature_list.json").exists()
    assert (tmp_path / "metadata.json").exists()
    rec = FlowRecord(0, "a", "b", 80, packet_count=1, byte_count=0)
    assert 0.0 <= loaded.score(rec) <= 1.0
