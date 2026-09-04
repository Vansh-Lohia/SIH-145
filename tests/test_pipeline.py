"""End-to-end smoke tests: featurize -> baseline -> honest eval -> streaming alerts."""
import asyncio
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from encdetect.data_gen.synthetic import generate_dataset  # noqa: E402
from encdetect.features.session import featurize  # noqa: E402
from encdetect.models.baseline_lgbm import LgbmBaseline  # noqa: E402
from encdetect.eval import protocol, metrics  # noqa: E402
from encdetect.streaming.pipeline import run_pipeline  # noqa: E402


def _labels(bundles):
    return np.array([1 if b.label == "malicious" else 0 for b in bundles], dtype=int)


def test_shared_ja4_cardinality_is_realistic():
    """Fingerprints must be SHARED across sessions (not unique per session), else target
    encoding leaks the label. Guards the bug fixed during prototype bring-up."""
    bundles = [featurize(s) for s in generate_dataset(n_benign=300, n_per_family=80, seed=1)]
    distinct = len({b.ja4 for b in bundles})
    assert 3 <= distinct <= 40, f"unrealistic JA4 cardinality: {distinct}"


def test_baseline_scores_are_calibrated_and_separating():
    bundles = [featurize(s) for s in generate_dataset(n_benign=600, n_per_family=120, seed=2)]
    tr, te = protocol.split_by_capture_file(bundles, test_fraction=0.3, seed=3)
    model = LgbmBaseline().fit(tr)
    score = model.predict_proba(te)
    y = _labels(te)
    assert score[y == 1].mean() > 0.6      # malicious scored high
    assert score[y == 0].mean() < 0.2      # benign scored low


def test_leave_one_family_out_is_harder_than_random():
    """The headline (LOFO) number should be <= the optimistic random-split number."""
    bundles = [featurize(s) for s in generate_dataset(n_benign=800, n_per_family=150, seed=4)]
    tr, te = protocol.split_by_capture_file(bundles, test_fraction=0.3, seed=5)
    rand_tpr, _ = metrics.tpr_at_fixed_fpr(
        _labels(te), LgbmBaseline().fit(tr).predict_proba(te), fpr=0.001)

    lofo = []
    for train, test, _held in protocol.leave_one_family_out(bundles):
        s = LgbmBaseline().fit(train).predict_proba(test)
        lofo.append(metrics.tpr_at_fixed_fpr(_labels(test), s, fpr=0.001)[0])
    assert np.mean(lofo) <= rand_tpr + 1e-9


def test_lofo_never_trains_with_zero_benign():
    """Regression test: when benign spans too few pcaps, split_by_capture_file's
    at-least-one-pcap rounding can put ALL benign into test, silently training on
    malicious-only data. leave_one_family_out must fall back rather than yield that."""
    bundles = [featurize(s) for s in generate_dataset(n_benign=40, n_per_family=80, seed=11)]
    # collapse every benign session onto a single synthetic pcap, reproducing the bug found
    # while diagnosing a real single-pcap live-capture benign source.
    for b in bundles:
        if b.label == "benign":
            b.pcap = "only_one_benign_capture.pcap"

    for train, test, held in protocol.leave_one_family_out(bundles):
        n_benign_train = sum(1 for b in train if b.label == "benign")
        assert n_benign_train > 0, f"held={held}: train has zero benign examples"


def test_split_by_capture_file_test_set_is_not_dominated_by_a_tiny_pcap():
    """Regression test: with pcaps of very unequal size (one 2-session fixture alongside
    much larger real captures), picking test pcaps by COUNT rather than session WEIGHT can
    land the whole test set on the tiny one -- non-empty, but statistically meaningless.
    Found while computing precision/recall on real CTU data: every leave-one-family-out
    fold's benign test set turned out to be the same 2-session fixture pcap."""
    bundles = [featurize(s) for s in generate_dataset(n_benign=400, n_per_family=1, seed=12)]
    # simulate: one tiny 2-session pcap plus the rest spread across several larger pcaps
    tiny = [b for b in bundles if b.label == "benign"][:2]
    for b in tiny:
        b.pcap = "tiny_fixture.pcap"
    for i, b in enumerate(b for b in bundles if b.label == "benign" and b not in tiny):
        b.pcap = f"large_capture_{i // 100}.pcap"

    _, test = protocol.split_by_capture_file(bundles, test_fraction=0.3, seed=13)
    assert len(test) > 10, (
        f"test split has only {len(test)} sessions -- likely landed on the tiny pcap alone")


def test_no_flow_from_same_pcap_crosses_split():
    bundles = [featurize(s) for s in generate_dataset(n_benign=300, n_per_family=80, seed=6)]
    tr, te = protocol.split_by_capture_file(bundles, test_fraction=0.3, seed=7)
    assert {b.pcap for b in tr}.isdisjoint({b.pcap for b in te})


def test_streaming_emits_schema_conformant_alerts():
    bundles = [featurize(s) for s in generate_dataset(n_benign=600, n_per_family=120, seed=8)]
    tr, te = protocol.split_by_capture_file(bundles, test_fraction=0.3, seed=9)
    model = LgbmBaseline().fit(tr)
    _, threshold = metrics.tpr_at_fixed_fpr(
        _labels(te), model.predict_proba(te), fpr=0.001)

    sessions = generate_dataset(n_benign=100, n_per_family=30, seed=10)
    emitted = []
    result = asyncio.run(run_pipeline(sessions, model, threshold, on_alert=emitted.append))
    assert result.n_sessions == len(sessions)
    assert emitted, "expected at least one alert"
    a = emitted[0]
    for field in ("alert_id", "detector", "flow_id", "severity", "confidence",
                  "window", "evidence"):
        assert field in a
    assert a["detector"] == "encrypted_session_v1"
    assert 0.0 <= a["confidence"] <= 1.0
    assert result.p99_latency_s() < 30.0
