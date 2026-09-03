"""Label sidecar matching + application (CLAUDE.md §8)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from encdetect.labels import LabelRule, apply_labels  # noqa: E402
from encdetect.features.session import Session, FlowKey  # noqa: E402


def _sess(src="10.0.0.5", dst="1.2.3.4", ts=100.0):
    return Session(flow=FlowKey(src_ip=src, src_port=443, dst_ip=dst, dst_port=443,
                                proto="tcp"), start_ts=ts)


def test_whole_capture_rule_labels_everything():
    rules = [LabelRule(label="malicious", family="dridex")]
    sessions = [_sess(), _sess(dst="9.9.9.9")]
    apply_labels(sessions, rules)
    assert all(s.label == "malicious" and s.family == "dridex" for s in sessions)


def test_ip_selector_matches_either_direction():
    rule = LabelRule(label="malicious", family="c2", dst_ip="1.2.3.4")
    assert rule.matches(_sess(dst="1.2.3.4"))
    assert rule.matches(_sess(src="1.2.3.4", dst="8.8.8.8"))   # either side counts
    assert not rule.matches(_sess(dst="8.8.8.8"))


def test_time_window_gate():
    rule = LabelRule(label="malicious", start_ts=50.0, end_ts=150.0)
    assert rule.matches(_sess(ts=100.0))
    assert not rule.matches(_sess(ts=200.0))


def test_most_specific_rule_wins():
    rules = [
        LabelRule(label="benign"),                                   # wildcard
        LabelRule(label="malicious", family="dridex", dst_ip="1.2.3.4"),  # specific
    ]
    s = _sess(dst="1.2.3.4")
    apply_labels([s], rules)
    assert s.label == "malicious" and s.family == "dridex"


def test_default_label_when_no_rule_matches():
    s = _sess(dst="8.8.8.8")
    apply_labels([s], [LabelRule(label="malicious", dst_ip="1.2.3.4")],
                 default_label="benign")
    assert s.label == "benign"
