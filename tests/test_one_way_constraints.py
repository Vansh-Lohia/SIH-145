"""Tests that enforce the strict one-way / passive constraints (spec sections
4, 13, 27, 28).  These are the security-critical guarantees of the component.
"""

import builtins
import socket

import pytest

from recon_detector import APPROVED_FEATURES, ReconDetector
from recon_detector import synthetic
from recon_detector.features import FORBIDDEN_SUBSTRINGS
from recon_detector.baselines import TRWResearchBaseline


def test_no_backward_or_reverse_features():
    banned = ["bwd", "backward", "syn", "rst", "ack flag", "down/up", "ratio",
              "reverse"]
    for name in APPROVED_FEATURES:
        low = name.lower()
        for b in banned:
            assert b not in low, f"{name} looks reverse-direction derived"
    # and the guard list itself catches them
    assert any("bwd" in s.lower() for s in FORBIDDEN_SUBSTRINGS)


def test_detection_works_with_only_forward_records():
    # Records only ever describe A -> B; there is no B -> A anywhere.
    det = ReconDetector()
    fired = False
    for rec in synthetic.vertical_scan(n_ports=40):
        assert "src_ip" in rec and "dst_ip" in rec
        res = det.process(rec)
        fired = fired or res.detected
    assert fired


def test_no_network_sockets_opened(monkeypatch):
    """Processing must be purely computational -- no sockets, ever."""
    def _boom(*a, **k):
        raise AssertionError("detector attempted to create a network socket")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    # getaddrinfo would be used by any DNS / reverse-DNS attempt
    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    monkeypatch.setattr(socket, "gethostbyname", _boom, raising=False)
    monkeypatch.setattr(socket, "gethostbyaddr", _boom, raising=False)

    det = ReconDetector()
    for rec in synthetic.mixed_scan(n_hosts=10, n_ports=10):
        det.process(rec)  # must not raise
    for rec in synthetic.benign_high_fanout(n=100):
        det.process(rec)


def test_no_file_or_url_opened_during_processing(monkeypatch):
    """The detector must not read files or open URLs while processing records."""
    real_open = builtins.open

    def _no_open(*a, **k):
        raise AssertionError("detector attempted file I/O during processing")

    det = ReconDetector()  # construct first (no model file needed)
    monkeypatch.setattr(builtins, "open", _no_open)
    try:
        for rec in synthetic.vertical_scan(n_ports=30):
            det.process(rec)
    finally:
        monkeypatch.setattr(builtins, "open", real_open)


def test_trw_refuses_without_connection_outcomes():
    """Classical TRW needs connection outcomes; under strict one-way we have
    none and must NOT fabricate them."""
    trw = TRWResearchBaseline()
    with pytest.raises(ValueError):
        trw.update("1.1.1.1", connection_success=None)


def test_no_connection_outcome_fields_required():
    # A record with only observed-direction fields is fully processable.
    det = ReconDetector()
    r = det.process({
        "timestamp": 1.0, "src_ip": "9.9.9.9", "dst_ip": "10.0.0.1",
        "dst_port": 22, "protocol": "TCP",
        "packet_count": 1, "byte_count": 0, "flow_duration": 0.0,
    })
    assert 0.0 <= r.score <= 1.0
