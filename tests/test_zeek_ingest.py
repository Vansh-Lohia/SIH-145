"""Reader tests against committed REAL Zeek output (Zeek 8.0.10 + FoxIO JA4 + splt.zeek).

Fixtures in tests/fixtures/zeek/test/ were produced from a small TLS 1.3 capture
(google + wikipedia). No WSL/Zeek needed to run these.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from encdetect.ingest.zeek_reader import sessions_from_log_dir  # noqa: E402
from encdetect.features.session import featurize  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures" / "zeek" / "test"
FIX_EMOTET = Path(__file__).resolve().parent / "fixtures" / "zeek" / "emotet_like"


def test_reads_real_ssl_log_sessions():
    sessions = sessions_from_log_dir(FIX, label="benign", environment="lab", pcap="test.pcap")
    assert len(sessions) == 2
    s = sessions[0]
    assert s.flow.dst_port == 443
    assert s.flow.proto == "tcp"
    assert s.tls_version_str == "TLS 1.3"
    # FoxIO JA4 carried through verbatim from ssl.log
    assert s.ja4_precomputed.startswith("t13d3013h2_")
    assert s.ja4s.startswith("t130200_")
    # label metadata attached
    assert s.label == "benign" and s.pcap == "test.pcap"


def test_real_splt_sequence_present():
    sessions = sessions_from_log_dir(FIX)
    s = next(x for x in sessions if x.packets)
    assert len(s.packets) >= 20                     # real per-packet SPLT from splt.zeek
    assert s.packets[0].inter_arrival_ms == 0.0     # first packet has no predecessor
    assert any(p.direction == 1 for p in s.packets)
    assert any(p.direction == -1 for p in s.packets)


def test_featurize_real_session_end_to_end():
    sessions = sessions_from_log_dir(FIX)
    bundles = [featurize(s) for s in sessions]
    b = bundles[0]
    # handshake + shape available; certificate absent under TLS 1.3 (correctly gated)
    assert b.availability["handshake"] is True
    assert b.availability["shape"] is True
    assert b.availability["certificate"] is False
    # JA4 string parsed into component features
    assert b.tabular["ja4_cipher_count"] == 30.0
    assert b.tabular["ja4_ext_count"] == 13.0
    assert b.tabular["ja4_sni_present"] == 1.0
    assert b.tabular["ja4_is_quic"] == 0.0
    # real shape features are populated (not silent zeros)
    assert b.tabular["pkt_count"] >= 20
    assert b.tabular["total_bytes"] > 0


def test_foxio_empty_ja4_sentinel_treated_as_no_value():
    """Regression test: FoxIO's JA4 package emits the literal string "(empty)" in ja4 when
    it can't compute a hash (seen on 100% of a real Emotet capture, 14,060 sessions). Before
    the fix this was carried through as if it were a real, universally-shared fingerprint,
    which would corrupt JA4 target encoding across the whole family. It must be normalised
    to "no value" like Zeek's own "-" unset marker, and handshake must report unavailable."""
    sessions = sessions_from_log_dir(FIX_EMOTET)
    assert len(sessions) == 1
    s = sessions[0]
    assert s.ja4_precomputed == ""            # NOT the literal string "(empty)"
    assert s.ja4s == "t100100_c013_bcb145a8c2a7"   # a real ja4s is preserved verbatim

    bundle = featurize(s)
    assert bundle.ja4 == ""
    assert bundle.availability["handshake"] is False
