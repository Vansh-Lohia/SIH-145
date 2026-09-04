"""Feature-family unit tests: JA4 construction, GREASE stripping, SPLT, certificate gating."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from encdetect.features import ja4, splt, certificate  # noqa: E402
from encdetect.features.splt import Packet  # noqa: E402


def _chrome_hello(shuffle_seed=None):
    ch = {
        "transport": "tcp",
        "tls_version": 0x0303,
        "supported_versions": [0x0304],
        "ciphers": [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F],
        "extensions": [0x0000, 0x0017, 0x000A, 0x000B, 0x0010, 0x000D, 0x002B],
        "sig_algs": [0x0403, 0x0804, 0x0401],
        "alpn": ["h2", "http/1.1"],
        "sni": "example.com",
    }
    return ch


def test_ja4_is_stable_under_extension_reordering():
    """JA4 sorts before hashing, so shuffling extension order must NOT change the hash
    (the core reason we use JA4, not JA3)."""
    a = dict(_chrome_hello())
    b = dict(_chrome_hello())
    b["extensions"] = list(reversed(b["extensions"]))
    ja4_a, _ = ja4.ja4_from_client_hello(a)
    ja4_b, _ = ja4.ja4_from_client_hello(b)
    assert ja4_a == ja4_b


def test_ja4_grease_is_stripped():
    base = _chrome_hello()
    greased = dict(base)
    greased["ciphers"] = [0x0A0A] + list(base["ciphers"])      # prepend a GREASE cipher
    greased["extensions"] = [0x1A1A] + list(base["extensions"])
    assert ja4.ja4_from_client_hello(base)[0] == ja4.ja4_from_client_hello(greased)[0]


def test_ja4_format_and_components():
    ja4_hash, comp = ja4.ja4_from_client_hello(_chrome_hello())
    a, b, c = ja4_hash.split("_")
    assert a[0] == "t"           # TLS over TCP
    assert a[1:3] == "13"        # TLS 1.3 from supported_versions
    assert a[3] == "d"           # SNI present
    assert len(b) == 12 and len(c) == 12
    assert comp.sni_present is True
    assert comp.cipher_count == 5


def test_ja4_quic_transport_flag():
    ch = _chrome_hello()
    ch["transport"] = "udp"
    ja4_hash, comp = ja4.ja4_from_client_hello(ch)
    assert ja4_hash[0] == "q"
    assert comp.transport == "q"


def test_splt_summary_and_sequence_shapes():
    pkts = [Packet(100, 1, 0.0), Packet(1400, -1, 12.0), Packet(1400, -1, 3.0),
            Packet(200, 1, 50.0)]
    stats = splt.summary_stats(pkts)
    assert stats["pkt_count"] == 4
    assert stats["burst_count"] == 3          # up, down(x2), up  -> 3 runs
    assert stats["up_pkt_count"] == 2 and stats["down_pkt_count"] == 2
    seq = splt.raw_sequence(pkts, n=6)
    assert len(seq) == 6                        # right-padded to N
    assert seq[-1] == (0, 0, 0.0)


def test_certificate_gated_on_tls12():
    cert = {"self_signed": True, "not_before": 0, "not_after": 30 * 86400,
            "subject_cn": "xyz", "sans": [], "key_size": 1024}
    tls13 = certificate.extract_cert_features({"cert": cert}, "TLS 1.3")
    assert tls13.cert_features_available is False   # encrypted under TLS 1.3
    tls12 = certificate.extract_cert_features({"cert": cert}, "TLS 1.2")
    assert tls12.cert_features_available is True
    assert tls12.self_signed is True
    assert tls12.validity_days == 30.0
