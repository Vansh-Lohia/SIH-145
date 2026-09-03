"""Synthetic TLS/QUIC session generator (PROTOTYPE / DEMO ONLY).

Produces `Session` objects with realistic-ish handshake, shape/timing, and (TLS 1.2)
certificate features, plus label metadata (pcap/family/environment). See package docstring
for why each family has a distinct signature.
"""
from __future__ import annotations

import numpy as np

from ..features.session import Session, FlowKey
from ..features.splt import Packet

_SIG_ALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
_GREASE = [0x0A0A, 0x1A1A, 0x2A2A]
_TLS13 = [0x0304]
_TLS12 = [0x0303]

# --- Handshake TEMPLATES ---------------------------------------------------------------
# Real TLS fingerprints are SHARED across many sessions — that is the whole point of a
# fingerprint. So each session draws a fixed template, producing a SMALL number of distinct
# JA4 values that recur across hundreds of sessions (making count/target encoding meaningful
# and non-leaky). GREASE + per-session extension shuffling is applied, but JA4 sorts before
# hashing so the fingerprint stays stable — demonstrating why JA4 beats JA3.
#
# Crucially, browser-mimicking malware (cobaltstrike, quicc2) draws the SAME browser
# templates as benign traffic, so their JA4 is indistinguishable from a real browser's —
# the "malware mimics browser fingerprints" reality (CLAUDE.md §6.1).
_TEMPLATES = {
    "chrome_tls13": dict(quic=False, tls13=True, browser_like=True,
        ciphers=[0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9],
        exts=[0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010, 0x000D, 0x002B,
              0x002D, 0x0033, 0x001B], alpn=["h2", "http/1.1"]),
    "firefox_tls13": dict(quic=False, tls13=True, browser_like=True,
        ciphers=[0x1301, 0x1303, 0x1302, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC030],
        exts=[0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010, 0x000D, 0x002B,
              0x002D, 0x0033, 0x0005], alpn=["h2", "http/1.1"]),
    "chrome_quic": dict(quic=True, tls13=True, browser_like=True,
        ciphers=[0x1301, 0x1302, 0x1303],
        exts=[0x0000, 0x0017, 0xFF01, 0x000A, 0x000D, 0x002B, 0x002D, 0x0033, 0x0039],
        alpn=["h3"]),
    # crude/older malware handshakes — their OWN fingerprints, distinct from browsers.
    "trickbot_tls12": dict(quic=False, tls13=False, browser_like=False,
        ciphers=[0xC02F, 0xC030, 0x009C, 0x009D, 0x002F],
        exts=[0x0000, 0x000A, 0x000B, 0x000D, 0xFF01], alpn=[]),
    "zeus_tls12": dict(quic=False, tls13=False, browser_like=False,
        ciphers=[0xC013, 0xC014, 0x002F, 0x0035],
        exts=[0x0000, 0x000A, 0x000B, 0xFF01], alpn=[]),
}


def _client_hello(rng, *, template, sni):
    t = _TEMPLATES[template]
    ciphers = list(t["ciphers"])
    exts = list(t["exts"])
    if sni and 0x0000 not in exts:
        exts.append(0x0000)
    if t["browser_like"]:  # Chrome-style GREASE + shuffled ext order (JA4 sorts it out)
        ciphers = [int(rng.choice(_GREASE))] + ciphers
        exts = [int(rng.choice(_GREASE))] + exts
        rng.shuffle(exts)
    return {
        "transport": "udp" if t["quic"] else "tcp",
        "tls_version": 0x0303,
        "supported_versions": (_TLS13 if t["tls13"] else _TLS12),
        "ciphers": ciphers,
        "extensions": exts,
        "sig_algs": _SIG_ALGS[:5],
        "alpn": t["alpn"],
        "sni": sni,
    }


def _packets(rng, *, n, up_bias, base_size, size_jitter, iat_mean, iat_jitter, beacon):
    pkts = []
    for i in range(n):
        direction = 1 if rng.random() < up_bias else -1
        size = max(40, int(rng.normal(base_size, size_jitter)))
        if beacon:  # near-periodic C2 beacon: low IAT variance
            iat = max(0.0, rng.normal(iat_mean, iat_jitter * 0.15))
        else:       # human/browser: bursty, heavy-tailed IATs
            iat = 0.0 if i == 0 else max(0.0, rng.exponential(iat_mean))
        pkts.append(Packet(size=size, direction=direction, inter_arrival_ms=iat))
    return pkts


def _cert(rng, *, self_signed, benign):
    not_before = 1_700_000_000.0
    validity = rng.uniform(300, 800) * 86400 if benign else rng.uniform(1, 90) * 86400
    cn = "example-cdn.net" if benign else "".join(
        rng.choice(list("abcdefghijklmnopqrstuvwxyz0123456789"), size=rng.integers(8, 20)))
    return {
        "self_signed": self_signed,
        "not_before": not_before,
        "not_after": not_before + validity,
        "subject_cn": cn,
        "sans": (["example-cdn.net", "*.example-cdn.net"] if benign else []),
        "key_size": int(rng.choice([2048, 3072, 4096]) if benign else rng.choice([1024, 2048])),
    }


# family -> generator config. benign is its own "family" bucket.
#
# `templates` = the handshake fingerprints this family emits. Browser-mimicking families
# (cobaltstrike, quicc2) reuse the SAME browser templates as benign, so JA4 cannot separate
# them. Families deliberately OVERLAP benign in shape/timing too, so no single universal
# "malicious" signal transfers cleanly to a held-out family. trickbot/zeus beacon AND carry
# their own JA4 (both partly generalise); cobaltstrike mimics a browser and does NOT beacon,
# so when held out it is nearly invisible — dragging the leave-one-family-out mean below the
# random-split number, exactly the effect CLAUDE.md §7 warns about.
_MAL_FAMILIES = {
    "trickbot":     dict(templates=["trickbot_tls12"], up_bias=0.42, base_size=340,
                         iat_mean=70, beacon=True, self_signed=True),
    "zeus":         dict(templates=["zeus_tls12"], up_bias=0.45, base_size=300,
                         iat_mean=95, beacon=True, self_signed=True),
    "cobaltstrike": dict(templates=["chrome_tls13", "firefox_tls13"], up_bias=0.36,
                         base_size=400, iat_mean=55, beacon=False, self_signed=False),
    "quicc2":       dict(templates=["chrome_quic"], up_bias=0.5, base_size=280,
                         iat_mean=80, beacon=True, self_signed=False),
}

_BENIGN_TEMPLATES = ["chrome_tls13", "firefox_tls13", "chrome_quic"]


def _make_session(rng, label, family, environment, pcap, n_packets):
    if label == "benign":
        cfg = dict(up_bias=0.34, base_size=400, iat_mean=50, beacon=False, self_signed=False)
        template = _BENIGN_TEMPLATES[int(rng.integers(len(_BENIGN_TEMPLATES)))]
    else:
        cfg = _MAL_FAMILIES[family]
        tmpls = cfg["templates"]
        template = tmpls[int(rng.integers(len(tmpls)))]

    sni = (None if (label == "malicious" and rng.random() < 0.4)
           else f"host{rng.integers(1000)}.example.com")
    ch = _client_hello(rng, template=template, sni=sni)
    pkts = _packets(rng, n=n_packets, up_bias=cfg["up_bias"], base_size=cfg["base_size"],
                    size_jitter=cfg["base_size"] * 0.3, iat_mean=cfg["iat_mean"],
                    iat_jitter=cfg["iat_mean"], beacon=cfg["beacon"])
    tls13 = _TEMPLATES[template]["tls13"]
    is_quic = _TEMPLATES[template]["quic"]
    cert = None if tls13 else _cert(rng, self_signed=cfg["self_signed"],
                                    benign=(label == "benign"))
    # realistic capture epoch (base + up to ~30 days of spread) so alert windows read sanely
    start = 1_700_000_000.0 + float(rng.uniform(0, 30 * 86400))
    return Session(
        flow=FlowKey(src_ip="10.0.0.%d" % rng.integers(2, 254),
                     src_port=int(rng.integers(1024, 65535)),
                     dst_ip="203.0.113.%d" % rng.integers(1, 254),
                     dst_port=443,
                     proto=("udp" if is_quic else "tcp")),
        client_hello=ch, cert=cert,
        tcp={"window_size": int(rng.choice([64240, 65535, 29200])),
             "options": [2, 4, 8, 1, 3], "mss": 1460,
             "window_scale": int(rng.choice([7, 8]))},
        packets=pkts,
        tls_version_str=("TLS 1.3" if tls13 else "TLS 1.2"),
        start_ts=start, end_ts=start + sum(p.inter_arrival_ms for p in pkts) / 1000.0,
        label=label, family=("" if label == "benign" else family),
        environment=environment, pcap=pcap,
    )


def generate_dataset(n_benign=1500, n_per_family=200, n_packets=20,
                     seed=42) -> list[Session]:
    """Generate a labelled set of Sessions grouped into pcap 'capture files'.

    ~10 sessions per pcap so split-by-capture and leave-one-family-out are meaningful.
    """
    rng = np.random.default_rng(seed)
    sessions: list[Session] = []

    # benign: environment 'lab', spread across capture files
    for i in range(n_benign):
        pcap = f"benign_run_{i // 15:03d}.pcap"
        sessions.append(_make_session(rng, "benign", "", "lab", pcap, n_packets))

    # malicious: one environment 'sandbox', capture files per family
    for family in _MAL_FAMILIES:
        for i in range(n_per_family):
            pcap = f"{family}_{i // 10:03d}.pcap"
            sessions.append(_make_session(rng, "malicious", family, "sandbox", pcap, n_packets))

    rng.shuffle(sessions)
    return sessions


MALWARE_FAMILIES = tuple(_MAL_FAMILIES.keys())
