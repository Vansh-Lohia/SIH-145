"""Unified session view + featurizer (CLAUDE.md §3, §6).

A `Session` bundles everything observable about one TLS/QUIC flow — handshake, packet
shape/timing, optional certificate — plus the label metadata (`pcap`, `family`,
`environment`) that the evaluation protocol depends on (CLAUDE.md §7, §8).

`featurize()` produces:
  - `tabular`: a flat dict of numeric features for the LightGBM baseline
  - `sequence`: the fixed-length SPLT array for the 1D-CNN
  - `availability`: fraction of each feature family that was observable (CLAUDE.md §3 —
    "Log the fraction of sessions where each family was available; report it.")

Each family degrades to neutral values (with an availability flag) rather than breaking,
so losing a family degrades the detector instead of crashing it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import ja4, splt, certificate
from .splt import Packet


@dataclass
class FlowKey:
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    proto: str = "tcp"


@dataclass
class Session:
    flow: FlowKey = field(default_factory=FlowKey)
    client_hello: dict[str, Any] | None = None
    server_hello: dict[str, Any] | None = None
    cert: dict[str, Any] | None = None
    tcp: dict[str, Any] | None = None
    packets: list[Packet] = field(default_factory=list)
    # JA4 already computed upstream (e.g. FoxIO's Zeek package in ssl.log). When set,
    # featurize() uses it directly instead of recomputing from a raw ClientHello.
    ja4_precomputed: str = ""
    ja4s: str = ""
    tls_version_str: str = ""          # e.g. "TLS 1.2" / "TLS 1.3" (from ssl.log)
    start_ts: float = 0.0
    end_ts: float = 0.0

    # label metadata (carried end to end; see labels sidecar, CLAUDE.md §8)
    label: str = ""                    # "benign" | "malicious"
    family: str = ""
    environment: str = ""
    pcap: str = ""


@dataclass
class FeatureBundle:
    tabular: dict[str, float]
    sequence: list[tuple[int, int, float]]
    availability: dict[str, bool]
    ja4: str
    label: str
    family: str
    environment: str
    pcap: str


def featurize(session: Session, n_packets: int = splt.DEFAULT_N) -> FeatureBundle:
    tabular: dict[str, float] = {}
    availability: dict[str, bool] = {}

    # --- Family 1: shape / timing (always available) ---
    tabular.update(splt.summary_stats(session.packets))
    sequence = splt.raw_sequence(session.packets, n=n_packets)
    availability["shape"] = len(session.packets) > 0

    # --- Family 2: handshake fingerprint (JA4+) ---
    ja4_hash = ""
    comp = None
    if session.ja4_precomputed:
        # JA4 from ssl.log (FoxIO). Recover component features by parsing the string.
        ja4_hash = session.ja4_precomputed
        comp = ja4.parse_ja4_a(ja4_hash)
    elif session.client_hello:
        ja4_hash, comp = ja4.ja4_from_client_hello(session.client_hello)
    if comp is not None:
        tabular["ja4_cipher_count"] = float(comp.cipher_count)
        tabular["ja4_ext_count"] = float(comp.extension_count)
        tabular["ja4_sni_present"] = float(comp.sni_present)
        tabular["ja4_is_quic"] = float(comp.transport == "q")
        availability["handshake"] = True
    else:
        tabular.update({
            "ja4_cipher_count": 0.0, "ja4_ext_count": 0.0,
            "ja4_sni_present": 0.0, "ja4_is_quic": 0.0,
        })
        availability["handshake"] = False

    # --- Family 3: certificate (TLS 1.2 only) ---
    tls_ver = session.tls_version_str or (
        (session.client_hello or {}).get("tls_version")
    )
    cert_feats = certificate.extract_cert_features(
        {"cert": session.cert, "sni": (session.client_hello or {}).get("sni")}, tls_ver
    )
    tabular.update(cert_feats.to_dict())
    availability["certificate"] = cert_feats.cert_features_available

    return FeatureBundle(
        tabular=tabular, sequence=sequence, availability=availability, ja4=ja4_hash,
        label=session.label, family=session.family,
        environment=session.environment, pcap=session.pcap,
    )


# Stable, ordered feature-name list for building matrices (JA4 hash handled separately as a
# categorical/count-encoded feature by the baseline model, not as a raw column here).
TABULAR_FEATURE_NAMES: list[str] = (
    splt.SUMMARY_FEATURE_NAMES
    + ["ja4_cipher_count", "ja4_ext_count", "ja4_sni_present", "ja4_is_quic"]
    + certificate.CERT_FEATURE_NAMES
)
