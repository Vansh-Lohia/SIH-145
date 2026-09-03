"""Certificate metadata features — TLS 1.2 ONLY (CLAUDE.md §6.3).

TLS 1.3 encrypts the certificate, so gate on TLS version and emit
`cert_features_available` so the model learns to ignore these when absent rather than
seeing silent zeros (CLAUDE.md §10: no silent zeros for missing cert features).

Features: self-signed flag, validity-window length, issuer, subject CN char entropy,
SAN count, SNI/subject mismatch, key size.

STUB — Build Order step 2 (bonus family).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CertFeatures:
    cert_features_available: bool = False
    self_signed: bool = False
    validity_days: float = 0.0
    subject_cn_entropy: float = 0.0
    san_count: int = 0
    sni_subject_mismatch: bool = False
    key_size: int = 0
    extra: dict[str, Any] = field(default_factory=dict)


def extract_cert_features(session: dict, tls_version: str) -> CertFeatures:
    """Return cert features; available only for TLS 1.2. STUB."""
    if not tls_version.startswith("TLS 1.2") and tls_version not in ("1.2", "771"):
        return CertFeatures(cert_features_available=False)
    raise NotImplementedError("Certificate features — Build Order step 2")
