"""Certificate metadata features — TLS 1.2 ONLY (CLAUDE.md §6.3).

TLS 1.3 encrypts the certificate, so we GATE on TLS version and emit
`cert_features_available` so the model learns to ignore these when absent rather than
seeing silent zeros (CLAUDE.md §10: no silent zeros for missing cert features).
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import Any

_TLS12_MARKERS = ("TLS 1.2", "TLSv1.2", "1.2", "771", 0x0303)


@dataclass
class CertFeatures:
    cert_features_available: bool = False
    self_signed: bool = False
    validity_days: float = 0.0
    subject_cn_entropy: float = 0.0
    san_count: int = 0
    sni_subject_mismatch: bool = False
    key_size: int = 0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # bools -> floats so everything is model-ready and uniform.
        return {k: float(v) if isinstance(v, bool) else v for k, v in d.items()}


def _char_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_tls12(tls_version: Any) -> bool:
    if isinstance(tls_version, (int, float)):
        return int(tls_version) == 0x0303
    return any(str(tls_version).startswith(str(m)) for m in _TLS12_MARKERS if isinstance(m, str))


def extract_cert_features(session: dict, tls_version: Any) -> CertFeatures:
    """Return cert features; populated only for TLS 1.2 (else availability flag stays False).

    `session` may carry a `cert` sub-dict with: self_signed, not_before, not_after (epoch s),
    subject_cn, sans (list), sni, key_size.
    """
    if not _is_tls12(tls_version):
        return CertFeatures(cert_features_available=False)

    cert = session.get("cert") or {}
    if not cert:
        return CertFeatures(cert_features_available=False)

    not_before = float(cert.get("not_before", 0.0))
    not_after = float(cert.get("not_after", 0.0))
    validity_days = max(0.0, (not_after - not_before) / 86400.0)

    subject_cn = cert.get("subject_cn", "") or ""
    sans = cert.get("sans") or []
    sni = cert.get("sni") or session.get("sni") or ""

    mismatch = bool(sni) and sni != subject_cn and sni not in sans

    return CertFeatures(
        cert_features_available=True,
        self_signed=bool(cert.get("self_signed", False)),
        validity_days=validity_days,
        subject_cn_entropy=_char_entropy(subject_cn),
        san_count=len(sans),
        sni_subject_mismatch=mismatch,
        key_size=int(cert.get("key_size", 0)),
    )


CERT_FEATURE_NAMES = [
    "cert_features_available", "self_signed", "validity_days",
    "subject_cn_entropy", "san_count", "sni_subject_mismatch", "key_size",
]
