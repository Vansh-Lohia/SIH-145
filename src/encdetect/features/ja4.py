"""JA4+ fingerprints, constructed IN-HOUSE (CLAUDE.md §6.1).

We build JA4 ourselves — not only import a library — because we must defend how the
fingerprint is constructed when questioned.

Rules:
- JA4 (ClientHello), JA4S (ServerHello), JA4X (certificate), JA4T (TCP options).
- Strip RFC 8701 GREASE values BEFORE hashing, else fingerprints are noise.
- JA4 sorts cipher/extension lists before hashing (unlike JA3), so Chrome's per-connection
  extension-order randomisation does not destabilise the hash. Never use JA3.
- Downstream these are FEATURES (target/count encoding), never lookup-table keys — malware
  deliberately mimics browser fingerprints (CLAUDE.md §4, §6.1, §10).

STUB — Build Order step 2.
"""
from __future__ import annotations

from dataclasses import dataclass

# RFC 8701 GREASE values (0x0a0a, 0x1a1a, ... 0xfafa) — strip before hashing.
GREASE_VALUES = frozenset(
    (v << 8) | v for v in (0x0A, 0x1A, 0x2A, 0x3A, 0x4A, 0x5A, 0x6A, 0x7A,
                           0x8A, 0x9A, 0xAA, 0xBA, 0xCA, 0xDA, 0xEA, 0xFA)
)


def is_grease(value: int) -> bool:
    return value in GREASE_VALUES


@dataclass
class JA4Components:
    """Raw components exposed as features alongside the hash (CLAUDE.md §6.1)."""
    tls_version: str = ""
    cipher_count: int = 0
    extension_count: int = 0
    alpn: str = ""
    sni_present: bool = False


def ja4_from_client_hello(client_hello: dict) -> tuple[str, JA4Components]:
    """Return (ja4_hash, components) from a parsed ClientHello. STUB."""
    raise NotImplementedError("JA4 — Build Order step 2")


def ja4s_from_server_hello(server_hello: dict) -> str:
    raise NotImplementedError


def ja4x_from_certificate(cert: dict) -> str:
    raise NotImplementedError


def ja4t_from_tcp_options(tcp_options: dict) -> str:
    raise NotImplementedError
