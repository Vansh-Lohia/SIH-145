"""JA4+ fingerprints, constructed IN-HOUSE (CLAUDE.md §6.1).

We build JA4 ourselves — not only import a library — because we must be able to defend how
the fingerprint is constructed when questioned. Reference: FoxIO JA4+ specification.

Design rules honoured here:
- JA4 (ClientHello), JA4S (ServerHello), JA4X (certificate), JA4T (TCP options).
- RFC 8701 GREASE values are stripped BEFORE hashing/counting, else fingerprints are noise.
- JA4 SORTS cipher/extension lists before hashing (unlike JA3), so Chrome's per-connection
  extension-order randomisation does not destabilise the hash. **We never compute JA3.**
- Downstream these hashes are FEATURES (target/count encoding), never lookup-table keys —
  malware deliberately mimics browser fingerprints (CLAUDE.md §4, §6.1, §10).

Input shape (a parsed ClientHello / ServerHello as a plain dict, e.g. from Zeek ssl.log or
our synthetic generator):

    {
      "transport": "tcp" | "udp",          # udp => QUIC => 'q'
      "tls_version": 0x0303,               # legacy record version (int)
      "supported_versions": [0x0304, ...], # from the supported_versions extension (ints)
      "ciphers": [0x1301, ...],            # cipher suites in wire order (ints)
      "extensions": [0x0000, 0x0010, ...], # extension types in wire order (ints)
      "sig_algs": [0x0403, ...],           # signature_algorithms values (ints)
      "alpn": ["h2", "http/1.1"],          # ALPN protocol list (strings)
      "sni": "example.com" | None,
    }
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

# RFC 8701 GREASE values: 0x0a0a, 0x1a1a, ... 0xfafa. Strip before hashing/counting.
GREASE_VALUES = frozenset(
    (v << 8) | v for v in (0x0A, 0x1A, 0x2A, 0x3A, 0x4A, 0x5A, 0x6A, 0x7A,
                           0x8A, 0x9A, 0xAA, 0xBA, 0xCA, 0xDA, 0xEA, 0xFA)
)

# Extensions removed from the JA4_c *hash list* but still included in the extension COUNT:
# SNI (0x0000) and ALPN (0x0010). Per JA4 spec.
_SNI_EXT = 0x0000
_ALPN_EXT = 0x0010

_EMPTY_HASH = "000000000000"

_VERSION_MAP = {
    0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3",
    0xFEFF: "d1", 0xFEFD: "d2",  # DTLS
}


def is_grease(value: int) -> bool:
    return value in GREASE_VALUES


def _strip_grease(values: list[int]) -> list[int]:
    return [v for v in values if not is_grease(v)]


def _sha12(items: list[str]) -> str:
    """First 12 hex chars of sha256 over the comma-joined items ('' => zero hash)."""
    joined = ",".join(items)
    if joined == "":
        return _EMPTY_HASH
    return hashlib.sha256(joined.encode()).hexdigest()[:12]


def _hex4(v: int) -> str:
    return f"{v:04x}"


def _negotiated_version(ch: dict) -> str:
    """Highest offered TLS version: prefer supported_versions, else legacy record version."""
    sv = _strip_grease(ch.get("supported_versions") or [])
    if sv:
        best = max(sv)
        return _VERSION_MAP.get(best, "00")
    return _VERSION_MAP.get(ch.get("tls_version", 0), "00")


def _alpn_code(alpn: list[str] | None) -> str:
    """First ALPN value's first+last char (JA4 spec), or '00' if none."""
    if not alpn:
        return "00"
    first = alpn[0]
    if not first:
        return "00"
    return f"{first[0]}{first[-1]}"


@dataclass
class JA4Components:
    """Raw components exposed as features ALONGSIDE the hash (CLAUDE.md §6.1)."""
    transport: str = "t"
    tls_version: str = ""
    sni_present: bool = False
    cipher_count: int = 0
    extension_count: int = 0
    alpn: str = ""


def parse_ja4_a(ja4: str) -> JA4Components:
    """Recover the raw component features from a JA4 string's first segment.

    Lets us reuse a JA4 computed elsewhere (e.g. FoxIO's Zeek package in ssl.log) as
    features without the raw ClientHello. Layout of segment `a`:
        [0]=transport  [1:3]=version  [3]=sni(d/i)  [4:6]=cipher_count  [6:8]=ext_count  [8:10]=alpn
    e.g. "t13d3013h2" -> tcp, TLS1.3, SNI present, 30 ciphers, 13 extensions, ALPN "h2".
    """
    a = ja4.split("_", 1)[0]
    if len(a) < 10:
        return JA4Components()

    def _int(s: str) -> int:
        try:
            return int(s)
        except ValueError:
            return 0

    return JA4Components(
        transport=a[0],
        tls_version=a[1:3],
        sni_present=(a[3] == "d"),
        cipher_count=_int(a[4:6]),
        extension_count=_int(a[6:8]),
        alpn=a[8:10],
    )


def ja4_from_client_hello(client_hello: dict) -> tuple[str, JA4Components]:
    """Build the JA4 fingerprint of a ClientHello and its raw components.

    JA4 = <a>_<b>_<c> where
      a = transport(1) + version(2) + sni_flag(1) + cipher_count(2) + ext_count(2) + alpn(2)
      b = sha256_12(sorted GREASE-stripped ciphers as 4-hex)
      c = sha256_12(sorted GREASE-stripped extensions minus SNI/ALPN, "_", sig_algs in order)
    """
    transport = "q" if client_hello.get("transport") == "udp" else "t"
    version = _negotiated_version(client_hello)
    sni = client_hello.get("sni")
    sni_flag = "d" if sni else "i"

    ciphers = _strip_grease(client_hello.get("ciphers") or [])
    all_exts = _strip_grease(client_hello.get("extensions") or [])
    sig_algs = _strip_grease(client_hello.get("sig_algs") or [])
    alpn_list = client_hello.get("alpn") or []

    cipher_count = min(len(ciphers), 99)
    ext_count = min(len(all_exts), 99)  # count INCLUDES SNI and ALPN
    alpn_code = _alpn_code(alpn_list)

    a = f"{transport}{version}{sni_flag}{cipher_count:02d}{ext_count:02d}{alpn_code}"

    # b: ciphers sorted numerically, as 4-hex, comma-joined, hashed.
    b = _sha12([_hex4(c) for c in sorted(ciphers)])

    # c: extensions sorted (SNI + ALPN removed from the hash list), then sig_algs in ORDER.
    hash_exts = sorted(e for e in all_exts if e not in (_SNI_EXT, _ALPN_EXT))
    ext_part = ",".join(_hex4(e) for e in hash_exts)
    sig_part = ",".join(_hex4(s) for s in sig_algs)  # NOT sorted, per spec
    c_input = f"{ext_part}_{sig_part}" if sig_part else ext_part
    c = _sha12([c_input]) if c_input not in ("", "_") else _EMPTY_HASH

    ja4 = f"{a}_{b}_{c}"
    components = JA4Components(
        transport=transport, tls_version=version, sni_present=bool(sni),
        cipher_count=cipher_count, extension_count=ext_count, alpn=alpn_code,
    )
    return ja4, components


def ja4s_from_server_hello(server_hello: dict) -> str:
    """JA4S: <transport><version><ext_count(2)><alpn> _ <chosen_cipher 4hex> _ hash(exts)."""
    transport = "q" if server_hello.get("transport") == "udp" else "t"
    version = _negotiated_version(server_hello)
    exts = _strip_grease(server_hello.get("extensions") or [])
    ext_count = min(len(exts), 99)
    alpn_code = _alpn_code(server_hello.get("alpn"))
    chosen = server_hello.get("chosen_cipher")
    chosen_hex = _hex4(chosen) if isinstance(chosen, int) else "0000"
    a = f"{transport}{version}{ext_count:02d}{alpn_code}"
    c = _sha12([_hex4(e) for e in sorted(exts)])
    return f"{a}_{chosen_hex}_{c}"


def ja4x_from_certificate(cert: dict) -> str:
    """JA4X: hashes of issuer RDN OIDs _ subject RDN OIDs _ certificate extension OIDs.

    Degrades to zero-hashes for any component absent (TLS 1.3 hides the certificate).
    """
    issuer = cert.get("issuer_oids") or []
    subject = cert.get("subject_oids") or []
    ext_oids = cert.get("ext_oids") or []
    return "_".join((
        _sha12([str(x) for x in issuer]),
        _sha12([str(x) for x in subject]),
        _sha12([str(x) for x in ext_oids]),
    ))


def ja4t_from_tcp_options(tcp: dict) -> str:
    """JA4T: window_size _ tcp_options(in order) _ MSS _ window_scale."""
    window = tcp.get("window_size", 0)
    options = tcp.get("options") or []  # list of TCP option kinds in order
    mss = tcp.get("mss", 0)
    wscale = tcp.get("window_scale", 0)
    opt_str = "-".join(str(o) for o in options)
    return f"{window}_{opt_str}_{mss}_{wscale}"
