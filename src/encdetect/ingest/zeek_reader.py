"""Stream Zeek TSV/JSON logs into per-session records (CLAUDE.md §4, Build Order step 1).

Read-only and offline: this parses files Zeek has already written from observed traffic. It
NEVER contacts a host, resolves a name, or looks anything up over a network (CLAUDE.md §2).

Supports both Zeek output styles:
  - default TSV logs (with the `#fields` header line)
  - JSON-lines logs (one JSON object per line, `LogAscii::use_json=T`)

The `uid` field joins conn/ssl/x509 records for the same session.
"""
from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..features.session import Session, FlowKey
from ..features.splt import Packet

# Zeek ssl.log `version` string -> our TLS version label (drives certificate gating).
_TLS_VERSION_MAP = {
    "TLSv13": "TLS 1.3", "TLSv12": "TLS 1.2", "TLSv11": "TLS 1.1", "TLSv10": "TLS 1.0",
    "DTLSv12": "DTLS 1.2", "DTLSv10": "DTLS 1.0",
}


def read_zeek_log(path: str | Path) -> Iterator[dict[str, Any]]:
    """Yield one dict per record from a Zeek log (conn/ssl/x509), TSV or JSON."""
    path = Path(path)
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        first = fh.readline()
        fh.seek(0)
        if first.lstrip().startswith("{"):
            yield from _read_json_lines(fh)
        else:
            yield from _read_tsv(fh)


def _read_json_lines(fh) -> Iterator[dict[str, Any]]:
    for line in fh:
        line = line.strip()
        if line:
            yield json.loads(line)


def _read_tsv(fh) -> Iterator[dict[str, Any]]:
    fields: list[str] = []
    sep = "\t"
    unset = "-"
    for line in fh:
        line = line.rstrip("\r\n")   # tolerate CRLF (e.g. after a Windows checkout)
        if line.startswith("#"):
            if line.startswith("#separator"):
                token = line.split(" ", 1)[1].strip()
                sep = token.encode().decode("unicode_escape") if token.startswith("\\x") \
                    or token.startswith("\\") else token
            elif line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#unset_field"):
                unset = line.split("\t", 1)[1].strip()
            continue
        if not fields:
            continue
        values = line.split(sep)
        rec = {f: (None if v == unset else v) for f, v in zip(fields, values)}
        yield rec


def join_session_logs(conn: dict[str, Any], ssl: dict[str, Any] | None,
                      x509: dict[str, Any] | None) -> dict[str, Any]:
    """Join conn/ssl/x509 records (same Zeek `uid`) into one flat session view."""
    merged: dict[str, Any] = {}
    for src, prefix in ((conn, "conn"), (ssl, "ssl"), (x509, "x509")):
        if src:
            for k, v in src.items():
                merged[f"{prefix}.{k}" if k in merged else k] = v
    return merged


def index_by_uid(records: Iterator[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Collect records keyed by Zeek `uid` (for joining ssl/x509 onto conn)."""
    out: dict[str, dict[str, Any]] = {}
    for rec in records:
        uid = rec.get("uid")
        if uid:
            out[uid] = rec
    return out


# --- Real-pcap ingestion: Zeek log directory -> Session objects ------------------------

def _num(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _read_dir(log_dir: Path, name: str) -> list[dict[str, Any]]:
    """Read one Zeek log if present (JSON or TSV), else return []."""
    path = log_dir / name
    return list(read_zeek_log(path)) if path.exists() else []


def _packets_from_splt(rows: list[dict[str, Any]], orig_h: str | None) -> list[Packet]:
    """Build the per-session (size, direction, inter-arrival ms) sequence from splt.log rows.

    Direction uses the recorded `is_orig` flag ('T'/'F'); inter-arrival is the delta between
    consecutive packet timestamps within the flow (first packet = 0).
    """
    rows = sorted(rows, key=lambda r: int(_num(r.get("seq"))))
    packets: list[Packet] = []
    prev_ts: float | None = None
    for r in rows:
        ts = _num(r.get("ts"))
        is_orig = str(r.get("is_orig")).upper() in ("T", "TRUE", "1")
        iat = 0.0 if prev_ts is None else max(0.0, (ts - prev_ts) * 1000.0)
        prev_ts = ts
        packets.append(Packet(size=int(_num(r.get("len"))),
                              direction=1 if is_orig else -1,
                              inter_arrival_ms=iat))
    return packets


def _cert_from_x509(rec: dict[str, Any] | None, sni: str | None) -> dict[str, Any] | None:
    """Map an x509.log record to the certificate feature inputs (TLS 1.2 only in practice)."""
    if not rec:
        return None

    def g(*keys: str) -> Any:
        for k in keys:
            if rec.get(k) not in (None, ""):
                return rec.get(k)
        return None

    issuer = g("certificate.issuer", "issuer") or ""
    subject = g("certificate.subject", "subject") or ""
    cn = ""
    for part in str(subject).split(","):
        if part.strip().upper().startswith("CN="):
            cn = part.strip()[3:]
            break
    sans = g("san.dns", "san_dns")
    if isinstance(sans, str):
        sans = [s for s in sans.split(",") if s]
    return {
        "self_signed": (str(issuer) == str(subject)) and bool(subject),
        "not_before": _num(g("certificate.not_valid_before", "not_valid_before")),
        "not_after": _num(g("certificate.not_valid_after", "not_valid_after")),
        "subject_cn": cn,
        "sans": sans or [],
        "sni": sni or "",
        "key_size": int(_num(g("certificate.key_length", "key_length"))),
    }


def sessions_from_log_dir(log_dir: str | Path, *, label: str = "", family: str = "",
                          environment: str = "", pcap: str = "") -> list[Session]:
    """Build Session objects from a directory of real Zeek logs.

    Consumes conn.log (5-tuple, proto, timing), ssl.log (version, SNI, ALPN, and the FoxIO
    JA4/JA4S already computed), splt.log (per-packet SPLT from zeek/splt.zeek), and x509.log
    (certificate metadata, TLS 1.2 only). Label metadata is attached from the arguments —
    in practice from the capture's labels sidecar (CLAUDE.md §8).
    """
    log_dir = Path(log_dir)
    conn = index_by_uid(iter(_read_dir(log_dir, "conn.log")))
    ssl = index_by_uid(iter(_read_dir(log_dir, "ssl.log")))

    splt_by_uid: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in _read_dir(log_dir, "splt.log"):
        if row.get("uid"):
            splt_by_uid[row["uid"]].append(row)

    # x509.log is keyed by certificate fingerprint; join via ssl.log cert_chain_fps.
    x509_by_fp: dict[str, dict[str, Any]] = {}
    for rec in _read_dir(log_dir, "x509.log"):
        fp = rec.get("fingerprint") or rec.get("id") or rec.get("certificate.fingerprint")
        if fp:
            x509_by_fp[str(fp)] = rec

    sessions: list[Session] = []
    for uid, s in ssl.items():          # one Session per TLS/QUIC session
        c = conn.get(uid, {})
        proto = (c.get("proto") or ("udp" if str(s.get("version", "")).startswith("DTLS")
                                    else "tcp")).lower()
        sni = s.get("server_name") or None
        tls_ver = _TLS_VERSION_MAP.get(str(s.get("version", "")), str(s.get("version", "")))

        # certificate join (first fingerprint in the chain), TLS 1.2 only in practice.
        cert_fps = s.get("cert_chain_fps") or ""
        first_fp = str(cert_fps).split(",")[0].strip() if cert_fps else ""
        cert = _cert_from_x509(x509_by_fp.get(first_fp), sni)

        start = _num(c.get("ts") or s.get("ts"))
        dur = _num(c.get("duration"))
        sessions.append(Session(
            flow=FlowKey(
                src_ip=str(s.get("id.orig_h") or c.get("id.orig_h") or ""),
                src_port=int(_num(s.get("id.orig_p") or c.get("id.orig_p"))),
                dst_ip=str(s.get("id.resp_h") or c.get("id.resp_h") or ""),
                dst_port=int(_num(s.get("id.resp_p") or c.get("id.resp_p"))),
                proto=proto,
            ),
            client_hello=None,          # raw ClientHello lists aren't in ssl.log
            cert=cert,
            packets=_packets_from_splt(splt_by_uid.get(uid, []), s.get("id.orig_h")),
            ja4_precomputed=str(s.get("ja4") or ""),
            ja4s=str(s.get("ja4s") or ""),
            tls_version_str=tls_ver,
            start_ts=start, end_ts=start + dur,
            label=label, family=family, environment=environment, pcap=pcap,
        ))
    return sessions
