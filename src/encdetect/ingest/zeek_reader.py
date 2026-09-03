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
from collections.abc import Iterator
from pathlib import Path
from typing import Any


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
        line = line.rstrip("\n")
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
