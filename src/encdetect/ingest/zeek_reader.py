"""Stream Zeek TSV/JSON logs into per-session records.

STUB — Build Order step 1 (CLAUDE.md §9). Wire to a real ssl.log first.
"""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any


def read_zeek_log(path: str | Path) -> Iterator[dict[str, Any]]:
    """Yield one dict per record from a Zeek log (conn/ssl/x509).

    TODO: support both TSV (default) and JSON Zeek output; carry the `uid` so
    conn/ssl/x509 records for the same session can be joined.
    """
    raise NotImplementedError("Zeek reader — Build Order step 1")


def join_session_logs(
    conn: dict[str, Any], ssl: dict[str, Any] | None, x509: dict[str, Any] | None
) -> dict[str, Any]:
    """Join conn/ssl/x509 records on Zeek `uid` into one session view."""
    raise NotImplementedError
