"""Zeek log ingestion (CLAUDE.md §4: Zeek chosen, don't hand-roll TCP reassembly).

Reads structured TLS metadata from conn.log / ssl.log / x509.log. Read-only, passive:
this layer NEVER contacts any host, resolves any name, or looks anything up over a network
(CLAUDE.md §2.1, §2.2).
"""
