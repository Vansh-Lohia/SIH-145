"""Streaming pipeline (CLAUDE.md §2.4, §4).

Python asyncio + sliding-window session state. Per-session decision on the first 20-30
packets or session close, whichever first. Target p99 alert latency < 30 s. Kafka/Flink
is the documented scale-up path, NOT built now.
"""
