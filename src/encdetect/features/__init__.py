"""Feature families, in order of durability (CLAUDE.md §3, §6).

1. shape/timing (SPLT)      — survives everything. Highest priority.
2. handshake (JA4+)         — under pressure from Encrypted Client Hello.
3. certificate (TLS 1.2)    — bonus, not a pillar.

Losing a family must DEGRADE the detector, not break it. Every extractor exposes an
availability flag so the model learns to ignore absent families rather than seeing
silent zeros (CLAUDE.md §6.3, §10).
"""
