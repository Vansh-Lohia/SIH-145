"""Synthetic session generator — PROTOTYPE / DEMO ONLY (CLAUDE.md §8).

This exists so the pipeline runs end-to-end before real Zeek logs are wired in. It is NOT a
substitute for the real data plan: real malicious captures come from Stratosphere/CTU, and
benign traffic must be GENERATED YOURSELF on the same network/period as the malware replay
(CLAUDE.md §8) — the main defence against the environment artifact.

The generator deliberately gives each malware family its OWN signature so that
leave-one-family-out is genuinely harder than a random split — reproducing, in miniature,
the exact failure mode the evaluation protocol guards against (CLAUDE.md §7).
"""
