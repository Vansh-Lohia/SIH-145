# Encrypted-Session Malware Detection

Detecting **encrypted (TLS/QUIC) command-and-control traffic from a compromised host**
using connection metadata only — no payload decryption.

One of six detectors in the **SIH 2026 PS 26145** pipeline ("AI-Based Detection of Cyber
Threats in Unidirectional IP Traffic"). Sponsor: **NTRO**. Team **SimpleX**, IIT Kharagpur.

> The full engineering contract lives in [`CLAUDE.md`](CLAUDE.md). Read it before changing
> any design. This README is the short version.

## What it does

Classifies a TLS/QUIC session as *legitimate application* vs *malware imitating one*, from
metadata alone: handshake fingerprints (JA4+), packet shape/timing (SPLT), and — for TLS 1.2
only — certificate metadata. Emits streaming, schema-conformant alerts with SHAP evidence.

## Hard constraints (non-negotiable — see `CLAUDE.md` §2)

- **Read-only ingest.** Passive only. No probing, no handshakes, no inline mitigation.
- **No outbound calls from the enclave.** No DNS / GeoIP / threat-intel lookups. Everything
  ships pre-loaded with an offline update path. Audit every dependency for network calls.
- **No payload decryption.** Metadata only. (Parsing the QUIC Initial ClientHello is
  permitted and standard passive practice — see `CLAUDE.md` §2.3.)
- **Streaming, not batch.** Bounded-latency alerts, target p99 < 30 s.
- **Frozen alert schema** — [`schema/alert_schema.json`](schema/alert_schema.json).

## Layout

```
src/encdetect/
  ingest/      # Zeek log readers (conn.log, ssl.log, x509.log), streaming state
  features/    # ja4+ (built in-house), splt shape/timing, certificate
  models/      # lightgbm baseline, 1d-cnn sequence, fusion
  eval/        # leave-one-family-out protocol, metrics (TPR@0.1%FPR), reports
  streaming/   # asyncio sliding-window pipeline, alert emission
schema/        # frozen alert schema
harness/       # tcpreplay harness for controlled-rate replay
data/          # pcaps, zeek_logs, labels (git-ignored; see labels sidecar format)
docs/          # design notes, evaluation write-ups
tests/
```

## Build order (see `CLAUDE.md` §9)

1. **Environment** — Zeek reader + tcpreplay harness; skeleton + schema committed. ✅
2. **Baseline** — in-house JA4 + tabular features + LightGBM, leave-one-family-out. ✅
3. **Sequence model** — 1D-CNN on SPLT. ✅
4. **Fusion** (score averaging) ✅, 5. **Ablation** ✅, 6. **Streaming** (asyncio, p99 latency) ✅

All six are wired together in an end-to-end prototype driven by a synthetic data generator
(so it runs before real Zeek logs exist). The generator is a **stand-in for the real data
plan** (`CLAUDE.md` §8), not a replacement for it.

## Getting started

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Run the end-to-end prototype

```bash
python scripts/run_prototype.py
```

This generates a labelled synthetic dataset, featurizes it (SPLT + JA4 + certificate),
trains the LightGBM baseline, and prints the honest evaluation — the **random-split** number
next to the **leave-one-family-out** number — then trains the 1D-CNN, fuses, runs the
ablation, and finally streams schema-conformant alerts with a p99 latency measurement.

### Run the tests

```bash
python -m pytest tests/ -q
```

Zeek and tcpreplay are external tools for real captures (install separately). See
[`docs/environment.md`](docs/environment.md). Prototype results and the leakage bug found
during bring-up are written up in [`docs/evaluation.md`](docs/evaluation.md).

## Evaluation discipline (see `CLAUDE.md` §7)

The headline number is **leave-one-family-out**, not the random split. Never split flows
from one pcap across train/test. Report **TPR at 0.1% FPR** and **alerts/hour**, never
accuracy alone. Follows Arp et al., *Dos and Don'ts of ML in Computer Security* (USENIX '22).
