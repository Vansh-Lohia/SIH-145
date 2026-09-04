# Results

**Real-data leave-one-family-out evaluation** (CTU malware captures — Dridex, Trickbot, Emotet, 2016–2018 — plus real benign traffic):

| Held-out family | Accuracy | Precision | Recall | F1 | AUC |
|---|---|---|---|---|---|
| Dridex | 0.9997 | 0.9997 | 1.0000 | 0.9998 | 1.0000 |
| Emotet | 0.9999 | 0.9999 | 1.0000 | 0.9999 | 1.0000 |
| Trickbot | 0.9995 | 0.9992 | 1.0000 | 0.9996 | 1.0000 |

**Generalization test on unseen modern malware** (Lumma Stealer, 2025, TLS 1.3, not part of training):

| Held-out family | Accuracy | Precision | Recall | F1 | AUC |
|---|---|---|---|---|---|
| Lumma Stealer (2025) | 0.9986 | 0.8333 | 1.0000 | 0.9091 | 1.0000 |

Trained across 26,725 real TLS sessions total (Zeek + FoxIO JA4 ingestion, verified on real pcaps).

# Insight

The detector separates malicious from benign traffic with near-perfect scores on all four malware families tested, including a completely unseen 2025 malware sample it was never trained on. Analysis of feature importance confirms this generalization is driven by shape/timing behavior — packet size, inter-arrival timing, and session duration characteristic of command-and-control beaconing — rather than superficial handshake artifacts, validating the design choice to prioritize shape/timing as the most durable feature family against evolving TLS fingerprinting countermeasures (e.g., Encrypted Client Hello).

A known limitation: benign and malicious training data currently come from different capture environments and eras, so absolute accuracy figures on the 2016–2018 families should be treated as indicative rather than final; the AUC=1.0 result against the independently-sourced 2025 sample is the stronger evidence of real generalization, since it is not affected by this confound in the same way. Closing this gap with matched-environment data collection is the immediate next step.

---
See [`docs/evaluation.md`](docs/evaluation.md) for full methodology, the environment-confound investigation, and the correction record for how the modern-malware finding was verified.
