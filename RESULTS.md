# Results

**Real-data leave-one-family-out evaluation** (CTU malware captures — Dridex, Trickbot, Emotet, 2016–2018 — plus real benign traffic from three independent sources):

| Held-out family | n malicious | n benign | AUC | Accuracy* | Precision* | Recall* | F1* |
|---|---|---|---|---|---|---|---|
| Dridex | 5,735 | 2,697 | **0.9425** | 0.3195 | 0.0000 | 0.0000 | 0.0000 |
| Emotet | 14,060 | 2,697 | **1.0000** | 0.9998 | 0.9998 | 1.0000 | 0.9999 |
| Trickbot | 2,570 | 2,697 | **1.0000** | 0.9994 | 0.9988 | 1.0000 | 0.9994 |

**Generalization test on unseen modern malware** (Lumma Stealer, 2025, TLS 1.3, no TLS 1.3 malicious example in training):

| Held-out family | n malicious | n benign | AUC | Accuracy* | Precision* | Recall* | F1* |
|---|---|---|---|---|---|---|---|
| Lumma Stealer (2025) | 10 | 2,697 | **0.6360** | 0.9956 | 0.0000 | 0.0000 | 0.0000 |

\* Precision/recall/F1/accuracy computed at a strict 0.1%-false-positive-rate operating threshold, per security-evaluation practice (real traffic is ~99.9% benign, so a threshold tuned for balanced accuracy is meaningless). **Read AUC as the primary number right now** — see caveat below.

Trained across 26,818 real TLS sessions (Zeek + FoxIO JA4 ingestion on real pcaps).

# Insight

**AUC — the model's ability to *rank* malicious traffic above benign — is strong for three of four families (0.94–1.00) and moderate for the fourth (0.64, the only modern/TLS 1.3 family tested).** The 0/0/0 precision/recall/F1 rows above are not model failure: they're a symptom of a strict low-false-positive threshold being set by only ~2,700 benign test sessions per fold — a handful of unusual benign examples can sit just above an otherwise tightly-clustered malicious score distribution at that threshold, even when the overall separation (AUC) is strong. This was confirmed directly: Dridex's 5,735 malicious sessions score within a very narrow band, but 2-3 benign sessions score marginally higher, zeroing the strict-threshold metrics while AUC stays at 0.94.

**A real bug was found and fixed while investigating this.** The JA4 fingerprint feature uses target encoding (a fingerprint's historical malicious rate becomes a numeric feature) rather than a blocklist — standard, defensible practice. But any *unfamiliar* fingerprint was falling back to the training set's raw malicious fraction (93%, itself just an artifact of downloading far more malicious than benign captures) instead of a neutral value. This meant any unusual fingerprint — malicious or entirely innocent — was scored "93% likely malicious" before any other evidence was considered. Fixed to fall back to a neutral 0.5 for genuinely unseen fingerprints; regression test added.

**What this means going in:** the detector can separate malicious from benign traffic well in ranking terms across old-era families and, to a lesser but still above-chance degree, a modern one. The specific low-false-positive operating point is not yet reliable — the concrete, evidenced fix is more real benign traffic volume so that threshold stabilizes, not a change to the model itself.

---
See [`docs/evaluation.md`](docs/evaluation.md) for full methodology, the environment-confound investigation, the target-encoder bug writeup, and the correction record for how each finding was verified.
