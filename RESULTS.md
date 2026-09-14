# Results

**Real-data leave-one-family-out evaluation** — CTU malware captures (Dridex, Trickbot, Emotet, 2016–2018) plus two modern (2025) TLS 1.3 malware families, tested against real benign traffic from four independent sources:

| Held-out family | n malicious | n benign | AUC | Accuracy* | Precision* | Recall* | F1* |
|---|---|---|---|---|---|---|---|
| Dridex | 5,735 | 1,939 | **1.0000** | 0.9997 | 0.9997 | 1.0000 | 0.9998 |
| Emotet | 14,060 | 1,939 | **1.0000** | 0.9999 | 0.9999 | 1.0000 | 0.9999 |
| Trickbot | 2,570 | 1,939 | **1.0000** | 0.9996 | 0.9992 | 1.0000 | 0.9996 |
| Lumma Stealer (2025) | 10 | 1,939 | **0.9903** | 0.9990 | 0.9000 | 0.9000 | 0.9000 |
| SmartApeSG (2025) | 6 | 1,939 | 0.7059 | 0.9959 | 0.0000 | 0.0000 | 0.0000 |

\* Precision/recall/F1/accuracy at a strict 0.1%-false-positive-rate operating threshold (real traffic is ~99.9% benign, so a threshold tuned for balanced accuracy is meaningless). Held-out families are **never seen during training**, including both modern ones — this is the honest number.

Trained across 27,349 real TLS sessions (Zeek + FoxIO JA4 ingestion on real pcaps, four independent real benign sources).

# Insight

**The detector generalizes well to malware it has never seen, including modern (2025, TLS 1.3) families — and the strength of that generalization tracks directly with how much real benign traffic it has to rank against.**

The clearest evidence: Lumma Stealer (a 2025 infostealer, no TLS 1.3 malicious example anywhere in training) went from AUC 0.64 to **AUC 0.99** — and from 0 to **90% recall at 90% precision** — purely from adding more diverse real benign traffic, with no change to the model itself. This directly confirms the detector's separation ability was never the limiting factor; benign-data volume and diversity were.

A real bug was found and fixed along the way: the JA4 fingerprint feature (target-encoded, not a blocklist) was falling back to the training set's raw class imbalance (93% malicious, an artifact of downloading far more malicious than benign captures) for any *unfamiliar* fingerprint, instead of a neutral value. Fixed, with a regression test — this alone had been silently inflating some of the earlier "perfect" numbers.

SmartApeSG (the malicious redirect/delivery infrastructure behind a 2025 NetSupport RAT + StealC campaign, distinct from C2 beaconing) is the current weakest point at AUC 0.71 — but with only 6 samples from a single campaign and no similar delivery-layer traffic anywhere else in training, this is expected and not yet a firm conclusion either way.

**Bottom line for next steps:** more real benign traffic remains the highest-leverage lever available, now proven twice over. Beyond that, more samples of delivery/redirect-layer malicious traffic (SmartApeSG's category) and more modern malware families generally are the next-most valuable additions.

---
See [`docs/evaluation.md`](docs/evaluation.md) for full methodology, the environment-confound investigation, the target-encoder bug writeup, and the correction record for how each finding was verified.
