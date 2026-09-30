# Volumetric / Protocol DDoS Detection 

This repo is scoped specifically to **volumetric and protocol DDoS attacks** (threat class **a** in the problem statement: SYN floods, UDP reflection/amplification, spoofed-source floods) - one of six threat-detection branches in a larger unidirectional (read-only) network threat-detection pipeline being built by the team. It does not cover C2 beaconing, DGA/DNS tunnelling, encrypted-malware detection, recon/port-scanning, or exfiltration - those are separate branches owned by other team members.

- **Problem Statement:** SIH 26145 - AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
- **Organization:** National Technical Research Organisation (NTRO)

## Context

This module assumes the "data diode" constraint from the problem statement: the detection system can only passively observe traffic (packet captures / flow records) and can never send probes, complete handshakes, or push mitigation actions back across the ingest path. Detection has to work purely from what crosses the wire.

The live ingestion layer (reading real-time traffic off the diode and feeding it into this detection engine) is being built separately by the team; this repo covers the detection engine itself, developed and validated against a self-contained Docker lab producing real captured traffic.

## Architecture Overview

The DDoS engine runs 3 parallel branches, all sharing one feature-extraction layer:

- **Branch A - SYN flood** (fully built and validated)
- **Branch B - UDP reflection/amplification** (fully built and validated)
- **Branch C - Spoofed-source / generic volumetric catch-all** (fully built and validated)

Each branch produces a continuous confidence score via a CUSUM change-point detector (the **hot path** - fast, per-window, no training data needed). A **cold-path** XGBoost fusion layer combines all three branches' scores into an overall confidence and identifies which branch(es) are driving an alert (built and design-verified; see Fusion Layer section for important caveats).

### Shared feature layer (computed identically across all three branches)

- **Packet rate** - packets/sec in the current window (the primary hot-path signal fed to CUSUM)
- **Fan-in** - distinct source IPs seen in the window
- **Max-source-share** - (packets from top source) / (total packets)
- **TTL deviation** - average mismatch between an observed source's TTL and that same source's learned baseline TTL

## Branch A - SYN Flood

**Lab setup:** 3-container Docker lab (`victim`, `attacker`, `monitor`). `monitor` shares `victim`'s network namespace and passively captures via `tcpdump` - mirroring the read-only diode constraint.

**Features:** SYN-only-to-ACK ratio (core signal), packet rate, TTL deviation.

**Detection:** CUSUM change-point detection on the ratio, log-transformed for numerical stability across a huge value range (0.1 in benign traffic, 5,000–15,000+ during a flood).

**Results (real captured data - 15s benign HTTP baseline, then a live `hping3 -S --flood`):**

| Metric | Benign | Flood |
|---|---|---|
| SYN-only : ACK ratio | ~0.1 | 5,000–15,000+ |
| CUSUM value | 0 (flat) | crosses alert threshold within 1 window (~1 sec) |

**Detection latency: ~1 second** - satisfies the problem statement's "bounded latency, streaming not batch" requirement.

**Known lab limitation:** our attacker uses its real IP (not spoofed), so the attacker's own kernel auto-RSTs unsolicited SYN-ACK replies - every SYN, SYN-ACK, and RST arrive in exactly matched triplets. This "self-cleaning" pattern is a Docker-loopback artifact, not real attacker behavior; the actual separating signal here is the complete absence of finished sessions (zero ACK/FIN) plus raw rate, not the classic SYN:SYN-ACK asymmetry a real spoofed attack would show. TTL deviation correctly reads 0 here since there's no spoofing to catch.

## Branch B - UDP Reflection / Amplification

**Mechanism:** a real `dnsmasq` DNS server (4th container, `dns_server`) configured with a deliberately oversized 255-byte TXT record. Confirmed real amplification via `dig`: a ~35-40 byte query returns a 292-byte response (~7-8x amplification). Spoofing implemented with `scapy`, forging the victim's IP as the query source so the amplified reply lands on `victim`, who never asked for it - captured end-to-end on real pcap.

**Features:**
- **Rate** - UDP packets/sec (hot-path CUSUM signal)
- **Port score** - fraction of packets touching a known-abused-service port (53/DNS, 123/NTP, 1900/SSDP, 11211/memcached, 19/chargen, 161/SNMP)
- **Orphan-response ratio** - fraction of large inbound responses with no matching prior outbound query from the victim within a lookback window - the most semantically direct reflection signature (an answer to a question never asked)
- Shared layer: fan-in, max-source-share, TTL deviation

**Results:** a real legitimate baseline (`dig` queries victim actually made) followed by a real spoofed-reflection burst.

- Baseline: rate ~2 pkts/sec, `orphan_score: 0.0` (real queries preceded the responses)
- Attack: rate spikes to 5→4→1 pkts/sec, `orphan_score: 1.0` throughout (victim never asked for these)
- CUSUM fires cleanly at attack onset

**Confidence fusion (branch-level):** `confidence = 0.6 × cusum_confidence + 0.2 × orphan_score + 0.2 × port_score`. Real finding: baseline windows show `confidence: 0.2` (not 0.0), because `port_score` alone can't distinguish attack from legitimate DNS traffic - both use port 53. This is exactly why the feature is fused with others rather than used alone.

**Architectural open question (flagged in original design, confirmed real):** orphan-response ratio requires visibility into the protected network's own outbound queries. Given the unidirectional/diode constraint, whether this visibility exists at the real deployment's vantage point is an open design question, not yet resolved.

## Branch C - Generic Volumetric / Spoofed-Source Catch-All

**Mechanism:** `hping3 --rand-source --flood`, generating a genuinely massive number of distinct spoofed source IPs against `victim`. Uses only the shared feature layer - no protocol-specific logic.

**Results (real capture, ~88,700 packets in a few seconds):**

| Metric | Benign | Attack |
|---|---|---|
| Fan-in | 2 | 42,567 (single window) |
| Max-source-share | 0.54 | 0.0 |
| CUSUM | 0 | fires within 1 window |

This is the branch that finally exercises fan-in and max-source-share meaningfully - Branches A and B never had genuine multi-source spoofing.

**Important, tested finding on TTL deviation:** it reads `0.0` here, and this is correct, not a flaw - TTL deviation catches **identity impersonation** (spoofing a *known, previously-baselined* address, like the classic reflection-attack pattern of forging the real victim's IP), not **novelty** (thousands of brand-new, never-before-seen fake addresses, which is what `--rand-source` generates). We built and passed a separate test confirming TTL deviation correctly fires (`ttl_deviation: 64.0`) when a known baseline IP is later impersonated with a mismatched TTL - proving the feature works for the specific attack pattern it targets, and is correctly silent for a different spoofing pattern that fan-in/max-source-share cover instead.

## Adaptive (Self-Relearning) CUSUM

A second detector variant that periodically re-estimates its baseline (mu, sigma) from recent non-alerting windows, rather than learning once and freezing forever - closer to how a real deployment would need to handle traffic patterns that legitimately shift over time (time of day, day of week).

**A real bug was found and fixed during testing:** standard CUSUM only decays by a small fixed amount (`k`) per calm window after an anomaly ends. Testing against a two-attack synthetic scenario showed that after a large sustained spike (CUSUM reaching ~1,760), it would take **~3,500 windows** to naturally decay back below the alert threshold - meaning the detector would report a stale "active alert" long after a real attack ended. Fixed with an immediate-reset rule: if a window's traffic drops back to or below baseline, reset the accumulator to zero rather than relying on slow linear decay. Verified against a two-attack test scenario: both attacks correctly caught, and the detector correctly falls silent and re-arms between them. This fix was also back-ported to the static (non-adaptive) detector used in Branches A and B.

**Known limitation (not yet solved):** the detector assumes its initial baseline-learning period is genuinely clean traffic. If monitoring starts *during* an attack already in progress, the detector will learn attack-level traffic as "normal" and fail to flag a continuation of that same attack. This is a known, general class of problem in online anomaly detection ("cold-start"/"poisoned baseline"), not specific to our implementation - mitigations (independently-verified clean baseline periods, robust statistics like median/MAD instead of mean/std) are noted as future work.

## Fusion Layer (Cold Path)

An XGBoost classifier combines all three branches' confidence scores (plus supporting evidence) into one overall confidence and a subtype attribution (e.g., `multi_vector_coordinated`).

**Critical honesty caveat:** no real dataset of simultaneous multi-branch attacks exists - our three branches were captured independently, at different times. The fusion model is trained on **synthetic co-occurrence scenarios** encoding our design assumption (branches co-firing together should score higher than any one alone; a single strongly-elevated branch should still trigger on its own). We verified this design assumption is learnable - the trained model correctly scores a single moderate branch as `~0.01` (not an attack) versus two moderate branches together at `~0.99` (coordinated attack) - proving the mechanism works for the pattern we designed it to catch.

**On the reported "99% accuracy":** a train/test split evaluation of the fusion model scores ~99% - but this number measures whether the model correctly learned to reproduce our own hand-written synthetic labeling rule, not whether that rule matches real attacker behavior. Both the training and test labels come from the same formula, so a near-perfect score here is expected and appropriate, not evidence of real-world accuracy. A real accuracy claim would require labeled real-world (or red-team-generated) multi-branch incidents, which don't yet exist for this project.

**Demonstration on real data:** feeding each branch's real peak captured confidence (all `1.0`) into the fusion layer correctly produced `fused_confidence: 1.0`, `multi_vector_coordinated (all three)`. This demonstrates the fusion *mechanism* correctly recognizing a hypothetical simultaneous attack - it is not evidence that a real three-way coordinated attack was captured, since the three peaks came from separate, independent test runs.

## External Validation Attempt

To address the synthetic-training-data limitation directly, we tried validating our detection approach against independently-labeled public datasets.

**No public dataset contains our exact features.** TTL deviation, fan-in, and orphan-response ratio require raw packets and our own specific windowing/baseline logic - no public flow-level dataset publishes this. Public datasets only provide pre-aggregated flow summaries from other tools (CICFlowMeter), so any external validation tests the underlying *principle* (rate/flag-based signals separate real attacks from real benign traffic), not our literal pipeline end-to-end.

**CICDDoS2019 (Kaggle: dhoogla/cicddos2019, Syn-training split):** the SYN/ACK flag-count columns in this specific processed file turned out to be **pre-normalized to a [0,1] range**, with 75%+ of both benign and attack flows collapsing to identical values. ROC-AUC came back at **0.499 - statistically identical to random guessing**. This is a property of this particular file's preprocessing, not of real network traffic or of our feature design; we did not have time to source the raw (non-normalized) version of this dataset.

**CIC-IDS2017 (Hugging Face, Friday-Afternoon-DDoS capture, ~226k real labeled flows):** a raw, genuinely unscaled feature - `Total Fwd Packets` - achieved **ROC-AUC = 0.712**, with recall 0.9996 but precision only 0.658 at the best single threshold. This confirms real, non-random signal in raw packet-volume, while also validating why our architecture doesn't rely on a single static-threshold feature: volume alone can't distinguish an attack from unusually busy legitimate traffic, which is exactly why our design fuses rate with SYN-ratio, TTL-deviation, and time-windowed CUSUM change-detection.

**A caught red flag, not a result to be proud of:** we briefly tested whether a more flexible model improved on this, and got a suspiciously high AUC. We did not pursue this further as a "win" - instead, we found that CIC-IDS2017 is documented in peer-reviewed literature (Engelen et al. 2021; Liu et al. 2022; Cantone et al., reporting label corruption rates up to 6.67% overall and above 75% in some attack classes; Rosay et al. 2023, Journal of Computer Virology and Hacking Techniques, finding that models trained on this dataset's flow-summarized form are "unlikely to have practical import") to contain structural flow-construction artifacts that flexible models are known to exploit as shortcuts rather than learning genuine attack behavior. We report this as a caught limitation, not a claimed result.

## Known Limitations (Summary)

- Lab attacker traffic (Branches A, B) is not spoofed, so classic SYN:SYN-ACK asymmetry and TTL-mismatch signatures don't manifest in our captures the way they would against a real spoofed attacker
- CUSUM baseline-learning assumes a clean startup period; a poisoned baseline (monitoring starting mid-attack) is a known, unsolved class of problem
- Fusion layer is trained on synthetic co-occurrence data; real multi-branch simultaneous attack data doesn't exist yet for this project
- No public dataset could validate our exact feature set (raw-packet-dependent); external validation tested the underlying principle on proxy features instead, with mixed/negative results honestly reported
- Orphan-response ratio's real-world computability depends on an open architectural question about the diode's visibility into outbound queries
- Adaptive baseline detector is built and tested standalone; not yet wired as the default across all three branches' live pipelines
- Live ingestion (reading a real-time traffic feed instead of saved pcaps) is out of scope for this repo - owned by the team's ingestion-layer work

## Repo Structure

```
ddos-demo/
├── docker-compose.yml          # 4-container lab: victim, attacker, monitor, dns_server
├── victim/Dockerfile
├── attacker/Dockerfile         # hping3, scapy, dig
├── attacker/spoof_query.py     # UDP reflection spoofing script
├── monitor/Dockerfile          # tcpdump, shares victim's netns
├── dns_server/Dockerfile
├── dns_server/dnsmasq.conf     # oversized TXT record for amplification
├── windowed_features.py        # Branch A feature extraction
├── udp_features.py             # Branch B feature extraction
├── generic_features.py         # Branch C feature extraction
├── cusum_detector.py           # Static CUSUM (Branch A, decay-reset fixed)
├── udp_cusum.py                # Branch B CUSUM + confidence fusion
├── generic_cusum.py            # Branch C CUSUM
├── adaptive_cusum.py           # Self-relearning CUSUM variant
├── adaptive_runner.py          # Wires adaptive detector into real pcap data
├── fusion_model.py             # Cold-path XGBoost fusion across branches
├── plot_detection.py           # Presentation plot (Branch A)
├── alerts_output.json          # Branch A real alert records
├── udp_alerts_output.json      # Branch B real alert records
├── generic_alerts_output.json  # Branch C real alert records
├── detection_plot.png
└── captures/                   # generated pcaps (gitignored - regenerate locally)
```

