# recon_detector — Passive One-Way Reconnaissance / Port-Scan Detector

*Smart India Hackathon (SIH) — Problem Statement **26145**, "AI-Based Detection
of Cyber Threats in Unidirectional IP Traffic" (NTRO).*

This repository implements **one** of the six SIH threat detectors: threat class
**#5, Reconnaissance / Port Scanning**. It is designed to plug into the team's
future common ingestion, alert-scoring, and dashboard layers without depending
on any of them.

---

## 1. SIH problem

The overall system passively monitors critical-infrastructure gateway/peering
links via traffic mirroring or hardware data diodes. The monitoring enclave can
observe traffic crossing the link but has **no path back into the production
network**, so the whole system must be **passive** and must never send packets,
probe hosts/ports, complete handshakes, request retransmissions, or depend on a
return path. It must detect, classify, and score six threat classes in near
real time. This component is responsible only for reconnaissance/port scanning,
characterised by the SIH as *"fan-out patterns from a single source across many
destination ports or hosts."*

## 2. Component scope

**Built here:** a supervised per-flow scan classifier, a source-level streaming
behavioural detector, temporal aggregation/state, vertical/horizontal/mixed
classification, slow-scan detection, score/evidence generation, a clean detector
API, a training/evaluation/streaming CLI, tests, benchmarks, and this document.

**Deliberately not built** (belongs to the common team layers): the dashboard,
the six-model orchestrator, ingestion / PCAP-NetFlow-IPFIX-sFlow parsing, common
feature extraction, common alert scoring, the other five detectors, and any
active scanner, probing, mitigation, database, queue, or distributed
infrastructure. A Python API + CLI is sufficient.

## 3. Overall team architecture

```
common ingestion → common feature extraction → normalized record
        → THIS detector → DetectionResult → common alert scoring → dashboard
```

The detector exposes a single entry point, `ReconDetector.process(record) →
DetectionResult`, and knows nothing about the other components.

## 4. Strict one-way constraint (non-negotiable)

Production input is treated as strictly one-directional: if we observe `A → B`
we do **not** assume we see `B → A`. The detector never requires SYN/ACK, RST,
ICMP responses, connection success/failure, handshake completion, RTT, response
latency, or port-open information. It identifies scanning **behaviour** from the
traffic that is actually observed; it does **not** decide whether a destination
port is open. See `tests/test_one_way_constraints.py`, which asserts (among
other things) that processing opens no sockets and performs no DNS.

## 5. Reconnaissance definition

A source exhibiting **fan-out**: contacting many destination ports (vertical),
many destination hosts (horizontal), or both (mixed), typically with many small
probe-like flows, optionally spread across time (slow/stealthy).

## 6. Per-flow model (`src/recon_detector/model.py`)

A supervised **`RandomForestClassifier`** over approved observed-direction
features answers a narrow question — *how scan-like is this single flow?* — and
outputs a **scan score** in `[0, 1]`. It is **not** called a probability (no
calibration was performed) and it never decides on its own that a source is
scanning. Two interchangeable scorers implement `score(record) → float`:

| Scorer | Use |
|---|---|
| `HeuristicFlowScorer` | dependency-free default; flags the classic tiny near-payload-free probe shape. Lets the detector run with no model file and keeps tests fast. |
| `MLFlowScorer` | the trained RandomForest over the approved feature list. |
| `CompositeFlowScorer` | **streaming default when a model is loaded.** Uses the ML scorer only when the record actually carries ≥5 of the model's features; otherwise falls back to the heuristic (see *Feature selection* for why). |

## 7. Source-level behavioural model (`src/recon_detector/behavior.py`)

The essential layer. For every source IP we keep **bounded** state and, per
source, compute: unique destination hosts / ports / (host,port) pairs; flow
count and recent rate; host / port / pair Shannon entropy; packet- and
byte-count statistics; small-flow fraction; mean and max per-flow scan score;
scan-like-flow fraction and **scan-like** fan-out (hosts/ports/pairs reached by
flows that individually look scan-like); and **persistence** across time
windows. Starting values: engineering window **60 s**, state TTL **~10 min**
(both configurable and evaluated, not universal constants).

Fan-out, diversity, and ratios are **accumulated over the retained history**
(bounded by the TTL horizon and a hard event cap), while the last
`window_seconds` drives the burst rate. This is what lets a few probes per
window accumulate into a detection.

## 8–10. Vertical / horizontal / mixed, and slow scans

Classification uses **scan-like** fan-out structure so that benign destinations
mixed in (camouflage) do not distort it:

- **Vertical** — many ports, one/few hosts.
- **Horizontal** — many hosts, one/few ports.
- **Mixed** — both high.
- **`unknown`** — returned whenever evidence is insufficient; we never force a
  label. All thresholds live in `DetectorConfig` and are exercised by the
  synthetic tests.

**Slow scans** are handled by temporal accumulation: bounded history, rolling
windows, per-source persistence (count of distinct windows containing scan-like
activity), and timestamp-based cleanup. A slow scan is detected through the
*persistence* path rather than a burst — but see *Limitations*: a sufficiently
slow scanner is indistinguishable from sparse benign traffic.

## 11. Temporal persistence

`persistence` = number of distinct `window_seconds`-buckets (within the retained
horizon) in which the source produced a scan-like flow. It feeds both the score
(a saturating term) and the slow-scan detection gate.

## 12. Score fusion (`ReconDetector._fuse`)

Three evidence sources are combined into `[0, 1]`:

```
score = w_flow · flow_evidence
      + w_fanout · fanout_evidence          (scan-like (host,port) pair fan-out)
      + w_persistence · persistence_evidence (distinct suspicious windows)
```

Defaults `w_flow=0.20`, `w_fanout=0.55`, `w_persistence=0.25` — behaviour
deliberately outweighs any single flow. `flow_evidence` only *confirms* scan-like
shape is present; it cannot drive a detection alone. Because `fanout_evidence`
counts **scan-like** pairs only, benign high fan-out (large flows) contributes
zero. All weights are documented and their sensitivity is easy to sweep via
`DetectorConfig`. The score is **not** a probability.

**Detection gate.** `detected` requires `score ≥ threshold` (default 0.6) **and**
one of two evidence paths: a *burst* (enough scan-like flows in the recent
window) or a *slow* path (persisted across ≥2 windows **and** ≥10 cumulative
scan-like pairs, so merely sparse traffic never fires).

## 13. Feature selection

The single source of truth is `APPROVED_FEATURES` in
`src/recon_detector/features.py` (an explicit list — **not** string matching):

```
Total Fwd Packets, Total Length of Fwd Packets,
Fwd Packet Length Max/Min/Mean/Std,
Fwd IAT Total/Mean/Std/Max/Min,
Fwd PSH Flags, Fwd URG Flags, Fwd Header Length,
Init_Win_bytes_forward, act_data_pkt_fwd, min_seg_size_forward
```

Deliberate exclusions:
- **`Destination Port`** is *not* an ML feature — its raw value is a weak
  identity a tree can memorise for this capture. It is used only as a
  **behavioural key** (vertical fan-out).
- **`Flow Duration`** and any `*/s` rate columns — bidirectional semantics.
- IP addresses are never encoded as model identities.

**Streaming/training feature mismatch (important).** The trained model expects
the full 17-dim CIC vector. The *minimal* streaming contract carries only
`packet_count / byte_count / flow_duration`; imputing 14 features from global
medians yields an out-of-distribution vector the model reads unreliably.
`CompositeFlowScorer` therefore uses the ML model only when the ingestion layer
actually supplies the features, and the heuristic otherwise. This is an honest
engineering choice, not a bug — and it is exactly why the behavioural layer, not
the ML model, is the core of the detector.

## 14. Forbidden features

Never used: any backward (`Bwd*`) packet/byte/length/IAT/flag feature, reverse
TCP behaviour, SYN/ACK, RST, connection success/failure, RTT or latency
requiring reverse traffic, forward/backward or down/up ratios, bidirectional
totals, or any feature whose computation needs reverse packets. `features.py`
carries a `FORBIDDEN_SUBSTRINGS` guard and `assert_features_are_one_way()`;
`tests/test_one_way_constraints.py` fails the build if a reverse-direction
feature ever appears in the approved list or a saved model.

## 15. Dataset limitation

Training uses `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
(CICFlowMeter/CICIDS-2017; 286,467 rows, labels `BENIGN` 127,537 / `PortScan`
158,930). **CICFlowMeter produces bidirectional flow records, so this is NOT a
true strict-one-way dataset.** We use only observed-direction-compatible
features for supervised training, while production inference is designed for
strict one-directional passive input. The CSV also has **no src/dst IP or
timestamp columns**, so source-level behavioural evaluation cannot come from it
(see *Data leakage*).

## 16. Training (`training/train.py`)

Reproducible pipeline (fixed `random_state=42`): locate dataset → inspect
columns/labels → validate approved features → replace inf, drop/​impute invalid
values (medians saved for inference) → stratified split → train RandomForest →
evaluate → save `per_flow_model.joblib`, `feature_list.json`, and
`metadata.json` (dataset, timestamp, medians, feature importances, holdout
metrics, leakage caveat, Python version). No large hyperparameter search.

```bash
python training/train.py --dataset /path/to/Friday-...-PortScan.pcap_ISCX.csv
```

## 17. Evaluation

Separated deliberately (spec §25):

- **A. Offline supervised benchmark** (`evaluation/evaluate_model.py`) — on the
  CIC holdout the model scores precision **0.9995**, recall **0.9999**, F1
  **0.9997**, ROC-AUC **0.9998**, PR-AUC **0.9997** (confusion matrix
  `[[38238, 24], [4, 47675]]`). **These numbers do NOT equal real-world
  streaming performance** — the split is a stratified *random* split on a
  dataset without source/time keys, so correlated flows can appear on both
  sides.
- **B / C. Source-level & synthetic strict-one-way evaluation**
  (`evaluation/synthetic_stream_test.py`) — scenarios A–L below.
- **D. Throughput benchmark** (`evaluation/benchmark.py`).

Synthetic scenarios (all strict one-way; results are whatever the detector
actually produces): **A** benign, **B** fast vertical, **C** fast horizontal,
**D** mixed, **E** slow vertical, **F** slow horizontal, **G** benign high
fan-out, **H** UDP scan, **I** camouflaged, **J** sparse (insufficient),
**K** repeated persistent, **L** multi-source low-rate. In the current run
**11/11** scored scenarios pass: every scan scenario is detected with the
correct type, and benign/sparse/high-fan-out are not flagged. **L is not flagged
by design** — see *Limitations*.

**Slow-rate sweep** (30-port vertical scan at decreasing rates) illustrates the
research tradeoff — time-to-detection grows with the inter-probe gap and
detection eventually fails:

| gap | ~rate | detected | time-to-detect |
|----:|------:|:--------:|---------------:|
| 0.05 s | 20/s | yes | 0.9 s |
| 0.5 s | 2/s | yes | 9 s |
| 5 s | 0.2/s | yes | 70 s |
| 20 s | 0.05/s | yes | 180 s |
| 45 s | 0.022/s | yes | 405 s |
| 90 s | 0.011/s | **no** | — |

## 18. Streaming API

Incremental — each record is processed as it arrives, no full stream required:

```python
from recon_detector import ReconDetector

det = ReconDetector()                              # heuristic per-flow scorer
det = ReconDetector.from_model_dir("models")       # trained composite scorer

result = det.process({
    "timestamp": 1725379200.0, "src_ip": "45.33.32.156",
    "dst_ip": "10.0.0.20", "dst_port": 3389, "protocol": "TCP",
    "packet_count": 1, "byte_count": 0, "flow_duration": 0.0,
})
det.expire_state(now)   # periodic TTL cleanup (also driven automatically in CLI stream)
```

CLI:

```bash
python -m recon_detector demo                       # built-in scenarios
python -m recon_detector stream --input flows.jsonl # JSONL (or - for stdin)
python -m recon_detector stream --csv replay.csv    # CSV replay
python -m recon_detector train --dataset PATH
python -m recon_detector evaluate --dataset PATH
```

## 19. Output schema (`DetectionResult`)

```json
{
  "detected": true,
  "threat_class": "reconnaissance_port_scan",
  "scan_type": "vertical",
  "score": 0.7464,
  "timestamp": 0.8,
  "source": "45.33.32.156",
  "evidence": {
    "window_seconds": 60.0, "observed_flows": 40, "recent_window_flows": 40,
    "unique_destination_hosts": 1, "unique_destination_ports": 40,
    "unique_destination_pairs": 40, "attempts_per_second": 0.6667,
    "destination_host_entropy": 0.0, "destination_port_entropy": 5.32,
    "destination_pair_entropy": 5.32, "small_flow_ratio": 1.0,
    "scan_like_flow_ratio": 1.0, "mean_flow_scan_score": 1.0,
    "max_flow_scan_score": 1.0, "persistence": 1, "ports_per_host": 40.0,
    "scan_like_hosts": 1, "scan_like_ports": 40, "scan_like_pairs": 40,
    "score_components": {"flow_evidence": 1.0, "fanout_evidence": 0.86,
                          "persistence_evidence": 0.28}
  }
}
```

The evidence block gives the common alert-scoring layer everything it needs to
re-weight or combine this signal. (Numbers above are from an actual run, not
hardcoded.)

## 20. Bounded state

State expires: inactive sources are dropped after the TTL; the number of tracked
sources is capped (LRU eviction); per-source event history is bounded by both
the time horizon and a hard event cap; unique-destination tracking uses capped
sets. Memory scales with *active sources + retained history*, not the lifetime
of the network. Verified by `tests/test_behavior.py` and
`evaluation/benchmark.py` (20 waves × 1000 fresh sources → ~1000 active after
expiry, not 20,000).

## 21. Benchmark

Measured on this machine (`evaluation/benchmark.py`, 60k records, 500-source
mix; your numbers will differ): **~73,000 flows/sec**, mean per-record latency
**~12 µs**, **p95 ~14 µs**, **p99 ~18 µs**, with bounded active-source state. No
numbers are invented — re-run to reproduce.

## 22. Limitations (stated honestly)

- **Distributed scanning.** This is a **single-source** detector. If ten sources
  each perform a small slice of a scan (scenario L), it will not identify the
  global campaign — that is a future team-level correlation problem. The output
  is structured so a correlator could aggregate per-source alerts.
- **Ultra-slow scanning.** There is a fundamental observability tradeoff
  (Safaei Pour & Bou-Harb 2019): a scanner slow enough to resemble sparse benign
  traffic will evade or greatly delay detection (see the 90 s row above). We do
  **not** claim detection of arbitrarily slow scans.
- **Dataset.** Offline metrics come from a bidirectional benchmark with a random
  split and no source/time keys; they do not prove streaming performance.
- **No port-open knowledge.** We detect scanning *behaviour*, never whether a
  port is open. We do not, and cannot, confirm connection outcomes.
- **Evasion.** No detector is immune; camouflage and rate-shaping can degrade it.

## 23. Integration

`process(record) → DetectionResult`. The detector does not depend on the other
five models, does not know about the dashboard, and does not know how ingestion
is implemented. Input is a plain normalized record (dict / JSONL); output is a
plain structured result. It never requires PCAP internally.

## 24. Research basis and interpretation

The design **adopts principles** from the literature without claiming any paper
prescribes this exact implementation:

- **Jung et al. 2004 (TRW).** Sequential hypothesis testing on connection
  outcomes. Because outcomes are unavailable under strict one-way observation,
  classical TRW is **not** the production detector — it is only an optional
  offline research baseline (`baselines.TRWResearchBaseline`) that *refuses to
  run without genuinely observed outcomes and never fabricates them*.
- **"Limitations to TRW…".** Motivates not relying on a single
  connection-outcome detector, using broader behavioural evidence, and expiring
  per-source state — all reflected here.
- **Ring et al. 2018 (PLOS ONE, slow flow-based scan detection).** A scan is a
  *sequence* of flows; unidirectional flow data suffices; aggregate flows into
  source-level events; slow scans need temporal aggregation; supervised
  classification works on aggregated features. This is the backbone of the
  design.
- **Safaei Pour & Bou-Harb 2019 (Computer Communications).** Passive detection
  has inherent visibility limits; detection time depends strongly on probing
  rate; low-rate/distributed probing delays or evades detection. We respond with
  temporal accumulation and persistence, and we **document** the limits rather
  than hiding them. Darknet sensor-width equations are intentionally **not**
  copied in.

**What research says vs what we implement:** research establishes that passive,
unidirectional, source-level temporal aggregation is a valid basis for scan
detection and that low-rate/distributed probing is fundamentally hard. We
implement observed-direction per-flow classification + source fan-out +
destination/port diversity/entropy + small-flow evidence + temporal windows +
persistence, and we explicitly bound our claims accordingly.

---

## Project layout

```
src/recon_detector/   schemas · features · model · behavior · detector · cli · synthetic · baselines
training/train.py     reproducible training pipeline
evaluation/           evaluate_model · synthetic_stream_test · benchmark
tests/                model · behavior · detector · one_way_constraints
models/               saved artifact (per_flow_model.joblib, feature_list.json, metadata.json, *_eval.json)
```

## Setup and reproduce

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt          # or: pip install -e .
python training/train.py --dataset /path/to/Friday-...-PortScan.pcap_ISCX.csv
python evaluation/evaluate_model.py --dataset /path/to/...csv --out models/offline_eval.json
python evaluation/synthetic_stream_test.py --model-dir models
python evaluation/benchmark.py --model-dir models
pytest
```

Requires Python 3.10+ and numpy, pandas, scikit-learn, joblib (pytest for tests).

## Scientific honesty

We never claim: that CICIDS is a true one-way dataset; that reverse traffic is
available; that ports can be confirmed open; that connection success is known;
that scores are calibrated probabilities; that arbitrarily slow or distributed
scans are guaranteed detected; that benchmark F1 equals real-world performance;
or that the detector is immune to evasion. Measured results, engineering
heuristics, research-derived design principles, assumptions, and limitations are
labelled as such throughout.
