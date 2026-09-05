# Project Explain: How the Port-Scan Detector Actually Works

This document walks through the project end-to-end: what problem it solves, why it's built the way it is, and how a single flow of traffic travels through the code from "packet on the wire" to "detection alert." It complements [README.md](README.md) (which is the formal spec-style reference); this file is the narrative "why does every piece exist" walkthrough.

---

## 1. What this actually is (and isn't)

This is **not** a port scanner. It doesn't scan anything, open sockets, or probe hosts. It's the opposite: a **passive detector** that watches traffic mirrored off a network link and decides whether *someone else* is running a port scan against the network.

This matters because of the SIH problem statement it was built for (NTRO, threat class #5 of 6): the system sits on a **data-diode / traffic-mirror** — it can *see* packets crossing a link but has **no way to send anything back**. So the detector must work from one-directional evidence only: it sees `attacker → victim` traffic, but never `victim → attacker` replies (no SYN-ACK, no RST, no "port is open/closed," nothing). Every design decision downstream — the features used, the model, the scoring — flows from this one constraint.

## 2. The core insight: a scan looks like *behavior*, not like one packet

A single scan probe (say, one empty TCP SYN to port 445) is often **indistinguishable** from a legitimate flow — a health check, a failed connection retry, a monitoring ping. The `capture_batch.sh` lab comment says this explicitly: benign traffic *deliberately* includes empty 0-byte flows (failed connections, health checks) that are byte-identical to scan probes, and scans *deliberately* include payload-carrying flows (`nmap -sV` version probes) that look like benign traffic.

So no single flow reliably proves a scan. What does prove it is **fan-out**: one source touching an unusually large number of destination ports and/or hosts, especially with flows that individually *look* probe-like. That's why the project is split into two cooperating layers:

1. **Per-flow scorer** — "does this one flow look like a probe?" (weak signal, used only to confirm shape)
2. **Behavioral tracker** — "is this source touching an unusual number of destinations?" (strong signal, does the actual detecting)

## 3. End-to-end data flow (production/streaming path)

```
raw packet/flow record (dict or JSONL line)
        │
        ▼
FlowRecord.from_dict()              [schemas.py]  — parses/validates one flow
        │
        ▼
flow_scorer.score(record)           [model.py]    — "how scan-like is THIS flow?" → 0..1
        │
        ▼
tracker.observe(src_ip, ...)        [behavior.py] — updates per-source state,
        │                                           returns WindowFeatures (fan-out,
        │                                           entropy, persistence, etc.)
        ▼
detector._fuse(feats)                [detector.py] — combines 3 evidence sources → score
detector._classify_scan_type(feats)                — vertical / horizontal / mixed / unknown
detector._decide(score, feats)                     — burst-path OR slow-path gate
        │
        ▼
DetectionResult(detected, score, scan_type, evidence{...})
```

Every one of these steps is described below with the *why*, not just the *what*.

---

## 4. Step 1 — the input contract (`schemas.py`)

`FlowRecord` is the boundary contract with whatever upstream system extracts flows from raw packets (NetFlow/IPFIX/PCAP/etc. — deliberately **not** built here; that's a different team's job per the SIH architecture). The minimal required fields are:

```
timestamp, src_ip, dst_ip, dst_port, protocol, packet_count, byte_count, flow_duration
```

Why so minimal? Because production ingestion may only be able to hand over coarse flow summaries, not full CICFlowMeter-style statistics. An optional `features` dict lets a richer upstream system supply the full 17-feature vector when available — the detector adapts to whichever level of detail it gets (see §6, the `CompositeFlowScorer`).

`parse_timestamp()` accepts either epoch numbers or ISO-8601 strings, and **deliberately raises** if timestamp is missing — because every downstream layer (windows, persistence, entropy over time) is meaningless without a real clock.

## 5. Step 2 — per-flow scoring: "how scan-like is this one flow?" (`model.py`)

Three interchangeable scorers, all implementing `score(record) -> float` in `[0, 1]`. This score is explicitly **not called a probability** — no calibration was done, it's just a monotonic "scan-likeness" signal.

### `HeuristicFlowScorer` — the dependency-free default
Real scans (SYN scans, connect scans, UDP probes) share one shape: **tiny flows carrying almost no payload** — you're just checking if a port responds, not exchanging data. The heuristic scores exactly that:

```python
pkt_term  = exp(-max(packets - 1, 0) / max_scan_packets)   # fewer packets → higher
byte_term = exp(-bytes_per_packet / max_scan_bytes_per_packet)  # less payload → higher
score = 0.5 * pkt_term + 0.5 * byte_term
```

Why keep this at all, given there's a trained ML model? Because it requires **zero trained artifacts** — the detector runs out of the box, tests stay fast, and (crucially, see below) it's the honest fallback when the ML model would be operating out-of-distribution.

### `MLFlowScorer` — the trained RandomForest
Trained on the 17 approved forward-only CIC features (see §7) over real captured traffic. `RandomForestClassifier` was chosen deliberately — it's simple, doesn't need feature scaling, handles the mixed distributions of packet/byte statistics well, and (importantly for a security tool) its `feature_importances_` are inspectable, so you can audit *why* it flags something rather than trusting an opaque model.

### `CompositeFlowScorer` — the honest bridge between the two
Here's a subtlety that's easy to get wrong: the trained model expects the **full 17-dimensional feature vector**. Production streaming records often carry only the minimal contract (`packet_count`/`byte_count`/`flow_duration`). If you naively impute the other 14 features from training-set medians, you get an **out-of-distribution vector** the model was never trained to read — it will produce a confident-looking but meaningless number.

`CompositeFlowScorer` refuses to do that silently. It only calls the ML model when the incoming record genuinely supplies ≥5 of the approved features; otherwise it falls back to the heuristic. This is called out in the code as *"an honest engineering choice, not a bug"* — and it's exactly why the behavioral layer, not this per-flow model, ends up carrying most of the detection weight in production.

## 6. Step 3 — the behavioral tracker: the real detector (`behavior.py`)

This is described in the code as *"the essential layer,"* built on Ring et al. (2018)'s core idea: **a scan is a sequence of flows, not one flow.**

For every source IP, `BehaviorTracker` keeps a **bounded** rolling history of recent events (`SourceState`) and computes, on every new flow:

- **Fan-out**: unique destination hosts / ports / (host,port) pairs the source has touched
- **Entropy**: Shannon entropy of the destination-host / port / pair distributions (a scan hitting many distinct targets has high entropy; a client repeatedly hitting the same few servers has low entropy)
- **Small-flow ratio**: fraction of flows that are tiny (probe-shaped)
- **Scan-like fan-out**: fan-out counted *only* over flows whose per-flow score was above threshold — this is the key anti-camouflage trick (see below)
- **Persistence**: number of distinct time windows (bucketed by `window_seconds`) in which the source produced at least one scan-like flow — this is what lets *slow* scans accumulate evidence over minutes without ever looking bursty

**Why restrict fan-out to "scan-like" flows only?** Because plain fan-out alone is a bad discriminator — a CDN, an update server, or a monitoring probe legitimately touches hundreds of hosts with substantial, real flows (see the `benign_high_fanout` synthetic scenario, and `FanoutThresholdBaseline` in `baselines.py`, which is deliberately kept in the codebase as a *counter-example* — it has no small-flow gating and over-fires on exactly this benign pattern). By only counting fan-out among flows that *also* look probe-shaped, benign high-volume traffic contributes essentially zero to the signal that actually drives detection, while a real scan — many tiny probes to many destinations — lights it up strongly.

**Why bound the state at all?** Because this has to run indefinitely on a live link. `SourceState` caps: event history (both by a time horizon *and* a hard event count), unique-destination tracking (capped sets), and `BehaviorTracker` caps the total number of tracked sources with LRU eviction, plus a TTL (`expire()`) that drops sources that have gone quiet. `evaluation/benchmark.py` explicitly verifies this: after 20 waves of 1000 fresh sources each with TTL expiry, memory holds at ~1000 active sources, not 20,000 — proving state doesn't grow with the lifetime of the network, only with currently-active sources.

**Why two different time notions (`window_seconds` vs `history_horizon`)?** `window_seconds` (default 60s) drives the "burst" view — how many flows just happened recently, used for the fast-scan detection path. `history_horizon`/TTL (default 600s) is a much longer retention window over which fan-out, diversity, and persistence *accumulate*. This split is exactly what makes slow-scan detection possible: a scanner sending one probe every 25 seconds never looks bursty in any single 60-second window, but accumulates enough distinct scan-like pairs and enough distinct "suspicious windows" over the 10-minute horizon to still trip the detector — via the *persistence* path, not the *burst* path.

## 7. Step 4 — fusing evidence into one score (`detector.py`)

`ReconDetector._fuse()` combines three independent evidence signals into a single `[0, 1]` score:

```
score = w_flow · flow_evidence + w_fanout · fanout_evidence + w_persistence · persistence_evidence
```

with defaults `w_flow=0.20`, `w_fanout=0.55`, `w_persistence=0.25`. This weighting is deliberate: **behavior outweighs any single flow**. `flow_evidence` (from the per-flow scorer) can only *confirm* that scan-shaped flows are present — it's structurally incapable of driving a detection on its own, because it's the smallest weight and, more importantly, the detection *gate* (next section) never accepts flow evidence alone.

`fanout_evidence` and `persistence_evidence` are each passed through a **saturating function**:

```python
def _saturate(value, scale):
    return 1.0 - exp(-value / scale)
```

Why saturate instead of using the raw count? Two reasons. First, it keeps the score bounded in `[0,1]` without an arbitrary hard cap. Second — and this is the subtle bit documented in the code — the saturation `scale` constants (`fanout_pair_scale=12`, `persistence_scale=2`) are tuned so the fused score crosses the detection *threshold* at almost exactly the same point where the separate slow-path *count gate* (§8) is satisfied. If the score saturated more slowly than the gate requires, real slow scans would sit just below threshold for a couple of extra probes — and because slow sessions are short by nature, that delay could mean missing the scan almost entirely. Benign/sparse traffic, by contrast, produces close to zero scan-like pairs, so it can never approach these knees regardless of how fast saturation is tuned — so tightening the knee for scans costs nothing in false positives.

## 8. Step 5 — the detection gate: why score alone isn't enough

`_decide()` requires **both** `score ≥ threshold` (default 0.6) **and** one of two independent evidence paths:

- **Burst path**: `recent_window_flows ≥ 8` AND `scan_like_pairs ≥ 8` — enough scan-shaped flows have happened *recently*.
- **Slow path**: `persistence ≥ 2` (suspicious activity seen in at least 2 distinct time windows) AND `scan_like_pairs ≥ 8` cumulative.

Why require a count gate on top of the score at all? Because it's a second, independent line of defense against a false positive that happens to score high by chance, and — just as importantly — it's what explicitly rules out *sparse* traffic. A handful of stray probes spread thinly over a long time could accumulate persistence without the extra `scan_like_pairs ≥ 8` cumulative-count requirement; the code comment is explicit that this "only affects genuine spread-out probing," not merely-sparse benign traffic. This is directly reflected in the synthetic test suite: scenario **J (sparse)** must *not* fire, while scenario **K (repeated persistent)** must.

## 9. Step 6 — classifying the scan type

`_classify_scan_type()` looks only at **scan-like** hosts/ports (again, filtering out camouflage noise):

- **Vertical** — many ports (`≥6`), one/few hosts (`≤3`) — "probing one target thoroughly"
- **Horizontal** — many hosts (`≥6`), one/few ports (`≤3`) — "probing one service across the network"
- **Mixed** — meaningful counts of both (`≥4` hosts and `≥4` ports)
- **`unknown`** — returned whenever the evidence doesn't clearly fit a shape; the detector **never forces a label** it isn't confident about

Why base this on scan-like fan-out instead of raw fan-out? Same anti-camouflage reasoning as §6 — mixing in benign destinations shouldn't be able to smear a clean vertical scan into looking "mixed."

## 10. The output contract (`DetectionResult`)

```json
{
  "detected": true, "threat_class": "reconnaissance_port_scan",
  "scan_type": "vertical", "score": 0.7464,
  "source": "45.33.32.156", "timestamp": 0.8,
  "evidence": { "...": "full feature snapshot + score_components breakdown" }
}
```

This is intentionally a **plain dict/JSON structure with no dependency on any other component**. The detector is one of six planned SIH threat detectors; it hands its output to a future "common alert-scoring" layer it knows nothing about. The `evidence` block exists specifically so that downstream layer can re-weight, combine with the other five detectors' outputs, or explain the alert to an analyst — without needing to recompute anything.

## 11. Why real captured traffic instead of a public dataset (`portscan-lab/`)

The obvious shortcut would be training on CIC-IDS-2017 (a standard public IDS dataset). This project deliberately doesn't, for a documented reason: that dataset has **no source-IP or timestamp columns that survive into a clean train/test split**, so you can't prove your model generalizes to *unseen sources* — which is the actual production scenario (a scanner you've never seen before starts scanning).

Instead, `portscan-lab/` spins up a tiny **Docker lab** (attacker + victim containers on a bridge network) and captures **real packets**:

- `docker-compose.yml` / `Dockerfile` — the lab topology
- `capture_batch.sh` — drives real `nmap` scans (vertical/horizontal/mixed/slow/service/connect variants) plus carefully-designed benign traffic that **deliberately overlaps** scan traffic in shape (empty failed-connection flows, connect-then-close health checks) so the model can't cheat by memorizing "0 bytes = scan." Two batches are captured with disjoint IP ranges (`base` argument) specifically to get a genuine **source-disjoint** train/eval split.
- `pcap_to_cic.py` — extracts the 17 approved forward-only CIC features directly from packets with `scapy`, keyed by the ordered 5-tuple `(src, dst, sport, dport, proto)` — the reverse 5-tuple is a *different* flow and never contributes, mirroring the one-way constraint at the data layer, not just the model layer.
- `build_batch.py` — merges per-pcap CSVs, and explicitly **drops the victim's own reply packets** (captured incidentally by tcpdump running on the attacker's interface) so the final dataset never contains reverse-direction traffic, even by accident.

## 12. Why `Destination Port` is excluded from the ML model (but not from the detector)

This is one of the more counterintuitive decisions, worth explaining directly: you'd think "which port was targeted" is obviously useful for a port-scan detector. It's excluded from the **feature vector** anyway, because in a small captured dataset it becomes a weak identity a tree model can memorize (e.g., "port 8443 → always scan" just because it happened to only appear in scan pcaps) rather than learning the actual behavioral shape. Instead, `dst_port` is used exactly where it should be — as a **behavioral key** in `behavior.py`, i.e., it's *counted* (how many distinct ports has this source touched) rather than fed to the classifier as a raw value.

Similarly excluded: `Flow Duration` and any `*/s` rate feature (their exact computation can implicitly depend on knowing when the flow "ended," which under one-way observation is ambiguous), and — the big one — **any backward/`Bwd*` feature** (SYN/ACK, RST, reverse byte counts, ratios). `features.py` hard-enforces this with `FORBIDDEN_SUBSTRINGS` and `assert_features_are_one_way()`, and `tests/test_one_way_constraints.py` fails the build if a reverse-direction feature ever sneaks into the approved list or a saved model. This isn't just style — it's the mechanism that keeps the one-way constraint from being silently violated as the code evolves.

## 13. Why training uses group-disjoint cross-validation, not a plain random split (`training/train.py`)

Scan probes are nearly identical to each other at the feature level (many are literally `packets=1, bytes=0`), so a plain random train/test split would let near-duplicate rows land on both sides — inflating the reported accuracy without proving anything about generalization. `group_disjoint_folds()` fixes this by grouping rows by their **exact feature-vector fingerprint** first, then running `StratifiedGroupKFold` so a fingerprint group always lands entirely on one side of a fold. Because a couple of fingerprint groups are enormous (over 25% of all rows each), the code evaluates **every fold**, not just one arbitrary split, and reports mean ± std — a single split could get lucky or unlucky depending on which giant group it isolates.

Crucially, the code is explicit that **this per-flow cross-validated number is not the headline metric**. The real evaluation is `simulate_live_stream.py`, which replays a **separate batch, captured from different source IPs**, one flow at a time through the actual `ReconDetector` (the full behavioral pipeline, not just the classifier) with ground truth hidden until after scoring. That's the number that actually reflects streaming, unseen-source performance.

## 14. Honest limitations (by design, not omission)

The project's documentation is unusually blunt about what it can't do, and it's worth restating why, because it shapes what you should and shouldn't expect from it:

- **Single-source only.** If ten different IPs each scan a small slice of the target (a distributed/botnet scan), this detector — by design — sees ten separate low-volume sources and won't connect them into one campaign. That's flagged as a future *correlation-layer* problem, not something to hack around here; scenario **L** in the synthetic tests is deliberately expected to **not** fire, and the output schema is structured (`source` field, per-source evidence) so a future correlator *could* aggregate across sources.
- **Ultra-slow scanning is fundamentally hard, not a bug.** There's a real observability limit (cited from Safaei Pour & Bou-Harb 2019): a scanner slow enough starts looking indistinguishable from sparse, unrelated benign traffic. The measured slow-rate sweep in README shows detection succeeding down to about one probe every 45 seconds, and failing at one probe every 90 seconds. No detector — regardless of design — escapes this tradeoff without either false-positiving on real sparse traffic or missing arbitrarily slow scans.
- **No port-open knowledge, ever.** Because there's no return path, the detector can never know if a probed port was actually open. It only ever detects the *behavior* of probing, never the outcome.

## 15. Where each CLI command fits (`cli.py`)

```bash
python -m recon_detector demo      # runs all 12 synthetic scenarios, prints first-detection info
python -m recon_detector stream    # feeds real JSONL/CSV records through the detector, prints DetectionResults
python -m recon_detector train     # wraps training/train.py
python -m recon_detector evaluate  # wraps evaluation/evaluate_model.py
```

`stream` is the shape production integration would actually take: records come in one at a time (`cmd_stream` reads JSONL or replays a CSV), each is passed to `det.process(rec)`, and `det.expire_state()` is called periodically (driven by the record's own timestamps, not wall-clock time — important for replaying historical captures) to keep memory bounded exactly as described in §6.

`_load_detector()` is the one place that decides ML-vs-heuristic at startup: if a `per_flow_model.joblib` exists in the given model directory it loads `CompositeFlowScorer`; if loading fails for any reason, or no model directory is given, it falls back to the pure heuristic detector rather than crashing — the tool should never simply refuse to run because a model artifact is missing or corrupt.

---

## One-paragraph summary

A flow record arrives; a lightweight per-flow scorer flags whether it *looks* like a probe (tiny, payload-free); a per-source behavioral tracker accumulates fan-out, entropy, and persistence over a bounded rolling history, counting fan-out *only* among probe-shaped flows so that legitimate high-volume traffic (CDNs, monitors) can't inflate the signal; these three evidence sources (flow shape, scan-like fan-out, temporal persistence) are fused with weights that deliberately favor behavior over any single flow, saturated so slow scans and fast scans both reach the same threshold appropriately; a detection requires both a high fused score and one of two independent gates (a recent burst, or persistence + cumulative count) so that neither noise nor merely-sparse traffic can trigger a false alarm; and the whole system is honest about what it cannot do — distributed scans across many sources, and arbitrarily slow single-source scans — rather than silently failing or overclaiming.
