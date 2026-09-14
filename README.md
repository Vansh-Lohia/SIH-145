# Volumetric / Protocol DDoS Detection 

This repo is scoped specifically to **volumetric and protocol DDoS attacks** (threat class **a** in the problem statement: SYN floods, UDP reflection/amplification, spoofed-source floods) - one of six threat-detection branches in a larger unidirectional (read-only) network threat-detection pipeline being built by the team. It does not cover C2 beaconing, DGA/DNS tunnelling, encrypted-malware detection, recon/port-scanning, or exfiltration - those are separate branches owned by other team members.

**Problem Statement:**  AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
**Organization:** National Technical Research Organisation (NTRO)

## Context

This module assumes the "data diode" constraint from the problem statement: the detection system can only passively observe traffic (packet captures / flow records) and can never send probes, complete handshakes, or push mitigation actions back across the ingest path. Detection has to work purely from what crosses the wire.

## Planned Architecture (Full Design)

The DDoS engine runs 3 parallel, always-on branches (no pre-classification is possible since live traffic is unlabeled):

- **Branch A - SYN flood**
- **Branch B - UDP reflection/amplification**
- **Branch C - Spoofed-source / generic volumetric** (protocol-agnostic catch-all)

All three branches share one feature-extraction layer to avoid recomputation, and each outputs a continuous confidence score (not a binary flag) - scores are combined at a fusion stage.

### Windowing scheme

- **Primary key:** `(destination_ip, protocol)`, 10-second sliding window. Keeps stats protocol-clean - SYN ratios are only meaningful over TCP, size/port stats only over UDP - so one protocol's baseline noise doesn't mask a spike in another.
- **Secondary:** one lightweight aggregate counter per `destination_ip` (all protocols combined) - total packets/bytes/sec. Feeds the fusion stage as an extra signal to catch multi-vector attacks (e.g. simultaneous SYN + UDP flood, each individually under per-protocol threshold).

### Shared feature layer (computed once per window, reused across branches)

- Packet / byte / new-flow rate (running counters)
- Distinct source-IP count in window ("fan-in")
- Max single-source share - `(packets from top source IP) / (total packets in window)`
- TCP flag counts (SYN, ACK, FIN, RST)
- TTL-baseline deviation - observed TTL for a source IP vs. a learned per-IP baseline TTL, flags spoofing without active probing
- Packet-size distribution stats (running mean/std)

> Full Shannon entropy for source-IP diversity was considered and dropped for the initial build - expensive at line rate (needs a full per-source frequency map + log-sum per window). Fan-in + max-source-share approximate the same signal at O(1) cost; revisit only if this proves insufficient.

### Branch A - SYN flood

**Features:** TCP flags containing SYN only (no ACK/FIN/RST); 1–2 packets per flow; ~40–64B per flow (header only); ~0ms flow duration; new-flows/sec spike targeting a single destination; TTL-baseline deviation as supporting evidence.

**Detection logic:** ratio of SYN-only flows to completed flows (ACK/FIN present), per destination, over a 10s window, compared against a **per-destination** historical baseline. CUSUM/EWMA change-point detection on this ratio for low-latency, O(1)-cost flagging.

### Branch B - UDP reflection/amplification

**Features:** volumetric rate spike (shared); packet-size distribution skewed large; source port matching known abused amplification services (53/DNS, 123/NTP, 1900/SSDP, 11211/memcached, 19/chargen, 161/SNMP); orphan-response ratio (large inbound UDP with no matching prior outbound query within ~30s lookback - *visibility into the protected network's own outbound queries needs confirmation given the unidirectional setup*); distinct source-IP count (shared).

**Detection logic (continuous score):**

```
rate_score    = normalize(current_udp_rate / baseline_udp_rate_for_dest)
port_score    = fraction of packets with src_port in known-abused-service set
orphan_score  = large inbound UDP w/ no matching outbound query / total large inbound UDP
entropy_score = shared fan-in / max-source-share value (normalized)
confidence    = w1*rate_score + w2*port_score + w3*orphan_score + w4*entropy_score
```

(weights hand-tuned for demo; learn from labeled data later)

### Branch C - Spoofed-source / generic volumetric

Protocol-agnostic catch-all for spoofed floods that don't match SYN or UDP-amplification signatures. Reuses shared features only:

```
rate_score   = normalize(current_rate / baseline_rate_for_dest)
fanin_score  = normalize(distinct_source_count)
spread_score = 1 - max_source_share
ttl_score    = ttl_baseline_deviation
confidence   = w1*rate_score + w2*fanin_score + w3*spread_score + w4*ttl_score
```

Also boosts confidence when co-firing with the SYN or UDP branch on the same destination.

### Model selection

- **Hot path** (per-packet/per-flow, must be O(1)): CUSUM/EWMA change-point detection - cheap, streaming-friendly, no training data needed.
- **Cold path** (per-window-close, ~every 10s per destination): fusion of branch scores.
  - Start: logistic regression over normalized sub-scores (weights learned from labeled synthetic traffic).
  - If time allows: small gradient-boosted tree (XGBoost/LightGBM).
- **Subtype attribution:** derived from which branch(es) contributed most, not a separate classifier.

### Open items

- Confirm outbound-query visibility for the UDP orphan-response check
- Fusion weights: hand-tuned for demo vs. learned
- Full Shannon entropy: revisit only if needed

## What's implemented so far - Branch A: Volumetric DDoS

- **Traffic generation & capture (Docker):** a 3-container lab (`victim`, `attacker`, `monitor`) simulating a passive monitoring setup. `monitor` shares `victim`'s network namespace and captures traffic via `tcpdump`, mirroring the read-only diode model - it observes everything to/from the victim but never talks back.
- **Feature extraction (`extract_features.py`, `windowed_features.py`):** reads pcaps with `scapy`, classifies TCP packets by flag combination (SYN-only, SYN-ACK, ACK, FIN, RST), and computes windowed features (1-second buckets) - packet rate and a SYN-only-to-completed-session ratio, which is the core signal for SYN flood detection.
- **Detection engine (`cusum_detector.py`):** a CUSUM (cumulative sum) change-point detector that learns a short baseline from early traffic, then flags sustained deviations above it. This is the "hot path" from the design - cheap, streaming-friendly, needs no training data.

### Results

Using a simulated benign baseline (15 HTTP requests over 15s) followed by a short unthrottled SYN flood (`hping3 -S --flood`):

| Metric | Benign | Flood |
|---|---|---|
| SYN-only : ACK ratio | ~0.1 | 5,000–15,000+ |
| CUSUM value | 0 (flat) | crosses alert threshold within 1 window (~1 sec) |

**Detection latency:** ~1 second from attack onset - maps to the problem statement's "bounded latency, streaming not batch" requirement.

**Note on the environment:** since the Docker attacker isn't spoofing its source IP, every SYN-ACK reply is auto-RST'd by the attacker's own kernel (it never issued a real `connect()`), so the SYN:SYN-ACK ratio alone doesn't distinguish flood from benign here - the separating signal is the SYN-only vs. completed-session (ACK/FIN) ratio and raw packet rate. Real-world spoofed attacks would show this at the SYN:SYN-ACK level directly (see planned TTL-deviation feature below).

## Repo structure

```
ddos-demo/
├── docker-compose.yml       # 3-container lab: victim, attacker, monitor
├── victim/Dockerfile        # simple HTTP server target
├── attacker/Dockerfile      # hping3 + curl
├── monitor/Dockerfile       # tcpdump, shares victim's netns
├── extract_features.py      # Stage 1: TCP flag classification
├── windowed_features.py     # Stage 2: time-windowed rate/ratio features
├── cusum_detector.py        # Stage 3: CUSUM change-point detection
└── captures/                # generated pcaps (gitignored - regenerate locally)
```

## Running the lab

```bash
docker compose up -d --build
```

Capture benign baseline:

```bash
docker exec -it monitor tcpdump -i eth0 -w /captures/benign.pcap
# in a second terminal:
docker exec -it attacker sh -c 'for i in $(seq 1 15); do curl -s -o /dev/null http://victim; sleep 1; done'
```

Capture flood traffic (keep it short - a few seconds of --flood generates a lot of packets):

```bash
docker exec -it monitor tcpdump -i eth0 -w /captures/syn_flood.pcap
# in a second terminal:
docker exec -it attacker hping3 -S --flood -p 80 victim
```

Run detection:

```bash
python cusum_detector.py
```

## Status / Next steps

- [x] SYN flood detection - feature extraction + CUSUM, demonstrated on real captured traffic
- [ ] UDP reflection/amplification detection (Branch B)
- [ ] TTL-baseline deviation feature (requires spoofed-source traffic to demonstrate meaningfully)
- [ ] Fusion layer (logistic regression / XGBoost) - deferred until multiple branches exist to fuse
- [ ] Standardized alert schema output
