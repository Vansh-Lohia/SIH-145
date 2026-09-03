# CLAUDE.md — Encrypted-Session Malware Detection

Module of SIH 2026 Problem Statement 26145, "AI-Based Detection of Cyber Threats in
Unidirectional IP Traffic". Sponsor: National Technical Research Organisation (NTRO).
Team **SimpleX**, IIT Kharagpur.

This repo is **one of six detectors** in a shared pipeline. This file is the contract.
Read it before proposing any design change.

---

## 1. What this module detects

A compromised host inside the protected network making **encrypted (TLS/QUIC) connections
to an attacker's command-and-control server**. The traffic looks like ordinary HTTPS. The
content is opaque. We classify it from metadata alone.

The question the model answers: *is this TLS session a legitimate application, or malware
imitating one?*

---

## 2. Hard constraints — these are not negotiable

These come from the problem statement. Violating any of them invalidates the submission,
regardless of accuracy.

### 2.1 Read-only ingest
The pipeline sits behind a **hardware data diode**. Traffic flows in; nothing flows out.

Forbidden, always:
- Active probing, port scanning, banner grabbing
- Completing or initiating any handshake
- Any inline block, drop, rate-limit, or mitigation action
- Re-contacting the traffic's source or destination for any reason

### 2.2 No outbound calls from the enclave
This is the subtle version of 2.1 and the one most likely to be violated by accident.
The enclave **has no internet**. Every lookup table, model, and blocklist ships pre-loaded,
with an offline update path.

Specifically forbidden in code:
- DNS resolution of any observed domain
- GeoIP or ASN lookups over the network
- Threat-intel APIs (VirusTotal, AbuseIPDB, urlscan, anything)
- Any library that downloads weights, wordlists, or data on first use

**When adding a dependency, check it for network calls at import and at first use.**
Pin versions. Vendor any data file the library would otherwise fetch.

### 2.3 No payload decryption
TLS/QUIC sessions are analysed from metadata only. Never from decrypted content.
No TLS interception, no key logging, no MITM proxy, not even in the lab.

**Permitted and not a violation:** parsing the QUIC Initial packet. QUIC Initial packets
are protected with keys derived from the Destination Connection ID using a published,
version-specific salt (RFC 9001). Any passive observer can read the ClientHello without
any secret. This is standard passive practice. **Document this reasoning explicitly** —
an evaluator will ask.

### 2.4 Streaming, not batch
Process incrementally. Emit alerts with bounded latency. No end-of-run report.

### 2.5 Standardised alert schema
See section 5. Frozen. Do not change without updating every other module.

---

## 3. What is observable

| Layer | Available | Notes |
|---|---|---|
| ClientHello | Cipher suite list, extension list, supported groups, sig algorithms, ALPN, SNI | Plaintext. The core fingerprint source. |
| ServerHello | Chosen cipher, chosen extensions | Plaintext. |
| Certificate | Issuer, subject, validity, SAN, key size, self-signed flag | **TLS 1.2 only.** TLS 1.3 encrypts it. |
| Post-handshake | Packet sizes, directions, inter-arrival times, byte totals, duration | Always available. Content opaque. |

**Three feature families, in order of durability:**

1. **Shape / timing** — survives everything. Highest priority.
2. **Handshake fingerprint** — under pressure from Encrypted Client Hello (ECH).
3. **Certificate metadata** — TLS 1.2 only, shrinking every year. Bonus, not a pillar.

Design so that losing a family degrades the detector rather than breaking it. Log the
fraction of sessions where each family was available; report it.

---

## 4. Frozen technical decisions

Do not revisit these without raising it explicitly.

| Decision | Choice | Reason |
|---|---|---|
| Parsing | **Zeek** (`conn.log`, `ssl.log`, `x509.log`) | Structured TLS metadata for free. Don't hand-roll a TCP reassembler. |
| Fingerprint | **JA4+ (JA4 / JA4S / JA4X / JA4T)**, never JA3 | Chrome randomises TLS extension order, so JA3 hashes are unstable per-connection. JA4 sorts before hashing. |
| GREASE | Strip RFC 8701 values before hashing | Otherwise fingerprints are noise. |
| Baseline model | **LightGBM on tabular features** | Trains in seconds, interpretable, strong on tabular. Build this first. |
| Sequence model | **1D-CNN** over first N packets, not LSTM | Better accuracy per unit of inference cost; we have a latency budget. |
| Fingerprints are | **features**, not a lookup table | Malware deliberately mimics browser fingerprints. A JA4 blocklist is a signature system wearing an ML hat. |
| Streaming | Python asyncio + sliding-window state | Kafka/Flink is documented as the scale-up path, not built. |
| Explainability | SHAP contributions on tree models | Required by the alert schema's `evidence` field. |

### Latency and window
- Per-session decision on the **first 20–30 packets**, or session close, whichever first.
- Target: **p99 alert latency < 30 s** from session start.
- State this number in documentation and demonstrate it.

---

## 5. Alert schema — shared contract, do not change alone

```json
{
  "alert_id": "uuid",
  "timestamp": "ISO8601",
  "detector": "encrypted_session_v1",
  "flow_id": {"src_ip": "", "src_port": 0, "dst_ip": "", "dst_port": 0, "proto": ""},
  "threat_class": "encrypted_malware",
  "mitre_technique": "T1071.001",
  "severity": "high",
  "confidence": 0.87,
  "window": {"start": "ISO8601", "end": "ISO8601"},
  "evidence": [
    {"feature": "ja4", "value": "t13d1516h2_8daaf6152771_b186095e22b6", "contribution": 0.31},
    {"feature": "iat_std_ms", "value": 12.4, "contribution": 0.22}
  ]
}
```

`severity` = inherent impact of the threat class. `confidence` = model certainty.
They are different fields. Do not conflate them.

---

## 6. Feature families to implement

### 6.1 Handshake (JA4+)
- JA4 from ClientHello, JA4S from ServerHello, JA4X from certificate, JA4T from TCP options
- Treat hashes as categorical features (target/count encoding), not as lookup keys
- Also expose raw components: TLS version, cipher count, extension count, ALPN, SNI present/absent

**Write the JA4 construction yourself** rather than only importing a library. You need to
defend how the fingerprint is built when questioned.

### 6.2 Shape / timing (SPLT)
Per session, first N=20 packets, each as `(size, direction, inter_arrival_ms)`.

Two consumers:
- **Summary stats** for the LightGBM baseline: mean/std/min/max of sizes and IATs, up:down
  packet ratio, up:down byte ratio, burst count, idle-gap count, session duration
- **Raw sequence** for the 1D-CNN

Reference: Anderson & McGrew (Cisco), *Identifying Encrypted Malware Traffic with
Contextual Flow Data* — the origin of SPLT features.

### 6.3 Certificate (TLS 1.2 only)
Self-signed flag, validity window length, issuer, subject CN character entropy,
SAN count, SNI/subject mismatch, key size.

Gate on TLS version. Emit a `cert_features_available` boolean so the model can learn to
ignore them when absent, rather than seeing silent zeros.

---

## 7. Evaluation protocol — the part that decides credibility

**Read Arp et al., "Dos and Don'ts of Machine Learning in Computer Security", USENIX
Security 2022.** Our protocol follows it. Cite it in the documentation.

The core risk: malware pcaps come from sandboxes, benign pcaps come from elsewhere, at a
different time, on a different network, with different TLS library versions. The model
then learns *"which capture environment is this?"* and reports 99% accuracy that collapses
on real traffic. Our DGA module already hit exactly this failure — recall fell from 95.6%
to ~0% under a held-out-family test.

### Mandatory rules

1. **Never split flows from the same pcap across train and test.** Split by capture file.
2. **Hold out entire malware families.** Train on families A–H, test on I–J. This number
   is the headline result, not the random-split number.
3. **Split temporally** where capture dates allow — train on older, test on newer.
4. **Report TPR at a fixed low FPR** (0.1%). Never balanced accuracy, never accuracy alone.
5. **Report alerts/hour** at the chosen operating point. 94% recall is worthless if it
   means 400 alerts an hour.
6. **Sanity-check top features.** If TTL, absolute timestamp, a single cipher suite used by
   only one capture, or anything environment-specific ranks highly — that's an artifact.
   Investigate before celebrating.
7. **Hold one dataset completely unseen** until the final week. Never tune against it.

### Report format for every experiment
```
split_type | TPR@0.1%FPR | precision | recall | F1 | alerts/hr | p99 latency
```
Log both the random-split number and the held-out-family number side by side. The gap
between them is itself a finding worth presenting.

---

## 8. Data

### Malicious
- **Stratosphere Lab / CTU** malware captures (stratosphereips.org) — real malware, long
  runs, Zeek logs included, family-labelled. Primary source; family labels enable rule 2.
- **malware-traffic-analysis.net** — real in-the-wild infection pcaps, less structured labels.

### Benign
**Generate this yourself.** Scripted browsing over Tranco top sites plus normal lab
activity, captured on the same network and in the same period as your malware replay
wherever possible. This is the main defence against the environment artifact.

### Label discipline
Every generated capture writes a sidecar `labels.jsonl`:
```json
{"pcap": "run_07.pcap", "start_ts": 0, "end_ts": 0, "src_ip": "", "dst_ip": "", "label": "benign|malicious", "family": "", "environment": ""}
```
Carry `family` and `environment` through the whole pipeline — the evaluation rules above
depend on them.

---

## 9. Build order

Do not skip step 1, and do not start step 3 before step 2 reports an honest number.

1. **Environment** — Zeek installed and emitting `ssl.log` from a replayed pcap.
   `tcpreplay` harness at controlled rate. Repo skeleton, alert schema file committed.
2. **Baseline** — JA4 computed in-house, tabular features, LightGBM, evaluated under
   leave-one-family-out. This is a real result even if the number is bad.
3. **Sequence model** — 1D-CNN on SPLT. Compare against baseline.
4. **Fusion** — concatenate CNN embedding into the GBM, or average scores. Only after
   both work independently.
5. **Ablation** — fingerprints alone / shape alone / combined. Publish the table; it
   proves each family contributes and makes the ECH argument concrete.
6. **Streaming integration** — wire into the shared pipeline, emit schema-conformant
   alerts, measure p99 latency and throughput.

---

## 10. Known traps

- **JA3 anywhere in the code.** Wrong choice, and a knowledgeable evaluator will catch it.
- **Fingerprint lookup tables.** Static signatures pretending to be ML.
- **Balanced test sets.** Real traffic is ~99.9% benign.
- **Silent zeros for missing certificate features.** Use an availability flag.
- **A dependency that phones home.** Audit before adding.
- **Deep learning before the baseline works.** The GBM is often competitive and always faster.
- **Reporting only the random-split number.** The held-out-family number is the real one.

---

## 11. Open items

- [ ] Throughput target: measure and state (`sustained X flows/sec, p99 latency Y s`)
- [ ] Confirm which malware families are available with clean labels in CTU
- [ ] Decide N for the packet-sequence window (20 vs 30) — test both
- [ ] ECH prevalence in our datasets — measure, expect near zero, report anyway
- [ ] Fusion strategy: embedding concat vs score averaging
