# Data (git-ignored)

Captures, Zeek logs, and label files are **not** committed (see `.gitignore`). This file
documents the expected layout and the label discipline from `CLAUDE.md` §8.

```
data/
  pcaps/        # raw captures (malicious + self-generated benign)
  zeek_logs/    # conn.log / ssl.log / x509.log per capture
  labels/       # one labels.jsonl sidecar per generated capture
```

## Sources (CLAUDE.md §8)

- **Malicious:** Stratosphere Lab / CTU (family-labelled, Zeek logs included) — primary;
  malware-traffic-analysis.net (in-the-wild, less structured).
- **Benign:** GENERATE YOURSELF — scripted browsing over Tranco top sites + normal lab
  activity, captured on the SAME network and period as the malware replay. This is the main
  defence against the environment artifact.

## Label sidecar format (`labels.jsonl`, one JSON object per line)

```json
{"pcap": "run_07.pcap", "start_ts": 0, "end_ts": 0, "src_ip": "", "dst_ip": "", "label": "benign|malicious", "family": "", "environment": ""}
```

Carry `family` and `environment` through the whole pipeline — the evaluation rules
(CLAUDE.md §7) depend on them.
