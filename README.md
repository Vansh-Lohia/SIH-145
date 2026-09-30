# SimpleX Dashboard — Passive Threat Detection (SIH 2026 · PS 26145)

One screen for all six SimpleX detectors on one-way (data-diode) traffic:
**live monitor · alert investigation with evidence · validation results · architecture**.
(The overall project README lives on the `main` branch.)

## What it shows

- **Real detector outputs, one schema.** Each detector branch has its own native output
  format. `exporters/` adapts all six into a single unified alert schema (`exporters/common.py`):
  threat class, **severity** (inherent impact) and **confidence** (detector certainty) as
  separate fields, **MITRE ATT&CK** technique, flow, evidence and data source.
- **Replay mode.** Alerts come from separate captures, so they are interleaved onto one
  replay timeline. Every alert keeps its **original capture time** and **data source**
  (real capture / lab-captured / synthetic scenario), shown in the UI.
- **Honest generalization.** Encrypted-malware alerts come from models that never saw the
  alert's malware family (leave-one-family-out); DGA alerts come from families held out of
  training. False positives the detectors actually produced are kept and labelled.

| Detector | Source branch | Data behind the alerts |
|---|---|---|
| Malware in encrypted sessions | `encrypted-malware` | Real: Stratosphere CTU + 2025 in-the-wild (malware-traffic-analysis.net) |
| DGA domains | `dga-dns` | Real: DGArchive + Tranco, six families held out of training |
| DNS tunnelling | `dga-dns` | Synthetic DNS windows |
| Data exfiltration | `data-exfiltration` | Lab: mirrored namespace network, Zeek |
| Volumetric DDoS | `volumetric-ddos-v2` | Lab: Docker attacker / victim / monitor |
| Port scanning | `port_scanning` | Synthetic strict one-way scenarios, trained detector |
| Botnet C2 | `botnet-c2` | Synthetic CTU-13-style scenarios (real CTU-13 validation in progress) |

## Run locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Regenerate the alert data

The exporters read each detector branch's code and outputs from `.sources/<branch>/`
(git-ignored), plus a local checkout of the encrypted-session detector.

```bash
for b in port_scanning botnet-c2 data-exfiltration volumetric-ddos-v2 dga-dns; do
  mkdir -p .sources/$b && git archive origin/$b | tar -x -C .sources/$b
done
cd exporters
python3 export_ddos.py && python3 export_exfil.py && python3 export_portscan.py
python3 export_dns.py && python3 export_botnet.py
ENCDETECT_REPO=/path/to/encrypted-session-detector python3 export_encrypted.py
python3 build_all.py          # -> data/alerts.jsonl
```

Validation numbers shown in the dashboard live in `data/validation.json`.
