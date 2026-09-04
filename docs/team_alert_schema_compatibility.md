# Alert schema compatibility across the team (SIH-145) — found 2026-09-04

Checked every other detector branch in `Vansh-Lohia/SIH-145` for how they build alerts, to
see whether this detector's output (`schema/alert_schema.json`, built via
`src/encdetect/alert.py`) is actually interoperable with a shared fusion/dashboard layer.
**It currently isn't — three different, incompatible shapes exist.** Nothing on other
branches was modified; this is a finding for the team to resolve, not something to patch
unilaterally.

## This detector (`encrypted-malware` branch) — matches `CLAUDE.md`'s frozen contract

```json
{
  "alert_id": "uuid", "timestamp": "ISO8601", "detector": "encrypted_session_v1",
  "flow_id": {"src_ip": "", "src_port": 0, "dst_ip": "", "dst_port": 0, "proto": ""},
  "threat_class": "encrypted_malware", "mitre_technique": "T1071.001",
  "severity": "high", "confidence": 0.87,
  "window": {"start": "ISO8601", "end": "ISO8601"},
  "evidence": [{"feature": "ja4", "value": "...", "contribution": 0.31}]
}
```
`severity` (inherent impact) and `confidence` (model certainty) are deliberately separate,
independent fields — set by the detector, not derived from each other.

## `dga-dns` branch (`src/pipeline/alert_schema.py`) — conflicts

```json
{"alert_id": "uuid", "timestamp": 1234567890.12, "flow_id": "some-string-id",
 "threat_class": "DGA", "severity": "HIGH", "confidence": 0.9, "evidence": {...}}
```

- **`severity` is derived FROM `confidence`** via fixed thresholds (≥0.85→CRITICAL, ≥0.60→
  HIGH, ≥0.30→MEDIUM, else LOW). This is exactly the conflation `CLAUDE.md` says not to do —
  severity should reflect the threat class's inherent impact, not the model's certainty.
- `flow_id` is a bare string, not a structured 5-tuple object.
- `timestamp` is a raw epoch float, not ISO8601.
- No `mitre_technique`, no `window` (start/end).
- `evidence` is a free-form dict, not a list of ranked `{feature, value, contribution}`.

## `port_scanning` branch (`src/recon_detector/schemas.py`) — conflicts differently

`DetectionResult`: `detected` (bool), `threat_class`, `scan_type`, **`score`** (single float —
no severity/confidence split at all), `timestamp` (epoch float), `source` (string),
`evidence` (dict). No structured `flow_id`, no `mitre_technique`, no `window`.

## `botnet-c2` / `data-exfiltration` / `volumetric-ddos-v2` — no alert-building code found
No `alert_schema`-shaped file or matching keys turned up in these branches at all as of this
check — either not built yet, or using a different convention/keyword not searched for.

## Why this matters now, not later

`CLAUDE.md`'s whole premise for the shared schema is that "the dashboard and downstream
components [don't become] tightly coupled to individual models" — that only holds if every
detector actually emits the same shape. Right now a fusion/dashboard layer would need
per-detector adapters for at least 3 different formats, or one detector's output silently
won't render fields the dashboard expects (no `mitre_technique`/`window` from two of them).

## Suggested next step (team decision, not made unilaterally here)

Pick one canonical schema — this detector's already matches the literal spec in the shared
`CLAUDE.md`, so it's a reasonable starting point — and have each detector emit that shape
directly, or have the fusion layer explicitly document per-detector adapters if reshaping
should happen there instead. Either is fine; what matters is picking one on purpose rather
than three teammates each building alerts independently and discovering the mismatch at
integration time.
