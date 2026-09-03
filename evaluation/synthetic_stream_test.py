"""Synthetic strict-one-way stream evaluation (spec sections 23, 24).

Runs scenarios A-L and reports, per scenario: whether/when detection fired,
how many flows were observed before first detection, the scan type, and the
peak score.  Also runs a slow-rate sweep to illustrate the research tradeoff
(lower rate + less concentration -> weaker/slower evidence).

Nothing here manufactures expected numbers -- results are whatever the detector
actually produces.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))

from recon_detector import DetectorConfig, ReconDetector  # noqa: E402
from recon_detector import synthetic  # noqa: E402

# Scenarios where a detection IS expected (ground truth), for scoring FN/FP.
SCAN_SCENARIOS = {
    "B_fast_vertical", "C_fast_horizontal", "D_mixed",
    "E_slow_vertical", "F_slow_horizontal", "H_udp_scan",
    "I_camouflaged", "K_repeated_persistent",
}
BENIGN_SCENARIOS = {"A_benign", "G_benign_high_fanout", "J_sparse"}
# L is explicitly a documented limitation (not scored as pass/fail).


def _make_detector(model_dir: Optional[str]) -> ReconDetector:
    config = DetectorConfig()
    if model_dir and (Path(model_dir) / "per_flow_model.joblib").exists():
        try:
            return ReconDetector.from_model_dir(model_dir, config=config)
        except Exception:  # noqa: BLE001
            pass
    return ReconDetector(config=config)


def run_scenario(fn: Callable, model_dir: Optional[str]) -> Dict:
    det = _make_detector(model_dir)
    records = fn()
    first = None
    flows_before = None
    peak = 0.0
    scan_type = "unknown"
    for i, rec in enumerate(records, start=1):
        res = det.process(rec)
        peak = max(peak, res.score)
        if res.detected and first is None:
            first = res.timestamp
            flows_before = i
            scan_type = res.scan_type
    return {
        "total_records": len(records),
        "detected": first is not None,
        "first_detection_ts": first,
        "flows_before_detection": flows_before,
        "scan_type": scan_type,
        "peak_score": round(peak, 4),
    }


def run_all(model_dir: Optional[str] = "models") -> Dict[str, Dict]:
    print("=== Synthetic strict-one-way stream evaluation ===")
    results = {}
    passed = 0
    total_scored = 0
    for name, fn in synthetic.SCENARIOS.items():
        r = run_scenario(fn, model_dir)
        results[name] = r
        verdict = ""
        if name in SCAN_SCENARIOS:
            total_scored += 1
            ok = r["detected"]
            passed += int(ok)
            verdict = "OK" if ok else "MISS (false negative)"
        elif name in BENIGN_SCENARIOS:
            total_scored += 1
            ok = not r["detected"]
            passed += int(ok)
            verdict = "OK" if ok else "FALSE POSITIVE"
        elif name == "L_multi_source_low_rate":
            verdict = ("not flagged (expected: single-source detector, distributed "
                       "campaign is a documented limitation)")
        print(f"[{name}] detected={r['detected']} "
              f"type={r['scan_type']} peak={r['peak_score']} "
              f"flows_before={r['flows_before_detection']} -> {verdict}")
    print(f"\nScored scenarios passed: {passed}/{total_scored}")
    return results


def slow_rate_sweep(model_dir: Optional[str] = "models") -> List[Dict]:
    """Vertical scan of fixed size at decreasing rates (spec section 24)."""
    print("\n=== Slow-rate sweep (vertical scan, 30 ports, varying gap) ===")
    rows = []
    for gap in [0.05, 0.5, 5.0, 20.0, 45.0, 90.0]:
        det = _make_detector(model_dir)
        import random
        records = synthetic.slow_vertical_scan(n_ports=30, gap=gap,
                                               rng=random.Random(99))
        first = None
        flows_before = None
        peak = 0.0
        for i, rec in enumerate(records, start=1):
            res = det.process(rec)
            peak = max(peak, res.score)
            if res.detected and first is None:
                first = res.timestamp
                flows_before = i
        span = records[-1]["timestamp"] - records[0]["timestamp"]
        row = {
            "gap_seconds": gap,
            "effective_rate_per_s": round(1.0 / gap, 4) if gap else None,
            "total_span_seconds": round(span, 2),
            "detected": first is not None,
            "flows_before_detection": flows_before,
            "time_to_detection_s": round(first - records[0]["timestamp"], 2) if first else None,
            "peak_score": round(peak, 4),
        }
        rows.append(row)
        print(f"gap={gap:>5}s rate~{row['effective_rate_per_s']}/s "
              f"detected={row['detected']} "
              f"flows_before={flows_before} "
              f"ttd={row['time_to_detection_s']}s peak={row['peak_score']}")
    print("Interpretation: as the gap grows the same scan takes longer to "
          "confirm and eventually resembles sparse benign traffic -- the "
          "observability tradeoff from Safaei Pour & Bou-Harb (2019).")
    return rows


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--model-dir", default="models")
    a = ap.parse_args()
    run_all(a.model_dir)
    slow_rate_sweep(a.model_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
