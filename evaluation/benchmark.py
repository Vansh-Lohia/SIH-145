"""Throughput / latency / bounded-state benchmark (spec sections 21, 26).

Measures actual performance -- no invented numbers.  Reports flows/sec, mean
and p95 per-record latency, active source-state size, and demonstrates that
state stays bounded under TTL expiry.
"""

from __future__ import annotations

import random
import sys
import time
from pathlib import Path
from typing import Dict, Optional

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))

from recon_detector import DetectorConfig, ReconDetector  # noqa: E402


def _make_detector(model_dir: Optional[str]) -> ReconDetector:
    if model_dir and (Path(model_dir) / "per_flow_model.joblib").exists():
        try:
            return ReconDetector.from_model_dir(model_dir, config=DetectorConfig())
        except Exception as exc:  # noqa: BLE001
            print(f"[warn] could not load model from {model_dir}: {exc}; "
                  "falling back to heuristic scorer", file=sys.stderr)
    return ReconDetector(config=DetectorConfig())


def _percentile(values, q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = int(round((len(s) - 1) * q))
    return s[k]


def run_throughput(model_dir: Optional[str] = "models", n: int = 100_000,
                   n_sources: int = 500) -> Dict:
    det = _make_detector(model_dir)
    rng = random.Random(7)
    print(f"=== Throughput benchmark: {n} records, {n_sources} sources ===")

    latencies = []
    t0 = time.perf_counter()
    base = 1_000_000.0
    for i in range(n):
        src = f"10.{rng.randint(0, n_sources // 256)}.{rng.randint(0,255)}.{rng.randint(1,254)}"
        rec = {
            "timestamp": base + i * 0.001,
            "src_ip": src,
            "dst_ip": f"192.168.{rng.randint(0,255)}.{rng.randint(1,254)}",
            "dst_port": rng.randint(1, 65535),
            "protocol": "TCP",
            "packet_count": rng.choice([1, 1, 1, 5, 20]),
            "byte_count": rng.choice([0, 0, 40, 2000]),
            "flow_duration": rng.uniform(0, 1),
        }
        s = time.perf_counter()
        det.process(rec)
        latencies.append((time.perf_counter() - s) * 1e6)  # microseconds
    elapsed = time.perf_counter() - t0

    result = {
        "records": n,
        "elapsed_seconds": round(elapsed, 3),
        "flows_per_second": round(n / elapsed, 1),
        "latency_us_mean": round(sum(latencies) / len(latencies), 2),
        "latency_us_p95": round(_percentile(latencies, 0.95), 2),
        "latency_us_p99": round(_percentile(latencies, 0.99), 2),
        "active_sources": det.active_sources,
        "retained_events": det.tracker.total_retained_events(),
    }
    for k, v in result.items():
        print(f"  {k}: {v}")
    return result


def run_bounded_state(model_dir: Optional[str] = "models") -> Dict:
    """Feed many transient sources over a long time span and show that TTL
    expiry keeps active-source count bounded."""
    print("\n=== Bounded-state test (TTL expiry) ===")
    det = _make_detector(model_dir)
    ttl = det.config.state_ttl
    peak = 0
    t = 1_000_000.0
    for wave in range(20):
        # each wave: 1000 brand-new sources, well after the previous wave's TTL
        t += ttl + 60
        for s in range(1000):
            det.process({
                "timestamp": t + s * 0.001,
                "src_ip": f"172.{wave}.{s // 256}.{(s % 256) + 1}",
                "dst_ip": "10.0.0.1",
                "dst_port": 80,
                "packet_count": 1, "byte_count": 0, "flow_duration": 0,
            })
        det.expire_state(t + 2)  # expire sources from earlier waves
        peak = max(peak, det.active_sources)
    result = {
        "waves": 20,
        "sources_per_wave": 1000,
        "active_sources_after_expiry": det.active_sources,
        "peak_active_sources": peak,
        "note": "active sources stay ~one wave, not 20k -- state is bounded by TTL.",
    }
    for k, v in result.items():
        print(f"  {k}: {v}")
    return result


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--model-dir", default="models_docker")
    ap.add_argument("--n", type=int, default=100_000)
    a = ap.parse_args()
    run_throughput(a.model_dir, n=a.n)
    run_bounded_state(a.model_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
