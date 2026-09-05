"""Command-line interface: ``python -m recon_detector <command>``.

Commands:
    train     -- train the per-flow model from a captured dataset CSV
    evaluate  -- offline supervised metrics on a holdout split
    stream    -- run the streaming detector over JSONL / CSV-replay input
    demo      -- run built-in synthetic scenarios and print detections
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable, Iterator, Optional

from .detector import DetectorConfig, ReconDetector
from .schemas import FlowRecord


def _load_detector(model_dir: Optional[str], config: DetectorConfig) -> ReconDetector:
    if model_dir and Path(model_dir).exists() and (Path(model_dir) / "per_flow_model.joblib").exists():
        try:
            return ReconDetector.from_model_dir(model_dir, config=config)
        except Exception as exc:  # noqa: BLE001
            print(f"[warn] could not load model from {model_dir}: {exc}; "
                  "falling back to heuristic scorer", file=sys.stderr)
    return ReconDetector(config=config)


def _iter_jsonl(path: Optional[str]) -> Iterator[dict]:
    fh = sys.stdin if path in (None, "-") else open(path, "r")
    try:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)
    finally:
        if fh is not sys.stdin:
            fh.close()


def _iter_csv_replay(path: str) -> Iterator[dict]:
    import csv

    with open(path, newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            yield {k: v for k, v in row.items()}


def cmd_stream(args: argparse.Namespace) -> int:
    config = DetectorConfig(
        window_seconds=args.window,
        state_ttl=args.ttl,
        detection_threshold=args.threshold,
    )
    det = _load_detector(args.model_dir, config)
    records: Iterable[dict]
    if args.csv:
        records = _iter_csv_replay(args.csv)
    else:
        records = _iter_jsonl(args.input)

    n = 0
    n_det = 0
    last_expire = None
    for rec in records:
        result = det.process(rec)
        n += 1
        # Periodic state expiry driven by record time.
        if last_expire is None:
            last_expire = result.timestamp
        if result.timestamp - last_expire > args.ttl:
            det.expire_state(result.timestamp)
            last_expire = result.timestamp
        if result.detected or args.all:
            n_det += 1
            print(result.to_json())
    print(f"[stream] processed={n} emitted={n_det} active_sources={det.active_sources}",
          file=sys.stderr)
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    # Imported lazily so `stream`/`demo` do not require the training deps path.
    from training.train import run_training

    run_training(
        dataset=args.dataset,
        model_dir=args.model_dir,
        test_size=args.test_size,
        n_estimators=args.n_estimators,
        max_rows=args.max_rows,
        random_state=args.random_state,
    )
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    from evaluation.evaluate_model import run_evaluation

    run_evaluation(model_dir=args.model_dir, out=args.out)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from . import synthetic

    config = DetectorConfig(window_seconds=args.window, state_ttl=args.ttl)
    for name, fn in synthetic.SCENARIOS.items():
        det = _load_detector(args.model_dir, config)
        records = fn()
        fired = False
        best = None
        for rec in records:
            res = det.process(rec)
            if best is None or res.score > best.score:
                best = res
            if res.detected and not fired:
                fired = True
                print(f"[{name}] FIRST DETECTION at ts={res.timestamp:.2f} "
                      f"score={res.score} type={res.scan_type} "
                      f"flows={res.evidence['observed_flows']}")
        if not fired:
            s = best.score if best else 0.0
            print(f"[{name}] no detection (max score={s})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="recon_detector",
                                description="Passive one-way port-scan detector")
    sub = p.add_subparsers(dest="command", required=True)

    common_model = dict(default="models_docker", help="model artifact directory")

    ptr = sub.add_parser("train", help="train per-flow model from a captured dataset CSV")
    ptr.add_argument("--dataset", default=None, help="path to training CSV (e.g. portscan-lab/train_docker.csv)")
    ptr.add_argument("--model-dir", **common_model)
    ptr.add_argument("--test-size", type=float, default=0.3)
    ptr.add_argument("--n-estimators", type=int, default=100)
    ptr.add_argument("--max-rows", type=int, default=None,
                     help="optional cap on rows for a quick run")
    ptr.add_argument("--random-state", type=int, default=42)
    ptr.set_defaults(func=cmd_train)

    pev = sub.add_parser("evaluate", help="report the model's saved cross-validated metrics")
    pev.add_argument("--model-dir", **common_model)
    pev.add_argument("--out", default=None, help="write metrics JSON here")
    pev.set_defaults(func=cmd_evaluate)

    pst = sub.add_parser("stream", help="stream JSONL/CSV records through the detector")
    pst.add_argument("--input", default="-", help="JSONL file or '-' for stdin")
    pst.add_argument("--csv", default=None, help="CSV-replay file (overrides --input)")
    pst.add_argument("--model-dir", **common_model)
    pst.add_argument("--window", type=float, default=60.0)
    pst.add_argument("--ttl", type=float, default=600.0)
    pst.add_argument("--threshold", type=float, default=0.6)
    pst.add_argument("--all", action="store_true", help="emit every record's result")
    pst.set_defaults(func=cmd_stream)

    pde = sub.add_parser("demo", help="run built-in synthetic scenarios")
    pde.add_argument("--model-dir", **common_model)
    pde.add_argument("--window", type=float, default=60.0)
    pde.add_argument("--ttl", type=float, default=600.0)
    pde.set_defaults(func=cmd_demo)
    return p


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
