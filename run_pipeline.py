"""
run_pipeline.py
================
Orchestrates the full pipeline: data_loading -> preprocessing ->
dataset_builder (windowing + features + labeling) -> splitting ->
train -> evaluate.

Usage
-----
Real data (requires CTU-13 re-sourced with StartTime/SrcAddr/Sport/
DstAddr/Dport — see config.py docstring):

    python run_pipeline.py --data-dir /path/to/scenarios --pattern "*.parquet"

Demo / smoke-test mode (SYNTHETIC data, proves the pipeline runs
end-to-end; produces no scientifically valid numbers — see
demo_data.py):

    python run_pipeline.py --demo

Optional:
    --window-seconds 900
    --step-seconds 180
    --min-flows 3
    --threshold 0.5
    --output-dir ./run_outputs
"""

from __future__ import annotations
import argparse
import os
import json

import pandas as pd

from config import WindowConfig, SPLIT_CFG
import data_loading
import preprocessing
from dataset_builder import build_window_dataset
from splitting import scenario_split, report_split_sizes
from train import train_logistic_regression
from evaluate import evaluate, score_stress_bucket, print_eval_result, \
    latency_report, print_latency_report


def parse_args():
    p = argparse.ArgumentParser(description="C2 beaconing detection baseline pipeline")
    p.add_argument("--data-dir", type=str, default=None,
                    help="Directory containing per-scenario CTU-13 files "
                         "(requires StartTime/SrcAddr/Sport/DstAddr/Dport)")
    p.add_argument("--pattern", type=str, default="*.parquet",
                    help="Glob pattern for scenario files, e.g. '*.parquet' or '*.binetflow.csv'")
    p.add_argument("--demo", action="store_true",
                    help="Use synthetic demo data instead of --data-dir "
                         "(smoke test only, not a real result)")
    p.add_argument("--window-seconds", type=int, default=900)
    p.add_argument("--step-seconds", type=int, default=180)
    p.add_argument("--min-flows", type=int, default=3)
    p.add_argument("--threshold", type=float, default=0.5)
    p.add_argument("--output-dir", type=str, default="./run_outputs")
    return p.parse_args()


def main():
    args = parse_args()
    os.makedirs(args.output_dir, exist_ok=True)

    # ---- 1. data loading ----
    if args.demo:
        print("[run_pipeline] DEMO MODE — using synthetic data. This proves "
              "the pipeline runs end-to-end; it is NOT a scientific result. "
              "See demo_data.py.")
        from demo_data import generate_demo_dataset
        raw_df = generate_demo_dataset()
    else:
        if not args.data_dir:
            raise SystemExit("Provide --data-dir (real data) or --demo (smoke test).")
        raw_df = data_loading.load_scenarios(args.data_dir, pattern=args.pattern)
    print(f"[run_pipeline] loaded {len(raw_df)} raw flow rows")

    # ---- 2. preprocessing ----
    clean_df = preprocessing.preprocess(raw_df)
    print(f"[run_pipeline] {len(clean_df)} flows after preprocessing "
          f"(dropped {len(raw_df) - len(clean_df)} with unparseable timestamps)")
    print("[run_pipeline] label_bucket counts:",
          clean_df["label_bucket"].value_counts().to_dict())

    # ---- 3. window generation + feature engineering + labeling ----
    cfg = WindowConfig(window_seconds=args.window_seconds,
                        step_seconds=args.step_seconds,
                        min_flows_for_prediction=args.min_flows)
    window_df = build_window_dataset(clean_df, cfg)
    print(f"[run_pipeline] generated {len(window_df)} windows; "
          f"label counts = {window_df['label'].value_counts().to_dict() if len(window_df) else {}}")

    if window_df.empty:
        raise SystemExit("No windows generated — check window config / min_flows "
                          "against your data's flow density.")

    # ---- 4. scenario-based split ----
    train_df, val_df, test_df = scenario_split(window_df, SPLIT_CFG)
    report_split_sizes(train_df, val_df, test_df)

    # ---- 5. model training ----
    trained = train_logistic_regression(train_df)
    print("[run_pipeline] trained LogisticRegression "
          f"(coefficients for {len(trained.feature_names)} features)")

    # ---- 6. evaluation ----
    results = {}
    for name, part in [("validation", val_df), ("test", test_df)]:
        confirmed = part[part["label"].isin(["positive", "negative"])]
        if confirmed.empty:
            print(f"\n[run_pipeline] {name}: no confirmed positive/negative "
                  f"windows to evaluate — skipping.")
            continue
        res = evaluate(trained, confirmed, threshold=args.threshold)
        print_eval_result(name, res)
        results[name] = res.as_dict()

        stress = score_stress_bucket(trained, part, threshold=args.threshold)
        print(f"  [{name}] stress-bucket (excluded/ambiguous windows): "
              f"n={stress['n_windows']}, flagged_rate="
              f"{stress['flagged_rate']:.4f}" if stress['n_windows'] else
              f"  [{name}] stress-bucket: no excluded windows present")
        results[f"{name}_stress"] = stress

    lat = latency_report(cfg, window_df)
    print_latency_report(lat)
    results["latency"] = lat

    out_path = os.path.join(args.output_dir, "results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n[run_pipeline] results written to {out_path}")


if __name__ == "__main__":
    main()
