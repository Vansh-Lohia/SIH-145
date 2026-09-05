#!/usr/bin/env python3
"""Simulate a live one-way network stream with blind accuracy verification.

The simulator streams records one-by-one through the ReconDetector.
The model receives ONLY the network features (timestamps, IPs, ports, flow features).
Ground truth labels (BENIGN vs PortScan, and the 4 scan types) are HIDDEN from the detector
during inference and used strictly by the verification harness to evaluate detection accuracy.

Outputs:
  - Real-time stream processing progress and alert notifications
  - Overall accuracy, precision, recall, and F1-score
  - Per-category breakdown (Benign FPR, Vertical Detection Rate, Horizontal Detection Rate,
    Slow Scan Detection Rate, Mixed Scan Detection Rate)
  - Taxonomic scan-type alignment
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from recon_detector.detector import DetectorConfig, ReconDetector
from recon_detector.schemas import DetectionResult, FlowRecord


def run_stream_simulation(
    csv_path: str,
    model_dir: str = "models_docker",
    delay_ms: float = 0.0,
    show_alerts: bool = True,
) -> Dict:
    detector = ReconDetector.from_model_dir(model_dir)

    print(f"[*] Loading stream records from: {csv_path}")
    records: List[Dict] = []
    with open(csv_path, newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            records.append(row)

    total_records = len(records)
    print(f"[*] Total records in live stream: {total_records}")
    print(f"[*] Loaded detector from: {model_dir}")
    print("=" * 70)
    print(" STREAMING STARTED (Ground truth hidden from detector)")
    print("=" * 70)

    # Tracking metrics
    # Confusion matrix components:
    # TP: True scan detected as scan
    # FP: Benign falsely detected as scan
    # TN: Benign correctly not detected
    # FN: True scan missed
    tp = 0
    fp = 0
    tn = 0
    fn = 0

    category_counts = {
        "benign": 0,
        "vertical": 0,
        "horizontal": 0,
        "slow": 0,
        "mixed": 0,
    }
    category_detected = {
        "benign": 0,  # False positives
        "vertical": 0,
        "horizontal": 0,
        "slow": 0,
        "mixed": 0,
    }

    start_wall = time.time()
    last_expire = None

    for i, row in enumerate(records, 1):
        # Extract ground truth (hidden from detector)
        true_label = row.get("Label", "BENIGN")
        true_scan_type = row.get("Scan_Type", "benign").lower()
        category_counts[true_scan_type] = category_counts.get(true_scan_type, 0) + 1

        # Strip ground truth before feeding into the detector
        input_record = {
            "timestamp": float(row["timestamp"]),
            "src_ip": row["src_ip"],
            "dst_ip": row["dst_ip"],
            "dst_port": int(row["dst_port"]),
            "protocol": row.get("protocol", "TCP"),
            "packet_count": float(row.get("Total Fwd Packets", 1.0)),
            "byte_count": float(row.get("Total Length of Fwd Packets", 0.0)),
            "flow_duration": float(row.get("Fwd IAT Total", 0.0)),
            "features": {k: float(row[k]) for k in row if k not in ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "Label", "Scan_Type"]},
        }

        # Inference: The detector processes the record blindly
        res: DetectionResult = detector.process(input_record)

        # Periodic TTL expiration
        if last_expire is None:
            last_expire = res.timestamp
        if res.timestamp - last_expire > detector.config.state_ttl:
            detector.expire_state(res.timestamp)
            last_expire = res.timestamp

        # Evaluate detection against ground truth
        is_scan = (true_label.lower() in ["portscan", "scan"])

        if res.detected:
            if is_scan:
                tp += 1
                category_detected[true_scan_type] += 1
            else:
                fp += 1
                category_detected["benign"] += 1
            
            if show_alerts and (fp <= 10 or tp <= 25 or i % 500 == 0):
                status_icon = "⚠️  [ALERT]" if is_scan else "❌ [FALSE ALARM]"
                print(f"{status_icon} flow={i:5d}/{total_records} | src={res.source:<15s} | "
                      f"score={res.score:.4f} | type={res.scan_type.upper():<10s} | "
                      f"(True: {true_scan_type.upper()})")
        else:
            if is_scan:
                fn += 1
            else:
                tn += 1

        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)

    elapsed = time.time() - start_wall
    fps = total_records / elapsed if elapsed > 0 else 0.0

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total_records if total_records > 0 else 0.0

    print("\n" + "=" * 70)
    print(" LIVE STREAM VERIFICATION REPORT")
    print("=" * 70)
    print(f"Processed Flows:   {total_records} in {elapsed:.2f}s ({fps:,.0f} flows/sec)")
    print(f"Active Sources:    {detector.active_sources}")
    print("-" * 70)
    print("1. OVERALL ACCURACY METRICS:")
    print(f"   Accuracy:       {accuracy * 100:6.2f}%")
    print(f"   Precision:      {precision * 100:6.2f}%")
    print(f"   Recall:         {recall * 100:6.2f}%")
    print(f"   F1-Score:       {f1:8.4f}")
    print("-" * 70)
    print("2. CONFUSION MATRIX:")
    print(f"   True Positives (Scans Detected):      {tp:5d}")
    print(f"   True Negatives (Benign Allowed):      {tn:5d}")
    print(f"   False Positives (Benign Flagged):     {fp:5d}")
    print(f"   False Negatives (Scans Missed):       {fn:5d}")
    print("-" * 70)
    print("3. DETAILED DETECTION BREAKDOWN BY SCAN TYPE:")
    for cat in ["vertical", "horizontal", "slow", "mixed"]:
        total_cat = category_counts[cat]
        det_cat = category_detected[cat]
        rate = (det_cat / total_cat * 100) if total_cat > 0 else 0.0
        print(f"   - {cat.capitalize():12s} Scans: {det_cat:5d} / {total_cat:5d} detected ({rate:6.2f}%)")

    b_total = category_counts["benign"]
    b_fp = category_detected["benign"]
    fpr = (b_fp / b_total * 100) if b_total > 0 else 0.0
    print(f"   - Benign Traffic:      {b_total - b_fp:5d} / {b_total:5d} passed without alarm (FPR: {fpr:4.2f}%)")
    print("=" * 70)

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "category_counts": category_counts,
        "category_detected": category_detected,
    }


def main():
    parser = argparse.ArgumentParser(description="Simulate live streaming traffic with blind accuracy testing")
    parser.add_argument("--csv", default="portscan-lab/eval_docker.csv",
                        help="CSV stream file to replay (real Docker-captured eval batch)")
    parser.add_argument("--model-dir", default="models_docker",
                        help="Path to trained model artifact directory")
    parser.add_argument("--delay-ms", type=float, default=0.0, help="Artificial delay in milliseconds per packet")
    parser.add_argument("--quiet", action="store_true", help="Do not print individual alert lines")
    args = parser.parse_args()

    run_stream_simulation(
        csv_path=args.csv,
        model_dir=args.model_dir,
        delay_ms=args.delay_ms,
        show_alerts=not args.quiet,
    )


if __name__ == "__main__":
    main()

