"""Botnet C2 beaconing -> unified alerts (botnet-c2 branch).

Runs the branch's real pipeline end to end (preprocess -> 15-min sliding windows ->
beacon features -> scenario-disjoint split -> LogisticRegression) on its DEMO data
generator. The data is synthetic and labelled as such in the dashboard; real CTU-13
validation replaces it once re-sourced. Alerts are the test-scenario windows the model
scores above threshold, one per conversation."""
import sys

from common import SOURCES, make_alert, write

SRC = SOURCES / "botnet-c2"
sys.path.insert(0, str(SRC))

import preprocessing  # noqa: E402
from config import SPLIT_CFG, WindowConfig  # noqa: E402
from dataset_builder import build_window_dataset  # noqa: E402
from demo_data import generate_demo_dataset  # noqa: E402
from splitting import scenario_split  # noqa: E402
from train import predict_proba, train_logistic_regression  # noqa: E402

THRESHOLD = 0.5
EVIDENCE = {"inter_arrival_cov": "Beacon interval variation (CoV)",
            "autocorr_peak_strength": "Periodicity strength",
            "inter_arrival_median": "Median beacon interval (s)",
            "missed_beacon_ratio": "Missed-beacon ratio",
            "host_top_dest_share": "Share to top destination"}


def main():
    windows = build_window_dataset(preprocessing.preprocess(generate_demo_dataset()),
                                   WindowConfig())
    train_df, val_df, test_df = scenario_split(windows, SPLIT_CFG)
    model = train_logistic_regression(train_df)
    test = test_df[test_df["label"].isin(["positive", "negative"])].copy()
    test["p"] = predict_proba(model, test)

    alerts, seen = [], set()
    for _, row in test[test["p"] >= THRESHOLD].sort_values("window_start").iterrows():
        scen, src, dst, port, proto = row["conv_key"]
        if (src, dst, port) in seen:
            continue
        seen.add((src, dst, port))
        ev = [{"feature": v, "value": round(float(row[k]), 3)} for k, v in EVIDENCE.items()]
        ev.append({"feature": "ground_truth", "value": "beacon" if row["label"] == "positive"
                   else "benign periodic (false positive)"})
        alerts.append(make_alert(
            detector="botnet_c2_logreg", threat="botnet_c2", confidence=float(row["p"]),
            captured_ts=None, evidence=ev,
            dataset=f"Synthetic CTU-13-style scenario ({scen}), unseen in training",
            kind="synthetic", src_ip=src, dst_ip=dst, dst_port=int(port), proto=proto,
            entity=f"{src} → {dst}:{port}",
            summary=f"Periodic beacon every ~{row['inter_arrival_median']:.0f}s "
                    f"to {dst}:{port} (CoV {row['inter_arrival_cov']:.2f})"))
    write("botnet_c2", alerts)


if __name__ == "__main__":
    main()
