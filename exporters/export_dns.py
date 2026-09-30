"""DGA + DNS tunnelling -> unified alerts (dga-dns branch).

DGA: the branch's own LightGBM + lexical features are retrained with six well-known
malware families HELD OUT, then used to score those families' real DGArchive domains
(plus a benign Tranco sample). Every DGA alert therefore comes from a family the model never
saw in training -- the same honest-generalization test the deck reports.

Tunnelling: the branch's trained Isolation Forest scores its synthetic DNS windows."""
import sys

import joblib
import numpy as np
import pandas as pd

from common import SOURCES, make_alert, write

SRC = SOURCES / "dga-dns"
sys.path.insert(0, str(SRC))

import config  # noqa: E402
config.DATA_DIR = SRC / "data"
from src.features.lexical import lexical_features  # noqa: E402
from src.models.dga_lightgbm import FEATURE_COLS as DGA_COLS, train  # noqa: E402
from src.models.tunnelling_detector import FEATURE_COLS as TUN_COLS, score  # noqa: E402

HELD_OUT = ["qakbot", "emotet", "conficker", "locky", "cryptolocker", "gozi"]
PER_FAMILY = 8
BENIGN_SAMPLE = 400
THRESHOLD = 0.9   # strict operating point: few false alarms, as in the deck's results
DGA_EVIDENCE = ["length", "entropy", "digit_ratio", "ngram_score", "dict_word_ratio"]


def dga_alerts():
    df = pd.read_parquet(SRC / "data" / "dga_dataset.parquet")
    feats = pd.DataFrame(df["domain"].map(lexical_features).tolist())
    df = pd.concat([df.reset_index(drop=True), feats], axis=1)

    train_idx = df.index[~df["family"].isin(HELD_OUT)]
    model = train(df, train_idx)

    rng = np.random.default_rng(7)
    test = pd.concat(
        [df[df["family"] == f].sample(PER_FAMILY, random_state=int(rng.integers(1e6)))
         for f in HELD_OUT]
        + [df[df["family"] == "benign"].sample(BENIGN_SAMPLE, random_state=11)])
    probs = model.predict_proba(test[DGA_COLS])[:, 1]

    alerts, fp = [], 0
    for (_, row), p in zip(test.iterrows(), probs):
        if p < THRESHOLD:
            continue
        is_benign = row["family"] == "benign"
        fp += is_benign
        ev = [{"feature": c, "value": round(float(row[c]), 3)} for c in DGA_EVIDENCE]
        ev.append({"feature": "ground_truth",
                   "value": "benign (false positive)" if is_benign
                   else f"{row['family']} — family unseen in training"})
        alerts.append(make_alert(
            detector="dga_lightgbm", threat="dga", confidence=float(p), captured_ts=None,
            evidence=ev, dataset="DGArchive + Tranco top-1M (held-out families)", kind="real",
            entity=row["domain"], summary=f"Algorithmically generated domain: {row['domain']}"))
    caught = sum(1 for a in alerts if "unseen" in a["evidence"][-1]["value"])
    print(f"  DGA held-out: {caught}/{PER_FAMILY * len(HELD_OUT)} unseen-family domains flagged, "
          f"{fp}/{BENIGN_SAMPLE} benign false positives")
    return alerts


def tunnel_alerts():
    model = joblib.load(SRC / "data" / "models" / "tunnelling_isolation_forest.pkl")
    win = pd.read_parquet(SRC / "data" / "tunnelling_windows.parquet").reset_index(drop=True)
    s, flagged = score(model, win)
    s = np.asarray(s)
    lo, hi = np.percentile(s, 1), np.percentile(s, 99.5)
    alerts = []
    for i in np.where(flagged)[0]:
        row = win.iloc[i]
        ev = [{"feature": c, "value": round(float(row[c]), 3)} for c in TUN_COLS]
        ev.append({"feature": "ground_truth", "value": row["label"]})
        alerts.append(make_alert(
            detector="dns_tunnel_iforest", threat="dns_tunnelling",
            confidence=float(np.clip((s[i] - lo) / (hi - lo), 0, 1)), captured_ts=None,
            evidence=ev, dataset="Synthetic DNS query windows", kind="synthetic",
            entity=f"DNS window #{i}",
            summary=f"{int(row['unique_subdomains'])} unique subdomains, "
                    f"avg query length {row['avg_query_len']:.0f}"))
    print(f"  tunnelling: {len(alerts)} windows flagged "
          f"({sum(a['evidence'][-1]['value'] == 'tunnel' for a in alerts)} true tunnel)")
    return alerts


def main():
    write("dga", dga_alerts())
    write("dns_tunnelling", tunnel_alerts())


if __name__ == "__main__":
    main()
