"""
Cold-path fusion layer combining Branch A (SYN), Branch B (UDP
reflection), and Branch C (generic volumetric/spoofed) into one overall
confidence + subtype attribution.

Trained on SYNTHETIC co-occurrence scenarios (real simultaneous
multi-branch attack data doesn't exist yet -- captures were taken
independently). Labeling rule, matching the design doc:
  - any single branch strongly elevated (>0.8) -> real attack on its own
  - two or more branches moderately elevated (>0.4) together -> coordinated attack
  - otherwise -> not flagged
Verified in test_fusion_3branch.py before this was written.
"""
import numpy as np
import xgboost as xgb
import json
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix 

def evaluate_fusion_model():
    """
    Train/test split evaluation -- the model never sees the test labels
    during training. IMPORTANT: both train and test labels come from the
    same hand-written label_row() rule, so this measures 'did the model
    learn the rule correctly,' NOT 'does the rule match real attacks.'
    """
    X, y = build_training_data()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=1)

    model = xgb.XGBClassifier(n_estimators=80, max_depth=3,
                               eval_metric="logloss", random_state=0)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    metrics = {
        "test_set_size": len(y_test),
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall": round(recall_score(y_test, y_pred), 4),
        "f1_score": round(f1_score(y_test, y_pred), 4),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
    }
    return metrics, model

def build_training_data(rng_seed=7, n=3000):
    rng = np.random.default_rng(rng_seed)

    def make_row(syn, udp, gen):
        syn_rate = syn * rng.uniform(800, 1500)
        udp_orphan = 0.9 if udp > 0.3 else 0.1
        gen_fanin = gen * rng.uniform(30000, 45000)
        return [syn, udp, gen, syn_rate, udp_orphan, gen_fanin]

    def label_row(syn, udp, gen):
        strong_any = max(syn, udp, gen) > 0.8
        moderate_count = sum(1 for v in (syn, udp, gen) if v > 0.4)
        return 1 if (strong_any or moderate_count >= 2) else 0

    X, y = [], []
    for _ in range(n):
        syn, udp, gen = rng.uniform(0, 1, 3)
        X.append(make_row(syn, udp, gen))
        y.append(label_row(syn, udp, gen))
    return np.array(X), np.array(y)


def train_fusion_model():
    X, y = build_training_data()
    model = xgb.XGBClassifier(n_estimators=80, max_depth=3,
                               eval_metric="logloss", random_state=0)
    model.fit(X, y)
    return model


def fuse(model, syn_conf, udp_conf, gen_conf, syn_rate=0.0, udp_orphan=0.0, gen_fanin=0.0):
    features = np.array([[syn_conf, udp_conf, gen_conf, syn_rate, udp_orphan, gen_fanin]])
    prob = model.predict_proba(features)[0][1]

    scores = {"syn_flood": syn_conf, "udp_reflection": udp_conf, "generic_volumetric": gen_conf}
    dominant = max(scores, key=scores.get)
    firing = [k for k, v in scores.items() if v > 0.4]

    if len(firing) >= 2:
        driver = f"multi_vector_coordinated ({' + '.join(firing)})"
    elif len(firing) == 1:
        driver = f"{firing[0]}_only"
    else:
        driver = "inconclusive"

    return {"fused_confidence": round(float(prob), 3), "subtype_attribution": driver}


def load_latest_confidence(alert_json_path):
    """Pull the highest confidence + its evidence from an alert file --
    i.e. 'what is this branch reporting right now / at its peak'."""
    with open(alert_json_path) as f:
        alerts = json.load(f)
    peak = max(alerts, key=lambda a: a["confidence"])
    return peak["confidence"], peak["evidence"]


if __name__ == "__main__":
    model = train_fusion_model()
    print("=== Fusion model evaluation (synthetic train/test split) ===")
    metrics, _ = evaluate_fusion_model()
    for k, v in metrics.items():
        print(f"  {k}: {v}")
    print("  CAVEAT: measures rule-learning fidelity on synthetic data,")
    print("  not real-world detection accuracy -- see report for details.\n")
    
    print("=== Synthetic design-check scenarios ===")
    print(fuse(model, 0.05, 0.05, 0.05))
    print(fuse(model, 0.9, 0.05, 0.05, syn_rate=1200))
    print(fuse(model, 0.5, 0.5, 0.05, syn_rate=900, udp_orphan=0.9))
    print(fuse(model, 0.5, 0.5, 0.5, syn_rate=900, udp_orphan=0.9, gen_fanin=40000))

    print("\n=== Applied to your REAL captured peak values ===")
    try:
        syn_conf, syn_ev = load_latest_confidence("alerts_output.json")
        udp_conf, udp_ev = load_latest_confidence("udp_alerts_output.json")
        gen_conf, gen_ev = load_latest_confidence("generic_alerts_output.json")

        result = fuse(
            model, syn_conf, udp_conf, gen_conf,
            syn_rate=syn_ev.get("packet_rate_per_sec", 0),
            udp_orphan=udp_ev.get("orphan_score", 0),
            gen_fanin=gen_ev.get("fan_in", 0),
        )
        print(f"Branch A peak confidence: {syn_conf}")
        print(f"Branch B peak confidence: {udp_conf}")
        print(f"Branch C peak confidence: {gen_conf}")
        print("Fused result:", result)
    except FileNotFoundError as e:
        print(f"(skipping real-data test -- file not found: {e})")