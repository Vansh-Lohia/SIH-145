"""Malware in encrypted sessions -> unified alerts (encrypted-malware detector).

Runs leave-one-family-out over the real captures: every alert for a malware family is
produced by a model that NEVER saw that family in training. Alerts fire above each fold's
0.1%-false-positive-rate threshold, exactly as reported in the deck. Confidence is the
session's rank against held-out benign traffic ("scored above X% of benign sessions"),
because the raw LightGBM probabilities are uncalibrated. Evidence lists only the SHAP
contributions that pushed the verdict TOWARD malicious.

Needs the local encrypted-session-detector checkout with its (git-ignored) Zeek logs:
  ENCDETECT_REPO=/path/to/encrypted-session-detector python3 export_encrypted.py
"""
import os
import sys
import warnings
from pathlib import Path

import numpy as np

from common import make_alert, write

warnings.filterwarnings("ignore")
REPO = Path(os.environ.get("ENCDETECT_REPO",
                           "/mnt/c/Users/aryan/encrypted-session-detector"))
sys.path.insert(0, str(REPO / "src"))

import shap  # noqa: E402
from encdetect.eval import metrics, protocol  # noqa: E402
from encdetect.features.session import featurize  # noqa: E402
from encdetect.ingest.zeek_reader import sessions_from_log_dir  # noqa: E402
from encdetect.labels import apply_labels, load_labels  # noqa: E402
from encdetect.models.baseline_lgbm import LgbmBaseline  # noqa: E402

PER_FAMILY = 12
READABLE = {
    "ja4_cipher_count": "TLS cipher-suite count", "ja4_ext_count": "TLS extension count",
    "ja4_sni_present": "SNI present", "ja4_target_enc": "Fingerprint (JA4) history",
    "size_mean": "Mean packet size (B)", "size_max": "Max packet size (B)",
    "size_std": "Packet size spread", "iat_mean": "Mean inter-arrival (ms)",
    "iat_std": "Inter-arrival spread (ms)", "iat_max": "Max inter-arrival (ms)",
    "updown_byte_ratio": "Upload / download bytes", "burst_count": "Burst count",
    "duration_ms": "Session duration (ms)", "total_bytes": "Total bytes",
    "down_pkt_count": "Server packets", "up_pkt_count": "Client packets",
    "idle_gap_count": "Idle gaps", "self_signed": "Self-signed certificate",
    "validity_days": "Certificate validity (days)",
}


def load():
    pairs = []
    for d in sorted((REPO / "data" / "zeek_logs").iterdir()):
        lab = REPO / "data" / "labels" / f"{d.name}.jsonl"
        if not d.is_dir() or not lab.exists():
            continue
        sessions = sessions_from_log_dir(d, pcap=d.name)
        apply_labels(sessions, load_labels(lab))
        pairs += [(s, featurize(s)) for s in sessions if s.label]
    return pairs


def main():
    pairs = load()
    by_id = {id(b): s for s, b in pairs}
    bundles = [b for _, b in pairs]
    alerts = []
    rng = np.random.default_rng(3)
    for train, test, held in protocol.leave_one_family_out(bundles):
        model = LgbmBaseline().fit(train)
        y = np.array([b.label == "malicious" for b in test], dtype=int)
        scores = model.predict_proba(test)
        _, thr = metrics.tpr_at_fixed_fpr(y, scores, 0.001)
        benign_scores = np.sort(scores[y == 0])
        explainer = shap.TreeExplainer(model.model)

        idx = np.where(scores > thr)[0]
        mal = [i for i in idx if y[i] == 1]
        fps = [i for i in idx if y[i] == 0]
        chosen = list(rng.choice(mal, min(PER_FAMILY, len(mal)), replace=False)) + fps
        for i in chosen:
            b, s = test[i], by_id[id(test[i])]
            enc = model.encoder.transform([b.ja4])
            X = model._matrix([b], enc)
            sv = explainer.shap_values(X)
            v = sv[1][0] if isinstance(sv, list) else np.asarray(sv)[0]
            raw = {**b.tabular, "ja4_target_enc": float(enc[0])}
            top = sorted([(n, c) for n, c in zip(model.feature_names, v) if c > 0],
                         key=lambda t: -t[1])[:4]
            ev = [{"feature": READABLE.get(n, n), "value": round(float(raw.get(n, 0)), 2),
                   "contribution": round(float(c), 4)} for n, c in top]
            ev.append({"feature": "JA4", "value": b.ja4 or "(not computable)"})
            ev.append({"feature": "ground_truth",
                       "value": f"{held} — family unseen in training" if y[i]
                       else "benign (false positive)"})
            pct = float(np.searchsorted(benign_scores, scores[i]) / len(benign_scores))
            alerts.append(make_alert(
                detector="encrypted_session_v1", threat="encrypted_malware", confidence=pct,
                captured_ts=s.start_ts or None, evidence=ev,
                dataset=("malware-traffic-analysis.net (2025)" if "2025" in s.pcap
                         else "Stratosphere CTU malware capture") if y[i]
                else f"Benign capture: {s.pcap}",
                kind="real", src_ip=s.flow.src_ip, src_port=s.flow.src_port,
                dst_ip=s.flow.dst_ip, dst_port=s.flow.dst_port, proto=s.flow.proto,
                entity=f"{s.flow.dst_ip}:{s.flow.dst_port}",
                summary=f"{s.tls_version_str} session to {s.flow.dst_ip}:{s.flow.dst_port} "
                        f"ranked above {pct:.1%} of benign traffic"))
        print(f"  {held:>14}: {len(mal)} flagged of {int(y.sum())}, {len(fps)} benign FPs "
              f"-> {len(chosen)} alerts")
    write("encrypted_malware", alerts)


if __name__ == "__main__":
    main()
