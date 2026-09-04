"""End-to-end prototype run (CLAUDE.md build order, condensed into one demo).

Pipeline:
  1. Generate a labelled synthetic dataset (families + benign, grouped by capture file).
  2. Featurize every session (SPLT + JA4 + certificate).
  3. Train the LightGBM baseline and evaluate under TWO protocols, side by side:
       - random split BY CAPTURE FILE           (the optimistic number)
       - LEAVE-ONE-FAMILY-OUT                    (the HEADLINE number)
     Report TPR@0.1%FPR, precision/recall/F1, alerts/hr — never accuracy alone.
  4. Train the 1D-CNN on SPLT sequences; fuse with the baseline (score averaging).
  5. Ablation: shape-only vs handshake-only vs combined.
  6. Feature sanity check (rule 6) + family-availability report (§3).
  7. Streaming: emit schema-conformant alerts and measure p99 latency.

Run:  python scripts/run_prototype.py
"""
from __future__ import annotations

import asyncio
import sys
import warnings
from pathlib import Path

import numpy as np

# Quiet third-party chatter (sklearn feature-name notice, shap output-shape notice) so the
# report table is readable. Our own code is warning-free.
warnings.filterwarnings("ignore", category=UserWarning)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from encdetect.data_gen.synthetic import generate_dataset, MALWARE_FAMILIES  # noqa: E402
from encdetect.features.session import featurize  # noqa: E402
from encdetect.models.baseline_lgbm import LgbmBaseline  # noqa: E402
from encdetect.models import fusion  # noqa: E402
from encdetect.eval import protocol, metrics  # noqa: E402
from encdetect.streaming.pipeline import run_pipeline  # noqa: E402


def _labels(bundles):
    return np.array([1 if b.label == "malicious" else 0 for b in bundles], dtype=int)


def _duration_hours(bundles):
    # treat the dataset as one capture hour per ~1000 sessions for alerts/hr scaling
    return max(1.0, len(bundles) / 1000.0)


def banner(text):
    print("\n" + "=" * 78)
    print(text)
    print("=" * 78)


def run():
    banner("1-2. Generate + featurize synthetic dataset (PROTOTYPE DATA)")
    sessions = generate_dataset(n_benign=1500, n_per_family=200, seed=42)
    bundles = [featurize(s) for s in sessions]
    y = _labels(bundles)
    print(f"  sessions: {len(bundles)}  |  malicious: {int(y.sum())}  "
          f"benign: {int((1 - y).sum())}  |  families: {', '.join(MALWARE_FAMILIES)}")

    # family availability (§3: report the fraction each family was observable)
    avail = {k: np.mean([b.availability[k] for b in bundles])
             for k in ("shape", "handshake", "certificate")}
    print("  feature-family availability: "
          + ", ".join(f"{k}={v:.0%}" for k, v in avail.items()))

    rows = []

    banner("3a. Baseline — random split BY CAPTURE FILE (optimistic)")
    tr, te = protocol.split_by_capture_file(bundles, test_fraction=0.3, seed=7)
    model = LgbmBaseline().fit(tr)
    score = model.predict_proba(te)
    row = metrics.evaluate(_labels(te), score, "random-by-capture", _duration_hours(te))
    rows.append(row)
    print("  " + metrics.ExperimentRow.HEADER)
    print("  " + row.format_row())

    banner("3b. Baseline — LEAVE-ONE-FAMILY-OUT (the headline number)")
    print("  " + metrics.ExperimentRow.HEADER)
    lofo_tprs = []
    for train, test, held in protocol.leave_one_family_out(bundles):
        m = LgbmBaseline().fit(train)
        s = m.predict_proba(test)
        r = metrics.evaluate(_labels(test), s, f"LOFO:{held}", _duration_hours(test))
        lofo_tprs.append(r.tpr_at_0p1_fpr)
        print("  " + r.format_row())
    lofo_mean = float(np.mean(lofo_tprs)) if lofo_tprs else 0.0
    print(f"\n  mean TPR@0.1%FPR across held-out families: {lofo_mean:.4f}")
    print(f"  random-split TPR@0.1%FPR:                   {row.tpr_at_0p1_fpr:.4f}")
    print("  --> the GAP between these two is itself the finding (CLAUDE.md §7).")

    banner("4. Sequence model (1D-CNN) + fusion")
    try:
        from encdetect.models.sequence_cnn import SequenceCNN
        seq_tr = [b.sequence for b in tr]
        seq_te = [b.sequence for b in te]
        cnn = SequenceCNN(n_packets=len(tr[0].sequence), epochs=12).fit(seq_tr, _labels(tr))
        cnn_score = cnn.predict_proba(seq_te)
        cnn_row = metrics.evaluate(_labels(te), cnn_score, "cnn-by-capture", _duration_hours(te))
        fused = fusion.average_scores(score, cnn_score, weight=0.6)
        fused_row = metrics.evaluate(_labels(te), fused, "fusion-by-capture", _duration_hours(te))
        print("  " + metrics.ExperimentRow.HEADER)
        print("  " + cnn_row.format_row())
        print("  " + fused_row.format_row())
    except Exception as e:  # torch missing or other issue — baseline still stands
        print(f"  (skipped CNN/fusion: {e})")

    banner("5. Ablation — which feature family carries the signal")
    print("  " + metrics.ExperimentRow.HEADER)
    for name, keep in (("shape-only", "shape"), ("handshake-only", "handshake"),
                       ("combined", None)):
        tr_a = [_mask_bundle(b, keep) for b in tr]
        te_a = [_mask_bundle(b, keep) for b in te]
        m = LgbmBaseline().fit(tr_a)
        s = m.predict_proba(te_a)
        r = metrics.evaluate(_labels(te_a), s, name, _duration_hours(te_a))
        print("  " + r.format_row())

    banner("6. Feature sanity check (rule 6 — hunt for environment artifacts)")
    imp = np.asarray(model.model.feature_importances_, dtype=float)
    order = np.argsort(imp)[::-1][:8]
    for i in order:
        print(f"  {model.feature_names[i]:<22} importance={imp[i]:.0f}")
    print("  --> confirm none of these are capture-environment tells (TTL, timestamps, a")
    print("      single-capture cipher). Shape/timing + JA4 encodings ranking high is healthy.")

    banner("7. Streaming — schema-conformant alerts + p99 latency")
    # Fresh hold-out stream (different seed): the pipeline featurizes and scores each session
    # incrementally, exactly as it would from the live Zeek reader.
    _, threshold = metrics.tpr_at_fixed_fpr(_labels(te), score, fpr=0.001)
    stream_sessions = generate_dataset(n_benign=500, n_per_family=60, seed=99)
    emitted = []
    result = asyncio.run(run_pipeline(stream_sessions, model, threshold,
                                      on_alert=emitted.append))
    print(f"  scored {result.n_sessions} sessions, emitted {len(result.alerts)} alerts "
          f"(threshold={threshold:.4f})")
    print(f"  p99 per-session scoring latency: {result.p99_latency_s()*1000:.2f} ms "
          f"(target end-to-end < 30 s)")
    if emitted:
        import json
        top = max(emitted, key=lambda a: a["confidence"])
        print("\n  highest-confidence alert:")
        print("  " + json.dumps(top, indent=2).replace("\n", "\n  "))

    banner("DONE — prototype ran end to end.")
    print("  Headline (leave-one-family-out) TPR@0.1%FPR = "
          f"{lofo_mean:.4f}; report this, not the random split.")


def _mask_bundle(bundle, keep):
    """Return a shallow copy of the bundle with only the kept family's features active."""
    from copy import copy
    b = copy(bundle)
    if keep == "shape":
        b.ja4 = ""  # drop handshake fingerprint
        b.tabular = {k: (0.0 if k.startswith("ja4_") or k in _CERT_KEYS else v)
                     for k, v in bundle.tabular.items()}
    elif keep == "handshake":
        b.tabular = {k: (v if k.startswith("ja4_") else 0.0)
                     for k, v in bundle.tabular.items()}
    return b


_CERT_KEYS = {"cert_features_available", "self_signed", "validity_days",
              "subject_cn_entropy", "san_count", "sni_subject_mismatch", "key_size"}


if __name__ == "__main__":
    run()
