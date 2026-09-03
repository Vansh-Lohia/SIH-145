"""Build a labelled feature dataset from one or more Zeek captures (CLAUDE.md §8, §9 step 2).

Each capture is a directory of Zeek logs plus a labels.jsonl sidecar. Sessions from one
capture share that capture's name as their `pcap` group, so the evaluation splitters never
mix a capture across train/test (rule 1).

Modes:
  --scan            pair every data/zeek_logs/<name>/ with data/labels/<name>.jsonl
  --manifest FILE   JSON: {"captures":[{"name","log_dir","labels","default_label"?}, ...]}

Outputs data/features/dataset.jsonl (one featurized session per line) and prints the
label/family distribution and feature-family availability. With --eval it trains the
LightGBM baseline under leave-one-family-out and prints the honest report — but only if the
real data actually has >=2 malicious families and some benign sessions.

Examples:
  python scripts/build_dataset.py --scan --eval
  python scripts/build_dataset.py --manifest data/manifest.json --eval
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from encdetect.ingest.zeek_reader import sessions_from_log_dir  # noqa: E402
from encdetect.labels import load_labels, apply_labels  # noqa: E402
from encdetect.features.session import featurize, FeatureBundle  # noqa: E402


def _load_capture(name: str, log_dir: Path, labels_path: Path | None,
                  default_label: str) -> list:
    sessions = sessions_from_log_dir(log_dir, pcap=name)
    if labels_path and labels_path.exists():
        apply_labels(sessions, load_labels(labels_path), default_label=default_label)
    elif default_label:
        for s in sessions:
            s.label = default_label
    return sessions


def _captures_from_scan() -> list[tuple[str, Path, Path | None, str]]:
    out = []
    zlogs = ROOT / "data" / "zeek_logs"
    for d in sorted(p for p in zlogs.glob("*") if p.is_dir()):
        labels = ROOT / "data" / "labels" / f"{d.name}.jsonl"
        out.append((d.name, d, labels if labels.exists() else None, ""))
    return out


def _captures_from_manifest(path: Path) -> list[tuple[str, Path, Path | None, str]]:
    spec = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for c in spec["captures"]:
        name = c["name"]
        log_dir = (ROOT / c["log_dir"]) if not Path(c["log_dir"]).is_absolute() \
            else Path(c["log_dir"])
        labels = c.get("labels")
        labels_path = ((ROOT / labels) if labels and not Path(labels).is_absolute()
                       else (Path(labels) if labels else None))
        out.append((name, log_dir, labels_path, c.get("default_label", "")))
    return out


def _bundle_to_row(b: FeatureBundle) -> dict:
    return {"label": b.label, "family": b.family, "environment": b.environment,
            "pcap": b.pcap, "ja4": b.ja4, "availability": b.availability,
            "tabular": b.tabular}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan", action="store_true")
    ap.add_argument("--manifest")
    ap.add_argument("--out", default="data/features/dataset.jsonl")
    ap.add_argument("--eval", action="store_true")
    args = ap.parse_args()

    if args.manifest:
        captures = _captures_from_manifest(Path(args.manifest))
    elif args.scan:
        captures = _captures_from_scan()
    else:
        ap.error("provide --scan or --manifest")

    if not captures:
        print("No captures found. Put Zeek logs under data/zeek_logs/<name>/ "
              "and labels under data/labels/<name>.jsonl.")
        return

    all_bundles: list[FeatureBundle] = []
    for name, log_dir, labels_path, default_label in captures:
        if not log_dir.exists():
            print(f"  skip {name}: {log_dir} missing")
            continue
        sessions = _load_capture(name, log_dir, labels_path, default_label)
        bundles = [featurize(s) for s in sessions]
        all_bundles.extend(bundles)
        lab = Counter(b.label or "unlabeled" for b in bundles)
        print(f"  {name}: {len(bundles)} sessions  {dict(lab)}")

    out_path = ROOT / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for b in all_bundles:
            fh.write(json.dumps(_bundle_to_row(b)) + "\n")

    print("=" * 72)
    print(f"total sessions: {len(all_bundles)}  ->  {out_path}")
    print("labels:", dict(Counter(b.label or 'unlabeled' for b in all_bundles)))
    print("families:", dict(Counter(b.family for b in all_bundles if b.family)))
    fams = ("shape", "handshake", "certificate")
    if all_bundles:
        avail = {k: sum(b.availability[k] for b in all_bundles) / len(all_bundles)
                 for k in fams}
        print("availability:", ", ".join(f"{k}={v:.0%}" for k, v in avail.items()))

    if args.eval:
        _run_eval(all_bundles)


def _run_eval(bundles: list[FeatureBundle]) -> None:
    import numpy as np
    from encdetect.models.baseline_lgbm import LgbmBaseline
    from encdetect.eval import protocol, metrics

    mal_families = {b.family for b in bundles if b.label == "malicious" and b.family}
    n_benign = sum(b.label == "benign" for b in bundles)
    print("\n" + "=" * 72)
    if len(mal_families) < 2 or n_benign == 0:
        print("Not enough real data for leave-one-family-out yet "
              f"(malicious families={len(mal_families)}, benign={n_benign}).")
        print("Need >=2 malicious families AND some benign sessions. Add more captures.")
        return

    def y(bs):
        return np.array([1 if b.label == "malicious" else 0 for b in bs], dtype=int)

    dur = max(1.0, len(bundles) / 1000.0)
    print("REAL-DATA evaluation (CLAUDE.md §7)")
    print("  " + metrics.ExperimentRow.HEADER)
    tprs = []
    for train, test, held in protocol.leave_one_family_out(bundles):
        m = LgbmBaseline().fit(train)
        s = m.predict_proba(test)
        r = metrics.evaluate(y(test), s, f"LOFO:{held}", dur)
        tprs.append(r.tpr_at_0p1_fpr)
        print("  " + r.format_row())
    print(f"\n  mean TPR@0.1%FPR (held-out-family) = {np.mean(tprs):.4f}  <- the headline")


if __name__ == "__main__":
    main()
