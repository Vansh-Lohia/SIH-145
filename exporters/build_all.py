"""Merge every detector's unified alerts into data/alerts.jsonl on one replay timeline.

The captures come from different places and years, so for the live demo their alerts are
interleaved onto a single REPLAY clock (`replay_offset_s`). Each alert keeps its original
capture time (`captured_at`) and data source, and the dashboard shows both -- nothing is
presented as having happened on one real network at one real time.

Run the exporters first (see README), then:  python3 build_all.py
"""
import json
import random

from common import OUT_DIR, ROOT

REPLAY_SECONDS = 600          # 10-minute replay at 1x speed
CAPS = {"dns_tunnelling": 30, "data_exfiltration": 25}   # keep the feed balanced
random.seed(2026)


def main():
    merged = []
    for path in sorted(OUT_DIR.glob("*.jsonl")):
        rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l]
        cap = CAPS.get(path.stem)
        if cap and len(rows) > cap:
            fps = [r for r in rows if "false positive" in str(r["evidence"][-1]["value"])
                   or r["evidence"][-1]["value"] in ("benign", "normal")]
            tps = [r for r in rows if r not in fps]
            k_fp = round(cap * len(fps) / len(rows))
            rows = random.sample(tps, cap - k_fp) + random.sample(fps, k_fp)
        merged += rows
        print(f"{path.stem:>18}: {len(rows)}")

    random.shuffle(merged)
    # a quiet start, then steady activity: offsets sorted, first alert after ~8 s
    offsets = sorted(random.uniform(8, REPLAY_SECONDS) for _ in merged)
    for a, off in zip(merged, offsets):
        a["replay_offset_s"] = round(off, 2)

    out = ROOT / "data" / "alerts.jsonl"
    with out.open("w", encoding="utf-8") as fh:
        for a in merged:
            fh.write(json.dumps(a) + "\n")
    print(f"total: {len(merged)} alerts -> {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
