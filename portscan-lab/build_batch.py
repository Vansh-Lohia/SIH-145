#!/usr/bin/env python3
"""Build a labeled, time-interleaved CSV from a batch captured by capture_batch.sh.

The batch dir holds ONE interleaved capture (`stream.pcap`) plus `roles.csv`
mapping every source IP to (Label, Scan_Type). We extract forward-only CIC
features from the pcap, then label each flow by its src_ip. Flows whose src_ip
is not a known role (victim reply packets, strays) are dropped -- this enforces
the strictly one-way constraint and never mislabels a reverse flow.

Usage: build_batch.py <batch_dir> <out.csv>
"""
import subprocess, sys, csv, glob, os
from pathlib import Path
from collections import Counter

HERE = Path(__file__).resolve().parent
PY = sys.executable


def load_roles(batch_dir: str):
    roles = {}
    with open(Path(batch_dir) / "roles.csv") as fh:
        for r in csv.DictReader(fh):
            roles[r["src_ip"]] = (r["Label"], r["Scan_Type"])
    return roles


def main() -> int:
    batch_dir, out_csv = sys.argv[1], sys.argv[2]
    roles = load_roles(batch_dir)

    pcaps = glob.glob(f"{batch_dir}/*.pcap")
    if not pcaps:
        print("no pcap found"); return 1

    tmp = Path(batch_dir) / "_raw.csv"
    rows, header = [], None
    for pcap in sorted(pcaps):
        subprocess.run([PY, str(HERE / "pcap_to_cic.py"), "--pcap", pcap,
                        "--label", "_", "--scan-type", "_", "--out", str(tmp)], check=True)
        with open(tmp) as fh:
            r = csv.reader(fh); h = next(r); header = header or h
            si, li, ti = h.index("src_ip"), h.index("Label"), h.index("Scan_Type")
            for row in r:
                role = roles.get(row[si])
                if role is None:            # not a known source => reverse/stray => drop
                    continue
                row[li], row[ti] = role      # label by src_ip role
                rows.append(row)
    tmp.unlink(missing_ok=True)

    ts_i = header.index("timestamp")
    rows.sort(key=lambda x: float(x[ts_i]))
    with open(out_csv, "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(header); w.writerows(rows)

    li, ti, si2, di, pi = (header.index(c) for c in ("Label", "Scan_Type", "src_ip", "dst_ip", "dst_port"))
    print(f"\n[build] {out_csv}: {len(rows)} flows")
    print(f"[build] labels: {dict(Counter(r[li] for r in rows))}")
    print(f"[build] scan types: {dict(Counter(r[ti] for r in rows))}")
    print(f"[build] unique src_ip: {len({r[si2] for r in rows})} | "
          f"unique dst_ip: {len({r[di] for r in rows})} | "
          f"unique dst_port: {len({r[pi] for r in rows})}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
