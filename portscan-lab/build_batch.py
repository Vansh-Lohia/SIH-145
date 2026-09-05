#!/usr/bin/env python3
"""Extract every pcap in a batch dir into one merged, time-sorted labeled CSV
matching the streaming simulator's schema (identity + 17 CIC features + Label +
Scan_Type). Usage: build_batch.py <batch_dir> <out.csv>"""
import subprocess, sys, csv, glob, os
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY = sys.executable

# Victim / protected hosts in the lab topology. A passive data-diode monitor
# sees only ONE direction (client -> server). tcpdump on the attacker NIC also
# records the victims' reverse replies (SYN-ACK/RST, ncat echoes); those are
# reverse-direction and must be dropped so the dataset is strictly one-way and
# victim replies are never mislabeled as scan traffic.
VICTIM_HOSTS = {"10.10.10.3"} | {f"10.10.10.{i}" for i in range(10, 41)}

# pcap basename -> (Label, Scan_Type)
MAP = {
    "benign":          ("BENIGN",   "benign"),
    "scan_vertical":   ("PortScan", "vertical"),
    "scan_horizontal": ("PortScan", "horizontal"),
    "scan_mixed":      ("PortScan", "mixed"),
    "scan_slow":       ("PortScan", "slow"),
}


def main() -> int:
    batch_dir, out_csv = sys.argv[1], sys.argv[2]
    tmp_dir = Path(batch_dir) / "_parts"
    tmp_dir.mkdir(exist_ok=True)

    rows, header = [], None
    for pcap in sorted(glob.glob(f"{batch_dir}/*.pcap")):
        base = Path(pcap).stem
        if base not in MAP:
            print(f"  ! skip {base} (no label mapping)"); continue
        label, stype = MAP[base]
        part = tmp_dir / f"{base}.csv"
        subprocess.run([PY, str(HERE / "pcap_to_cic.py"), "--pcap", pcap,
                        "--label", label, "--scan-type", stype, "--out", str(part)],
                       check=True)
        with open(part) as fh:
            r = csv.reader(fh)
            h = next(r)
            header = header or h
            src_i = h.index("src_ip")
            kept = [row for row in r if row[src_i] not in VICTIM_HOSTS]
            rows.extend(kept)

    if header is None:
        print("no pcaps found"); return 1

    ts_i = header.index("timestamp")
    rows.sort(key=lambda x: float(x[ts_i]))
    with open(out_csv, "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(header); w.writerows(rows)

    # summary
    lab_i, st_i = header.index("Label"), header.index("Scan_Type")
    from collections import Counter
    labc, stc = Counter(r[lab_i] for r in rows), Counter(r[st_i] for r in rows)
    print(f"\n[build] {out_csv}: {len(rows)} flows")
    print(f"[build] labels: {dict(labc)}")
    print(f"[build] scan types: {dict(stc)}")
    print(f"[build] unique src_ip: {len({r[header.index('src_ip')] for r in rows})} | "
          f"unique dst_ip: {len({r[header.index('dst_ip')] for r in rows})} | "
          f"unique dst_port: {len({r[header.index('dst_port')] for r in rows})}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
