#!/usr/bin/env bash
# Turn captured pcaps into ONE labeled CSV in the model's exact schema,
# then produce a TIME-ORDERED train/test split (the split CIC-IDS-2017 could
# not do). Run from portscan-lab/ after capture_traffic.sh.
set -euo pipefail

PY="../.venv/bin/python"          # project venv (has scapy + pandas)
OUT=dataset
mkdir -p "$OUT/parts"

label_of() { case "$1" in benign*) echo BENIGN;; scan*) echo PortScan;; *) echo BENIGN;; esac; }

echo "[*] Extracting forward-direction CIC features from each pcap..."
for p in pcaps/*.pcap; do
  base=$(basename "$p" .pcap)
  $PY pcap_to_cic.py --pcap "$p" --label "$(label_of "$base")" --out "$OUT/parts/$base.csv"
done

echo "[*] Merging + time-ordered split..."
$PY - "$OUT" <<'EOF'
import glob, sys, pandas as pd
out = sys.argv[1]
parts = [pd.read_csv(f) for f in sorted(glob.glob(f"{out}/parts/*.csv"))]
df = pd.concat(parts, ignore_index=True)
df = df.sort_values("timestamp").reset_index(drop=True)
df.to_csv(f"{out}/portscan_dataset.csv", index=False)

# time-ordered split: first 70% by time = train, last 30% = test
cut = int(len(df) * 0.7)
df.iloc[:cut].to_csv(f"{out}/train.csv", index=False)
df.iloc[cut:].to_csv(f"{out}/test.csv", index=False)

print(f"[build] total rows: {len(df)}")
print("[build] label counts:\n", df['Label'].value_counts().to_string())
print(f"[build] train={cut} rows  test={len(df)-cut} rows (time-ordered)")
print(f"[build] wrote {out}/portscan_dataset.csv, train.csv, test.csv")
EOF

echo
echo "[✓] Dataset ready in $OUT/. Train your model on it with:"
echo "    ../.venv/bin/python ../training/train.py --dataset $OUT/portscan_dataset.csv"
