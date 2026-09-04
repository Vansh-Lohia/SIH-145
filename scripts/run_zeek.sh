#!/usr/bin/env bash
# Run Zeek (with FoxIO JA4 + our SPLT logger) over one pcap, emitting logs to an output dir.
#
# Passive/offline: reads a capture file Zeek parses locally. No network, no mitigation.
# -C disables checksum verification — REQUIRED in WSL because of NIC checksum offloading,
# otherwise Zeek treats offloaded packets as bad-checksum and drops them.
#
# Usage: run_zeek.sh <pcap> <out_dir> [zeek_bin]
set -euo pipefail

PCAP="${1:?usage: run_zeek.sh <pcap> <out_dir> [zeek_bin]}"
OUT="${2:?usage: run_zeek.sh <pcap> <out_dir> [zeek_bin]}"
ZEEK="${3:-/opt/zeek/bin/zeek}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$OUT"
cd "$OUT"

# `ja4` loads the FoxIO JA4+ package; splt.zeek adds the per-packet SPLT log.
"$ZEEK" -C -r "$PCAP" ja4 "$HERE/../zeek/splt.zeek"

echo "Zeek logs written to: $OUT"
ls -1 "$OUT"
