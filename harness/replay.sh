#!/usr/bin/env bash
# Controlled-rate pcap replay harness (CLAUDE.md §9, Build Order step 1).
#
# Replays a capture at a controlled rate so Zeek emits ssl.log downstream. Passive/offline:
# replays into a local capture interface, never onto a live network toward any real host.
#
# Usage: ./harness/replay.sh <pcap> [interface] [mbps]
set -euo pipefail

PCAP="${1:?usage: replay.sh <pcap> [interface] [mbps]}"
IFACE="${2:-lo}"
MBPS="${3:-10}"

command -v tcpreplay >/dev/null || { echo "tcpreplay not installed" >&2; exit 1; }

echo "Replaying $PCAP on $IFACE at ${MBPS} Mbps ..."
tcpreplay --intf1="$IFACE" --mbps="$MBPS" "$PCAP"
