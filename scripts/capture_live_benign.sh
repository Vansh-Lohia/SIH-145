#!/usr/bin/env bash
# Capture REAL benign TLS traffic by scripting HTTPS visits to popular sites while tcpdump
# records the wire packets. Requires tcpdump to have raw-capture capability without sudo:
#   sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump   (one-time)
#
# This directly implements CLAUDE.md §8's preferred benign-data recipe ("scripted browsing
# over Tranco top sites... captured on the same network and period as your malware replay")
# rather than relying solely on a downloaded stand-in dataset.
#
# Usage: capture_live_benign.sh <out.pcap> [iface] [seconds]
set -euo pipefail

OUT="${1:?usage: capture_live_benign.sh <out.pcap> [iface] [seconds]}"
IFACE="${2:-eth0}"
DURATION="${3:-120}"

# A fixed slice of the Tranco top-sites list: real, popular, TLS-serving domains spanning
# CDNs, social, commerce, news, and infra — enough diversity for realistic JA4/SPLT variety.
SITES=(
  google.com wikipedia.org youtube.com facebook.com amazon.com
  microsoft.com apple.com cloudflare.com github.com stackoverflow.com
  reddit.com twitter.com linkedin.com netflix.com nytimes.com
  bbc.com cnn.com wordpress.com mozilla.org ubuntu.com
  docker.com python.org npmjs.com wikipedia.org bing.com
  yahoo.com adobe.com salesforce.com dropbox.com spotify.com
  paypal.com
)

echo "Starting tcpdump on $IFACE -> $OUT (duration ${DURATION}s)..."
tcpdump -i "$IFACE" -w "$OUT" 'tcp port 443' &
TCPDUMP_PID=$!
sleep 2   # let tcpdump attach before generating traffic

echo "Generating real HTTPS traffic to ${#SITES[@]} sites..."
END=$(( $(date +%s) + DURATION ))
while [ "$(date +%s)" -lt "$END" ]; do
  for site in "${SITES[@]}"; do
    curl -sS -m 5 -o /dev/null "https://$site/" || true
    [ "$(date +%s)" -ge "$END" ] && break
  done
done

echo "Stopping capture..."
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

ls -lh "$OUT"
echo "Done: $OUT"
