#!/usr/bin/env bash
# Generate benign + port-scan traffic, capture it, and run Zeek to produce
# labeled conn.log files. Run from the portscan-lab/ folder AFTER:
#   docker compose up -d --build
set -euo pipefail

VICTIM_IP=10.10.10.3
OUT=logs
mkdir -p "$OUT/benign" "$OUT/scan"

echo "[*] Waiting for victim services to come up..."
sleep 3

# ---------------------------------------------------------------------------
# 1) BENIGN capture: a normal client touching just one or two ports.
# ---------------------------------------------------------------------------
echo "[*] Capturing BENIGN traffic..."
docker exec -d attacker bash -c "tcpdump -i eth0 -w /tmp/benign.pcap not port 22 2>/dev/null"
sleep 1
docker exec attacker bash -c "curl -s -m 3 http://$VICTIM_IP:8080/ >/dev/null || true"
docker exec attacker bash -c "curl -s -m 3 http://$VICTIM_IP:80/   >/dev/null || true"
sleep 2
docker exec attacker bash -c "pkill tcpdump || true"
sleep 1

# ---------------------------------------------------------------------------
# 2) SCAN capture: attacker runs nmap across 1000 ports of the victim.
# ---------------------------------------------------------------------------
echo "[*] Capturing PORT-SCAN traffic..."
docker exec -d attacker bash -c "tcpdump -i eth0 -w /tmp/scan.pcap 2>/dev/null"
sleep 1
docker exec attacker bash -c "nmap -p 1-1000 $VICTIM_IP >/dev/null"
sleep 2
docker exec attacker bash -c "pkill tcpdump || true"
sleep 1

# ---------------------------------------------------------------------------
# 3) Run Zeek OFFLINE on each pcap -> conn.log (no netns/tc needed).
# ---------------------------------------------------------------------------
echo "[*] Running Zeek over the captures..."
docker exec attacker bash -c "cd /tmp && rm -rf zb && mkdir zb && cd zb && zeek -C -r /tmp/benign.pcap"
docker exec attacker bash -c "cd /tmp && rm -rf zs && mkdir zs && cd zs && zeek -C -r /tmp/scan.pcap"

# ---------------------------------------------------------------------------
# 4) Pull the logs back to your Mac.
# ---------------------------------------------------------------------------
docker cp attacker:/tmp/zb/conn.log "$OUT/benign/conn.log"
docker cp attacker:/tmp/zs/conn.log "$OUT/scan/conn.log"

echo
echo "[✓] Done."
echo "    Benign log: $OUT/benign/conn.log"
echo "    Scan log:   $OUT/scan/conn.log"
echo
echo "Distinct destination ports the attacker (10.10.10.2) touched:"
echo -n "  benign: "; awk '$1!~/^#/ && $3=="10.10.10.2"{print $6}' "$OUT/benign/conn.log" | sort -u | wc -l
echo -n "  scan:   "; awk '$1!~/^#/ && $3=="10.10.10.2"{print $6}' "$OUT/scan/conn.log"   | sort -u | wc -l
