#!/usr/bin/env bash
# Generate DIVERSE benign + multiple scan types and capture each to its own pcap.
# Run from portscan-lab/ AFTER: docker compose up -d --build
# Then feed the pcaps to pcap_to_cic.py (see build_dataset.sh).
set -euo pipefail

VICTIM_IP=10.10.10.3
OUT=pcaps
mkdir -p "$OUT"

cap_start() { docker exec -d attacker bash -c "tcpdump -U -i eth0 -w /tmp/$1.pcap 2>/dev/null"; sleep 1; }
cap_stop()  { docker exec attacker bash -c "pkill -2 tcpdump || pkill tcpdump || true"; sleep 2;
              docker cp attacker:/tmp/$1.pcap "$OUT/$1.pcap"; }

echo "[*] Waiting for victim services..."; sleep 3
docker exec victim bash -c "for h in \$(seq 10 40); do ip addr add 10.10.10.\$h/24 dev eth0 2>/dev/null || true; done" || true

# ------------------------- BENIGN -------------------------
# 1) single-port clients (a real client touches one/two ports, sizeable flows)
cap_start benign_client
for i in $(seq 1 25); do
  docker exec attacker bash -c "curl -s -m 3 -d 'benign_post_payload_data_$i' http://$VICTIM_IP:8080/ >/dev/null || true"
  docker exec attacker bash -c "curl -s -m 3 -d 'benign_post_payload_data_$i' http://$VICTIM_IP:80/   >/dev/null || true"
done
cap_stop benign_client

# 2) legit HIGH FAN-OUT on a couple ports (CDN/update-like) — MUST NOT be flagged
cap_start benign_fanout
docker exec attacker bash -c "for h in \$(seq 10 40); do curl -s -m 2 -d 'cdn_update_ping' http://10.10.10.\$h:8080/ >/dev/null 2>&1 & done; wait" || true
for p in 80 8080 3306 22; do
  for i in $(seq 1 5); do
    docker exec attacker bash -c "echo 'status_check' | nc -w 1 $VICTIM_IP $p >/dev/null 2>&1 || true"
  done
done
cap_stop benign_fanout

# ------------------------- SCANS -------------------------
# SYN scan (half-open)
cap_start scan_syn ;  docker exec attacker bash -c "nmap -sS -p 1-1000 $VICTIM_IP >/dev/null" ; cap_stop scan_syn
# TCP connect scan
cap_start scan_connect ; docker exec attacker bash -c "nmap -sT -p 1-1000 $VICTIM_IP >/dev/null" ; cap_stop scan_connect
# FIN scan (stealth)
cap_start scan_fin ; docker exec attacker bash -c "nmap -sF -p 1-1000 $VICTIM_IP >/dev/null" ; cap_stop scan_fin
# SLOW / timed scan — exercises slow-scan detection in ~10s instead of 50m
cap_start scan_slow ; docker exec attacker bash -c "nmap -sS --scan-delay 200ms -p 1-50 $VICTIM_IP >/dev/null" ; cap_stop scan_slow
echo "[✓] Captured pcaps in $OUT/:"
ls -la "$OUT"
