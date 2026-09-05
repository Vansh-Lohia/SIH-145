#!/usr/bin/env bash
# Capture ONE batch of REALISTIC one-way traffic to <outdir>/*.pcap.
#
# Design goal: the per-flow feature space of benign and scan traffic OVERLAPS,
# so no single flow feature separates them -- exactly like real traffic. The
# only reliable discriminator is behavioural FAN-OUT (a source touching many
# ports/hosts). Specifically:
#   * benign has EMPTY flows too: failed connections to closed ports (SYN->RST),
#     and connect-then-close health checks -- byte-identical to scan probes.
#   * scans have PAYLOAD flows too: nmap -sV service/version probes.
#   * benign 0-byte flows come from LOW-fan-out sources; scan 0-byte flows come
#     from HIGH-fan-out sources. That difference is what the detector must learn.
#
# Usage:  ./capture_batch.sh <outdir> <base> [profile]
#   <base>    : source-IP base (last octet). Different bases => SOURCE-DISJOINT.
#   [profile] : "default" (-T4) or "hard" (-T2 + decoys) for the scan timing.
set -euo pipefail

OUTDIR="${1:?usage: capture_batch.sh <outdir> <base> [profile]}"
BASE="${2:?usage: capture_batch.sh <outdir> <base> [profile]}"
PROFILE="${3:-default}"
mkdir -p "$OUTDIR"

PRIMARY=10.10.10.3
VICTIMS_RANGE="10.10.10.10-40"
OPEN_PORTS="22 80 443 3306 8080"                    # victim actually listens here
CLOSED_PORTS="21 23 139 445 3389 5900 8443 9200 1521 27017"   # refused -> SYN/RST
ATKS=();  for i in 0 1 2 3;                do ATKS+=("10.10.10.$((BASE+i))");  done
BENS=();  for i in $(seq 10 21);           do BENS+=("10.10.10.$((BASE+i))"); done   # 12 clients
MONS=();  for i in 22 23 24;               do MONS+=("10.10.10.$((BASE+i))"); done   # fan-out monitors
DECOYS="10.10.10.$((BASE+40)),10.10.10.$((BASE+41)),10.10.10.$((BASE+42))"

if [ "$PROFILE" = "hard" ]; then TIMING="-T2 --scan-delay 40ms"; EVASION="-D $DECOYS"
else                             TIMING="-T4";                   EVASION=""; fi

cap_start() { docker exec -d attacker bash -c "tcpdump -U -i eth0 -w /tmp/$1.pcap 2>/dev/null"; sleep 2; }
cap_stop()  { sleep 1; docker exec attacker bash -c "pkill -2 tcpdump 2>/dev/null || pkill tcpdump || true"; sleep 2;
              docker cp "attacker:/tmp/$1.pcap" "$OUTDIR/$1.pcap"; }
run()  { docker exec attacker bash -c "$1"; }
nmap_scan() { run "nmap -sS -Pn -n -e eth0 $TIMING $EVASION $1 >/dev/null 2>&1 || true"; }

echo "[*] profile=$PROFILE base=$BASE attackers=${ATKS[*]}"
docker exec victim bash -c "for h in \$(seq 10 40); do ip addr add 10.10.10.\$h/24 dev eth0 2>/dev/null || true; done" || true
for ip in "${ATKS[@]}" "${BENS[@]}" "${MONS[@]}"; do
  docker exec attacker bash -c "ip addr add ${ip}/24 dev eth0 2>/dev/null || true" || true
done

# ============================ BENIGN ============================
echo "[*] BENIGN (payload sessions + failed conns + health checks + fan-out) ..."
cap_start benign
BEN_SCRIPT='
set +e
bens="'"${BENS[*]}"'"; mons="'"${MONS[*]}"'"
open="'"$OPEN_PORTS"'"; closed="'"$CLOSED_PORTS"'"; V='"$PRIMARY"'
send()  { head -c "$2" /dev/zero | tr "\0" "A" | ncat -s "$1" -w 1 "$3" "$4" >/dev/null 2>&1; }  # payload
empty() { ncat -s "$1" -w 1 --send-only "$2" "$3" </dev/null >/dev/null 2>&1; }                  # 0-byte
# (1) normal payload sessions: 1-4 varied-size requests to open service ports
for r in $(seq 1 30); do
  for s in $bens; do
    ( for q in $(seq 1 $(( (RANDOM%4)+1 ))); do
        p=$(echo $open | tr " " "\n" | shuf -n1)
        case $((RANDOM%3)) in 0) sz=$(((RANDOM%600)+150));; 1) sz=$(((RANDOM%5000)+1500));; 2) sz=$(((RANDOM%25000)+8000));; esac
        send "$s" "$sz" "$V" "$p"
      done ) &
  done; wait
done
# (2) FAILED connections: each client hits 1-3 CLOSED ports (SYN->RST, 0 bytes)
#     -- byte-identical to a SYN scan probe, but from a LOW-fan-out source.
for r in $(seq 1 22); do
  for s in $bens; do
    ( for q in $(seq 1 $(( (RANDOM%3)+1 ))); do
        p=$(echo $closed | tr " " "\n" | shuf -n1); empty "$s" "$V" "$p"
      done ) &
  done; wait
done
# (3) health checks: connect-then-close to an OPEN port, no data (0 bytes)
for r in $(seq 1 16); do
  for s in $bens; do
    ( p=$(echo $open | tr " " "\n" | shuf -n1); empty "$s" "$V" "$p" ) &
  done; wait
done
# (4) legitimate high fan-out monitors: MANY hosts, small PAYLOAD health checks
for r in $(seq 1 14); do
  for s in $mons; do
    for h in $(seq 10 40); do p=$(( (RANDOM%2)==0 ? 80 : 443 )); ( send "$s" 120 10.10.10.$h "$p" ) & done
  done; wait
done
'
run "$BEN_SCRIPT"
cap_stop benign

# ============================ SCANS ============================
echo "[*] VERTICAL (-sS, empty probes) ..."
cap_start scan_vertical
for atk in "${ATKS[@]:0:3}"; do nmap_scan "-S $atk -p 1-500 $PRIMARY"; done
cap_stop scan_vertical

echo "[*] CONNECT (-sT, completes handshake; overlaps benign health checks) ..."
cap_start scan_connect
for atk in "${ATKS[@]:0:2}"; do run "nmap -sT -Pn -n -e eth0 $TIMING -S $atk -p 1-400 $PRIMARY >/dev/null 2>&1 || true"; done
cap_stop scan_connect

echo "[*] SERVICE (-sV, payload probes; overlaps benign payload) ..."
cap_start scan_service
for atk in "${ATKS[@]:1:2}"; do
  run "nmap -sV -Pn -n -e eth0 --version-intensity 4 -S $atk -p $(echo $OPEN_PORTS | tr ' ' ',') $PRIMARY >/dev/null 2>&1 || true"
  run "nmap -sV -Pn -n -e eth0 --version-intensity 2 -S $atk -p 1-200 $PRIMARY >/dev/null 2>&1 || true"
done
cap_stop scan_service

echo "[*] HORIZONTAL (-sS, many hosts) ..."
cap_start scan_horizontal
for atk in "${ATKS[@]:0:3}"; do for port in 445 22 80 3389 23; do nmap_scan "-S $atk -p $port $VICTIMS_RANGE"; done; done
cap_stop scan_horizontal

echo "[*] MIXED (-sS, many hosts AND ports) ..."
cap_start scan_mixed
for atk in "${ATKS[@]:1:2}"; do nmap_scan "-S $atk -p 20,21,22,23,80,443,445,3306,8080,8443 $VICTIMS_RANGE"; done
cap_stop scan_mixed

echo "[*] SLOW (spread across time windows; ~1-3 min) ..."
cap_start scan_slow
for atk in "${ATKS[@]:0:2}"; do
  run "nmap -sS -Pn -n -e eth0 --scan-delay 250ms --max-rate 5 $EVASION -S $atk -p 1-120 $PRIMARY >/dev/null 2>&1 || true"
done
cap_stop scan_slow

echo "[✓] Batch '$PROFILE' captured to $OUTDIR/:"; ls -la "$OUTDIR"
