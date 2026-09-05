#!/usr/bin/env bash
# Capture ONE batch of REAL traffic (rich benign + 4 scan types) to <outdir>/*.pcap.
#
# Usage:  ./capture_batch.sh <outdir> <base> [profile]
#   <base>    : source-IP base (last octet). Batches with different bases are
#               SOURCE-DISJOINT -- the split the project could never do on CIC-IDS.
#   [profile] : "default" (fast -T4 scans) or "hard" (slow -T2 + nmap decoys,
#               for probing generalization to different timing/evasion).
#
#   ./capture_batch.sh pcaps_train 50            # training batch
#   ./capture_batch.sh pcaps_eval  90            # eval batch (disjoint sources)
#   ./capture_batch.sh pcaps_hard  130 hard      # generalization batch
set -euo pipefail

OUTDIR="${1:?usage: capture_batch.sh <outdir> <base> [profile]}"
BASE="${2:?usage: capture_batch.sh <outdir> <base> [profile]}"
PROFILE="${3:-default}"
mkdir -p "$OUTDIR"

PRIMARY=10.10.10.3
VICTIMS_RANGE="10.10.10.10-40"                       # 31 protected hosts
ATKS=();  for i in 0 1 2 3;                do ATKS+=("10.10.10.$((BASE+i))");  done
BENS=();  for i in 10 11 12 13 14 15 16 17 18 19 20 21; do BENS+=("10.10.10.$((BASE+i))"); done
MONS=();  for i in 22 23 24;               do MONS+=("10.10.10.$((BASE+i))"); done   # fan-out (CDN/monitor)
DECOYS="10.10.10.$((BASE+40)),10.10.10.$((BASE+41)),10.10.10.$((BASE+42))"

if [ "$PROFILE" = "hard" ]; then
  TIMING="-T2 --scan-delay 40ms"; EVASION="-D $DECOYS"
else
  TIMING="-T4";                   EVASION=""
fi

cap_start() { docker exec -d attacker bash -c "tcpdump -U -i eth0 -w /tmp/$1.pcap 2>/dev/null"; sleep 2; }
cap_stop()  { sleep 1; docker exec attacker bash -c "pkill -2 tcpdump 2>/dev/null || pkill tcpdump || true"; sleep 2;
              docker cp "attacker:/tmp/$1.pcap" "$OUTDIR/$1.pcap"; }
run()  { docker exec attacker bash -c "$1"; }
nmap_scan() { run "nmap -sS -Pn -n -e eth0 $TIMING $EVASION $1 >/dev/null 2>&1 || true"; }

echo "[*] profile=$PROFILE  base=$BASE  attackers=${ATKS[*]}"
docker exec victim   bash -c "for h in \$(seq 10 40); do ip addr add 10.10.10.\$h/24 dev eth0 2>/dev/null || true; done" || true
for ip in "${ATKS[@]}" "${BENS[@]}" "${MONS[@]}"; do
  docker exec attacker bash -c "ip addr add ${ip}/24 dev eth0 2>/dev/null || true" || true
done

# ============================ BENIGN ============================
# Realistic client mix: normal multi-request sessions with varied payload sizes
# (small API calls, medium pages, bulk transfers) from many client IPs, PLUS a
# legitimate high-fan-out pattern (monitoring/CDN health checks across many
# hosts) -- the hardest negative, which MUST stay unflagged.
echo "[*] BENIGN (normal sessions + high fan-out) ..."
cap_start benign
BEN_SCRIPT='
set +e
bens="'"${BENS[*]}"'"
mons="'"${MONS[*]}"'"
ports="22 80 443 3306 8080"
send() { head -c "$2" /dev/zero | tr "\0" "A" | ncat -s "$1" -w 1 "$3" "$4" >/dev/null 2>&1; }
# normal sessions: each client makes 1-4 varied-size requests to a service
for r in $(seq 1 35); do
  for s in $bens; do
    (
      reqs=$(( (RANDOM % 4) + 1 ))
      for q in $(seq 1 $reqs); do
        p=$(echo $ports | tr " " "\n" | shuf -n1)
        case $((RANDOM % 3)) in
          0) sz=$(( (RANDOM % 600) + 150 ));;      # small API call
          1) sz=$(( (RANDOM % 5000) + 1500 ));;    # medium page
          2) sz=$(( (RANDOM % 25000) + 8000 ));;   # bulk transfer
        esac
        send "$s" "$sz" '"$PRIMARY"' "$p"
      done
    ) &
  done
  wait
done
# legitimate high fan-out: monitors hit MANY hosts on 80/443 with tiny health checks
for r in $(seq 1 14); do
  for s in $mons; do
    for h in $(seq 10 40); do
      p=$(( (RANDOM % 2) == 0 ? 80 : 443 ))
      ( send "$s" 120 10.10.10.$h "$p" ) &
    done
  done
  wait
done
'
run "$BEN_SCRIPT"
cap_stop benign

# ============================ SCANS ============================
echo "[*] VERTICAL ..."
cap_start scan_vertical
for atk in "${ATKS[@]:0:3}"; do nmap_scan "-S $atk -p 1-700 $PRIMARY"; done
cap_stop scan_vertical

echo "[*] HORIZONTAL ..."
cap_start scan_horizontal
for atk in "${ATKS[@]:0:3}"; do
  for port in 445 22 80 3389 23; do nmap_scan "-S $atk -p $port $VICTIMS_RANGE"; done
done
cap_stop scan_horizontal

echo "[*] MIXED ..."
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
