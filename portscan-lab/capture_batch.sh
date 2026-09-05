#!/usr/bin/env bash
# Capture ONE batch of REALISTIC, TIME-INTERLEAVED one-way traffic.
#
# Unlike a naive "all benign then all scans" capture, benign traffic runs
# CONTINUOUSLY in the background for the whole window while scans fire at
# staggered start times -- so scans and normal traffic coexist in time, exactly
# like a real link. Everything lands in ONE pcap; each flow is labelled by its
# SOURCE IP (we assign every IP a role, written to roles.csv).
#
# Design goals (unchanged): per-flow feature space of benign and scan OVERLAPS
# (benign has empty failed-connection / health-check flows; scans have -sV
# payload flows), so only behavioural FAN-OUT separates them. Two edge profiles
# narrow the fan-out gap: `chatty` benign (high fan-out -> FP stress) and
# `stealth` scans (low fan-out -> recall stress).
#
# Usage:  ./capture_batch.sh <outdir> <base> [profile] [duration_s]
#   Different <base> => SOURCE-DISJOINT batches (train vs eval).
set -euo pipefail

OUTDIR="${1:?usage: capture_batch.sh <outdir> <base> [profile] [duration_s]}"
BASE="${2:?usage: capture_batch.sh <outdir> <base> [profile] [duration_s]}"
PROFILE="${3:-default}"
DUR="${4:-150}"
mkdir -p "$OUTDIR"

PRIMARY=10.10.10.3
VICTIMS_RANGE="10.10.10.10-40"
OPEN_PORTS="22 80 443 3306 8080"
CLOSED_PORTS="21 23 139 445 3389 5900 8443 9200 1521 27017"
CHATTY_PORTS="22 80 443 3306 8080 21 23 445 3389 8443 9200 1521 27017 5432 6379 9092 2181 8000 8888 9090 3000 5000 8081 11211 15672"

ip() { echo "10.10.10.$((BASE+$1))"; }
# Dedicated source IPs per ROLE (so a single concurrent capture can be labelled
# by src_ip). Offsets stay in 0..33 => within [BASE, BASE+33], disjoint per base.
VERT=("$(ip 0)" "$(ip 1)" "$(ip 2)")
CONNECT=("$(ip 3)")
SERVICE=("$(ip 4)" "$(ip 5)")
HORIZ=("$(ip 6)" "$(ip 7)" "$(ip 8)")
MIXED=("$(ip 9)" "$(ip 10)")
SLOW=("$(ip 11)" "$(ip 12)")
STEALTH=("$(ip 13)" "$(ip 14)" "$(ip 15)")
BENS=(); for o in 16 17 18 19 20 21 22 23 24 25 26 27; do BENS+=("$(ip $o)"); done
MONS=("$(ip 28)" "$(ip 29)" "$(ip 30)")
CHATTYS=("$(ip 31)" "$(ip 32)" "$(ip 33)")

if [ "$PROFILE" = "hard" ]; then TIMING="-T2"; EVASION="-D $(ip 40),$(ip 41),$(ip 42)"
else                             TIMING="-T4"; EVASION=""; fi

run() { docker exec attacker bash -c "$1"; }
scan_bg() { ( sleep "$1"; run "$2" ) & }   # start a scan after $1 seconds

echo "[*] profile=$PROFILE base=$BASE duration=${DUR}s"
docker exec victim bash -c "for h in \$(seq 10 40); do ip addr add 10.10.10.\$h/24 dev eth0 2>/dev/null || true; done" || true
ALL=("${VERT[@]}" "${CONNECT[@]}" "${SERVICE[@]}" "${HORIZ[@]}" "${MIXED[@]}" "${SLOW[@]}" "${STEALTH[@]}" "${BENS[@]}" "${MONS[@]}" "${CHATTYS[@]}")
for a in "${ALL[@]}"; do docker exec attacker bash -c "ip addr add ${a}/24 dev eth0 2>/dev/null || true" || true; done

# ---- roles.csv: src_ip -> Label, Scan_Type (used by build_batch.py) ----
{ echo "src_ip,Label,Scan_Type"
  for x in "${VERT[@]}" "${CONNECT[@]}" "${SERVICE[@]}"; do echo "$x,PortScan,vertical"; done
  for x in "${HORIZ[@]}";   do echo "$x,PortScan,horizontal"; done
  for x in "${MIXED[@]}";   do echo "$x,PortScan,mixed"; done
  for x in "${SLOW[@]}";    do echo "$x,PortScan,slow"; done
  for x in "${STEALTH[@]}"; do echo "$x,PortScan,stealth"; done
  for x in "${BENS[@]}" "${MONS[@]}"; do echo "$x,BENIGN,benign"; done
  for x in "${CHATTYS[@]}"; do echo "$x,BENIGN,chatty"; done
} > "$OUTDIR/roles.csv"

# ---- start the single capture ----
docker exec -d attacker bash -c "tcpdump -U -i eth0 -w /tmp/stream.pcap 2>/dev/null"; sleep 2

# ---- benign: runs CONTINUOUSLY in the background for the whole window ----
BEN_SCRIPT='
set +e
bens="'"${BENS[*]}"'"; mons="'"${MONS[*]}"'"; chattys="'"${CHATTYS[*]}"'"
open="'"$OPEN_PORTS"'"; closed="'"$CLOSED_PORTS"'"; cports="'"$CHATTY_PORTS"'"; V='"$PRIMARY"'
send()  { head -c "$2" /dev/zero | tr "\0" "A" | ncat -s "$1" -w 1 "$3" "$4" >/dev/null 2>&1; }
empty() { ncat -s "$1" -w 1 --send-only "$2" "$3" </dev/null >/dev/null 2>&1; }
end=$(( $(date +%s) + '"$DUR"' )); it=0
while [ $(date +%s) -lt $end ]; do
  it=$((it+1))
  # normal clients (the bulk of benign): payload session + occasional failed conn / health check
  for s in $bens; do
    ( p=$(echo $open | tr " " "\n" | shuf -n1)
      case $((RANDOM%3)) in 0) sz=$(((RANDOM%600)+150));; 1) sz=$(((RANDOM%5000)+1500));; 2) sz=$(((RANDOM%25000)+8000));; esac
      send "$s" "$sz" "$V" "$p"
      [ $((RANDOM%2)) -eq 0 ] && empty "$s" "$V" "$(echo $closed | tr " " "\n" | shuf -n1)"
      [ $((RANDOM%3)) -eq 0 ] && empty "$s" "$V" "$(echo $open | tr " " "\n" | shuf -n1)"
    ) &
  done
  # fan-out monitors: many hosts, small payload -- throttled (every 4th iteration)
  if [ $((it%4)) -eq 0 ]; then
    for s in $mons; do ( for h in $(seq 10 40); do send "$s" 120 10.10.10.$h "$(( (RANDOM%2)==0 ? 80 : 443 ))"; done ) & done
  fi
  # chatty apps: many ports across a few hosts -- throttled (every 5th iteration);
  # still reaches full ~25-port fan-out over the window, just fewer total flows
  if [ $((it%5)) -eq 0 ]; then
    for s in $chattys; do ( for h in '"$PRIMARY"' 10.10.10.11 10.10.10.12; do for p in $cports; do
          if [ $((RANDOM%5)) -eq 0 ]; then empty "$s" "$h" "$p"; else send "$s" $(((RANDOM%80)+40)) "$h" "$p"; fi
        done; done ) & done
  fi
  wait
done
'
docker exec -d attacker bash -c "$BEN_SCRIPT"

# ---- scans: staggered start times so they interleave with benign ----
for atk in "${VERT[@]}";    do scan_bg 5   "nmap -sS -Pn -n -e eth0 $TIMING $EVASION -S $atk -p 1-500 $PRIMARY >/dev/null 2>&1 || true"; done
for atk in "${SLOW[@]}";    do scan_bg 12  "nmap -sS -Pn -n -e eth0 --scan-delay 250ms --max-rate 5 $EVASION -S $atk -p 1-120 $PRIMARY >/dev/null 2>&1 || true"; done
for atk in "${HORIZ[@]}";   do scan_bg 30  "for port in 445 22 80 3389 23; do nmap -sS -Pn -n -e eth0 $TIMING $EVASION -S $atk -p \$port $VICTIMS_RANGE >/dev/null 2>&1; done || true"; done
for atk in "${MIXED[@]}";   do scan_bg 45  "nmap -sS -Pn -n -e eth0 $TIMING $EVASION -S $atk -p 20,21,22,23,80,443,445,3306,8080,8443 $VICTIMS_RANGE >/dev/null 2>&1 || true"; done
for atk in "${SERVICE[@]}"; do scan_bg 60  "nmap -sV -Pn -n -e eth0 --version-intensity 3 -S $atk -p $(echo $OPEN_PORTS | tr ' ' ,) $PRIMARY >/dev/null 2>&1; nmap -sV -Pn -n -e eth0 --version-intensity 2 -S $atk -p 1-200 $PRIMARY >/dev/null 2>&1 || true"; done
for atk in "${CONNECT[@]}"; do scan_bg 80  "nmap -sT -Pn -n -e eth0 $TIMING -S $atk -p 1-400 $PRIMARY >/dev/null 2>&1 || true"; done
i=0; for atk in "${STEALTH[@]}"; do
  sp=("22 80 443 3389 445 23 21 8080 3306 8443" "135 139 1433 1521 3306 5432 6379 27017 9200 11211" "20 21 22 23 25 53 80 110 143 443")
  scan_bg $((70+i*15)) "nmap -sS -Pn -n -e eth0 --scan-delay 300ms --max-rate 4 -S $atk -p $(echo ${sp[$i]} | tr ' ' ,) $PRIMARY >/dev/null 2>&1 || true"; i=$((i+1))
done

echo "[*] traffic running (${DUR}s window); waiting for scans + benign to finish ..."
wait                                   # all staggered scan jobs
# ensure benign background loop has finished its window, then stop capture
sleep 6
docker exec attacker bash -c "pkill -2 tcpdump 2>/dev/null || pkill tcpdump || true"; sleep 3
docker cp attacker:/tmp/stream.pcap "$OUTDIR/stream.pcap"
echo "[✓] Batch '$PROFILE' -> $OUTDIR/stream.pcap  (+ roles.csv)"; ls -la "$OUTDIR"
