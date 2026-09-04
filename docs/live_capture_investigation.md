# Live benign-traffic capture — was blocked, now unblocked

**Update 2026-09-04:** the user ran the one-time `setcap` command below. Live capture now
works. `scripts/capture_live_benign.sh` scripts real HTTPS traffic (curl to 31 popular
domains) while `tcpdump` records it — 237 real TLS 1.3 sessions captured in ~2 minutes, no
sudo needed. See `docs/evaluation.md` ("Update: live capture unblocked...") for what this
did and didn't resolve. `tcpreplay` (needed to also replay a malware pcap through the same
live interface) is still not installed — that's the next concrete step, not a blocker.

The original investigation is kept below for reference.

`CLAUDE.md` §8 prefers benign traffic **generated on the same network and period as the
malware replay** over a downloaded stand-in, because that's what actually removes the
environment-artifact confound (§7) rather than just relabeling around it. This was
investigated on 2026-09-04 and is currently blocked in this environment. Recorded here so
the next session doesn't re-walk the same dead ends.

## What was tried

1. **A CTU capture with malicious and benign traffic already mixed in one pcap** (would
   remove the confound with zero new capture work). Checked `CTU-219-2`'s
   `ssl.log.labeled` — all 744 sessions are `label=Malicious`. Checked the "background" TLS
   destinations inside the Dridex/Trickbot/Emotet captures (traffic to IPs other than the
   known C2) — none exist; every CTU-Malware-Capture-Botnet-* pcap used here is **pre-filtered
   by CTU to the infected host's malicious traffic only**. No mixed-label source found.

2. **Live capture in WSL**: script real HTTPS browsing (curl to a Tranco-style site list)
   while `tcpdump`/live `zeek -i eth0` records it, optionally alongside a `tcpreplay` of a
   malware pcap onto the same interface so both classes share one capture environment. Blocked:

   ```
   tcpdump: eth0: You don't have permission to perform this capture on that device
   (Attempt to create packet socket failed - CAP_NET_RAW may be required)
   sudo: interactive authentication is required
   ```

   The WSL user is in the `sudo` group but sudo requires an interactive password not
   available to the agent running this session — and entering a sudo password on the user's
   behalf is out of scope regardless of availability.

3. **Docker as a workaround** (a container can be granted `--cap-add=NET_RAW` without host
   root). `docker` CLI exists on Windows but the Docker Desktop engine is not running
   (`failed to connect to the docker API ... dockerDesktopLinuxEngine`), and starting it
   requires GUI interaction.

## What would unblock it (either is a one-time action)

```bash
# Grant tcpdump raw-capture rights permanently (no sudo needed afterward):
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump
```
or start Docker Desktop and keep it running.

## What was done instead

Downloaded more CTU-Normal (benign) captures to increase benign volume/diversity — a
strictly weaker fix (still a different capture era/setup than the malware sandboxes) but
fully executable without elevated privileges. See `data/SOURCES.md` for what's downloaded and
`docs/evaluation.md` for the environment-confound caveat that remains on every real-data
result until this is closed properly.
