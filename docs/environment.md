# Environment setup (Build Order step 1)

External tools (not pip packages):

- **Zeek** — https://zeek.org — emits `conn.log`, `ssl.log`, `x509.log`.
- **tcpreplay** — controlled-rate pcap replay into a local capture interface.

## Offline / no-outbound rule (CLAUDE.md §2.2)

The enclave has **no internet**. Before adding any dependency, verify it makes no network
call at import or first use, and vendor any data file it would otherwise download. Pin all
versions. This includes model/threat-intel/GeoIP libraries — none are permitted to phone home.

## Passive replay note

Replay is into a local interface for Zeek to observe. We never replay toward a real host,
never complete a handshake, and never take any inline action (CLAUDE.md §2.1).

## QUIC Initial parsing (permitted — document this)

Parsing the QUIC Initial ClientHello is **not** decryption: Initial packets are protected
with keys derived from the Destination Connection ID via a published, version-specific salt
(RFC 9001), readable by any passive observer without any secret. Standard passive practice
(CLAUDE.md §2.3).

## Real setup in use

Zeek **8.0.10** with the **FoxIO JA4** package, installed at `/opt/zeek` inside WSL
(Ubuntu). `ssl.log` carries `ja4` / `ja4s`; `conn.log` also carries `ja4t` / `ja4l`.

### `-C` is required on every pcap (WSL)

WSL NICs do checksum offloading, so captured packets have "bad" (unfilled) checksums. Without
`-C`, Zeek drops them and `ssl.log` comes out empty. **Always pass `-C`.**

### Per-packet SPLT

Standard Zeek logs give only aggregate byte/packet counts. `zeek/splt.zeek` adds `splt.log`
with the first N packets of each flow as `(seq, len, is_orig)`, keyed by connection `uid`, so
the shape/timing family (CLAUDE.md §6.2) has real per-packet data.

### Run one pcap end to end

```bash
# 1. Zeek (JA4 + SPLT) over a pcap, into a log dir  (run inside WSL):
bash scripts/run_zeek.sh /path/to/capture.pcap data/zeek_logs/capture

# 2. Sessions -> features (run on the host):
python scripts/ingest_pcap.py --logdir data/zeek_logs/capture

# Or do both at once (Python shells out to WSL for step 1):
python scripts/ingest_pcap.py --pcap /path/to/capture.pcap --label malicious --family trickbot
```

`scripts/run_zeek.sh` runs `zeek -C -r <pcap> ja4 zeek/splt.zeek`. The reader
(`ingest/zeek_reader.py`) joins `conn.log` + `ssl.log` + `splt.log` + `x509.log` on `uid`
into `Session` objects that flow straight into `features/session.py`.

Committed fixtures in `tests/fixtures/zeek/test/` are real logs from a small TLS 1.3 capture,
so `tests/test_zeek_ingest.py` runs without WSL/Zeek.
