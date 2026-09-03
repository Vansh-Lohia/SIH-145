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

## Quick check

```bash
# Zeek emitting ssl.log from a replayed pcap:
zeek -r data/pcaps/sample.pcap
ls -la ssl.log conn.log x509.log
```
