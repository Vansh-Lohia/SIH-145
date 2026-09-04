"""Ingest one pcap end-to-end: Zeek logs -> Session objects -> featurize (CLAUDE.md step 1).

Two modes:
  --logdir DIR   consume an existing directory of Zeek logs (conn/ssl/splt/x509)
  --pcap FILE    run Zeek first (via WSL) into a fresh log dir, then consume it

Prints a summary proving the real output flows through features/session.py: session count,
feature-family availability, the real JA4 fingerprints seen, and one full FeatureBundle.

Examples:
  python scripts/ingest_pcap.py --logdir data/zeek_logs/test
  python scripts/ingest_pcap.py --pcap /home/me/x.pcap --label malicious --family trickbot
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from encdetect.ingest.zeek_reader import sessions_from_log_dir  # noqa: E402
from encdetect.features.session import featurize  # noqa: E402


def _win_to_wsl(p: str) -> str:
    """Translate C:\\x -> /mnt/c/x so a Windows path works inside WSL."""
    p = str(p)
    if len(p) > 2 and p[1] == ":":
        return "/mnt/" + p[0].lower() + p[2:].replace("\\", "/")
    return p.replace("\\", "/")


def run_zeek_via_wsl(pcap: str, out_dir: Path, distro: str = "Ubuntu") -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    script = _win_to_wsl(str(ROOT / "scripts" / "run_zeek.sh"))
    cmd = ["wsl.exe", "-d", distro, "-e", "bash", "-lc",
           f'bash "{script}" "{_win_to_wsl(pcap)}" "{_win_to_wsl(str(out_dir))}"']
    print(f"$ {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--logdir", help="existing Zeek log directory")
    ap.add_argument("--pcap", help="pcap to run Zeek over first (via WSL)")
    ap.add_argument("--distro", default="Ubuntu", help="WSL distro name (default: Ubuntu)")
    ap.add_argument("--label", default="", help="benign|malicious (from labels sidecar)")
    ap.add_argument("--family", default="")
    ap.add_argument("--environment", default="")
    args = ap.parse_args()

    if args.pcap:
        log_dir = Path(args.logdir) if args.logdir else ROOT / "data" / "zeek_logs" / \
            Path(args.pcap).stem
        run_zeek_via_wsl(args.pcap, log_dir, args.distro)
    elif args.logdir:
        log_dir = Path(args.logdir)
    else:
        ap.error("provide --logdir or --pcap")

    pcap_name = Path(args.pcap).name if args.pcap else log_dir.name
    sessions = sessions_from_log_dir(
        log_dir, label=args.label, family=args.family,
        environment=args.environment, pcap=pcap_name)

    print("=" * 72)
    print(f"Ingested {len(sessions)} TLS/QUIC session(s) from {log_dir}")
    if not sessions:
        print("No ssl.log sessions found — is this a TLS pcap? Did Zeek emit ssl.log?")
        return

    bundles = [featurize(s) for s in sessions]

    fams = ("shape", "handshake", "certificate")
    avail = {k: sum(b.availability[k] for b in bundles) / len(bundles) for k in fams}
    print("feature-family availability: "
          + ", ".join(f"{k}={v:.0%}" for k, v in avail.items()))

    print("\nreal JA4 fingerprints seen (FoxIO, from ssl.log):")
    for ja4, n in Counter(b.ja4 for b in bundles).most_common(10):
        print(f"  {n:4d}  {ja4}")

    b = bundles[0]
    s = sessions[0]
    print(f"\nsample session: {s.flow.src_ip}:{s.flow.src_port} -> "
          f"{s.flow.dst_ip}:{s.flow.dst_port} {s.flow.proto}  ({s.tls_version_str})")
    print(f"  ja4  = {s.ja4_precomputed}")
    print(f"  ja4s = {s.ja4s}")
    print(f"  packets captured for SPLT: {len(s.packets)}")
    print("  tabular features:")
    for k in sorted(b.tabular):
        print(f"    {k:24s} {b.tabular[k]}")
    print(f"  SPLT sequence (first 6 of {len(b.sequence)}): {b.sequence[:6]}")
    print("\nOK — real Zeek output flowed end to end through features/session.py.")


if __name__ == "__main__":
    main()
