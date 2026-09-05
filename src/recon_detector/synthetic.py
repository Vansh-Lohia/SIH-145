"""Synthetic strict-one-way flow streams for unit tests and the ``demo`` CLI.

These are controlled A->B-only scenarios (camouflage, evasion, multi-source,
slow scans) with known ground truth -- behavioural regression fixtures, NOT
training data. Real train/eval data comes from Docker capture (see
``portscan-lab/`` and ``simulate_live_stream.py``). Every record here is
observed-direction only -- there is no reverse traffic in these generators.
"""

from __future__ import annotations

import random
from typing import Dict, Iterator, List, Optional

_COMMON_PORTS = [80, 443, 22, 53, 25, 110, 143, 993, 995, 3389, 8080, 8443]


def _record(ts: float, src: str, dst: str, port: int, proto: str = "TCP",
            packets: float = 1.0, byts: float = 0.0, dur: float = 0.0) -> Dict:
    return {
        "timestamp": round(ts, 6),
        "src_ip": src,
        "dst_ip": dst,
        "dst_port": int(port),
        "protocol": proto,
        "packet_count": packets,
        "byte_count": byts,
        "flow_duration": dur,
    }


def benign_traffic(n: int = 200, rng: Optional[random.Random] = None,
                   start: float = 0.0, src: str = "10.0.0.5") -> List[Dict]:
    """Normal client: a handful of hosts, common ports, sizeable flows."""
    rng = rng or random.Random(1)
    hosts = [f"93.184.216.{i}" for i in range(1, 6)]
    out = []
    t = start
    for _ in range(n):
        t += rng.uniform(0.05, 0.6)
        pkts = rng.randint(6, 60)
        out.append(_record(t, src, rng.choice(hosts), rng.choice([80, 443]),
                           packets=pkts, byts=pkts * rng.randint(200, 1400),
                           dur=rng.uniform(0.05, 5.0)))
    return out


def benign_high_fanout(n: int = 300, rng: Optional[random.Random] = None,
                       start: float = 0.0, src: str = "10.0.0.9") -> List[Dict]:
    """Legitimate high fan-out (CDN / update / monitoring): many hosts but on a
    couple of ports and with *substantial* flows -- must NOT be flagged."""
    rng = rng or random.Random(2)
    out = []
    t = start
    for i in range(n):
        t += rng.uniform(0.02, 0.3)
        host = f"151.101.{rng.randint(0, 3)}.{rng.randint(1, 254)}"
        pkts = rng.randint(8, 80)
        out.append(_record(t, src, host, rng.choice([80, 443]),
                           packets=pkts, byts=pkts * rng.randint(300, 1400),
                           dur=rng.uniform(0.1, 8.0)))
    return out


def vertical_scan(n_ports: int = 40, rng: Optional[random.Random] = None,
                  start: float = 0.0, src: str = "45.33.32.156",
                  dst: str = "10.0.0.20", rate: float = 50.0) -> List[Dict]:
    """One source -> one host -> many ports.  Tiny probe flows."""
    rng = rng or random.Random(3)
    out = []
    t = start
    dt = 1.0 / rate if rate > 0 else 0.02
    ports = rng.sample(range(1, 65535), n_ports)
    for p in ports:
        t += dt
        out.append(_record(t, src, dst, p, packets=1.0, byts=0.0, dur=0.0))
    return out


def horizontal_scan(n_hosts: int = 40, port: int = 445,
                    rng: Optional[random.Random] = None, start: float = 0.0,
                    src: str = "45.33.32.157", rate: float = 50.0) -> List[Dict]:
    """One source -> many hosts -> one port.  Tiny probe flows."""
    rng = rng or random.Random(4)
    out = []
    t = start
    dt = 1.0 / rate if rate > 0 else 0.02
    for i in range(n_hosts):
        t += dt
        host = f"10.0.{i // 254}.{(i % 254) + 1}"
        out.append(_record(t, src, host, port, packets=1.0, byts=0.0, dur=0.0))
    return out


def mixed_scan(n_hosts: int = 15, n_ports: int = 15,
               rng: Optional[random.Random] = None, start: float = 0.0,
               src: str = "45.33.32.158", rate: float = 50.0) -> List[Dict]:
    """One source -> many hosts AND many ports."""
    rng = rng or random.Random(5)
    out = []
    t = start
    dt = 1.0 / rate if rate > 0 else 0.02
    ports = rng.sample(range(1, 65535), n_ports)
    for i in range(n_hosts):
        host = f"10.1.{i // 254}.{(i % 254) + 1}"
        for p in ports:
            t += dt
            out.append(_record(t, src, host, p, packets=1.0, byts=0.0, dur=0.0))
    return out


def slow_vertical_scan(n_ports: int = 24, rng: Optional[random.Random] = None,
                       start: float = 0.0, src: str = "45.33.32.160",
                       dst: str = "10.0.0.30", gap: float = 25.0) -> List[Dict]:
    """Vertical scan spread across multiple windows (one probe every ``gap`` s)."""
    rng = rng or random.Random(6)
    out = []
    t = start
    ports = rng.sample(range(1, 65535), n_ports)
    for p in ports:
        t += gap
        out.append(_record(t, src, dst, p, packets=1.0, byts=0.0, dur=0.0))
    return out


def slow_horizontal_scan(n_hosts: int = 24, port: int = 23,
                         rng: Optional[random.Random] = None, start: float = 0.0,
                         src: str = "45.33.32.161", gap: float = 25.0) -> List[Dict]:
    rng = rng or random.Random(7)
    out = []
    t = start
    for i in range(n_hosts):
        t += gap
        host = f"172.16.{i // 254}.{(i % 254) + 1}"
        out.append(_record(t, src, host, port, packets=1.0, byts=0.0, dur=0.0))
    return out


def udp_scan(n_ports: int = 40, rng: Optional[random.Random] = None,
             start: float = 0.0, src: str = "45.33.32.162",
             dst: str = "10.0.0.40", rate: float = 50.0) -> List[Dict]:
    """UDP scan -- non-TCP, tiny flows."""
    rng = rng or random.Random(8)
    out = []
    t = start
    dt = 1.0 / rate if rate > 0 else 0.02
    ports = rng.sample(range(1, 65535), n_ports)
    for p in ports:
        t += dt
        out.append(_record(t, src, dst, p, proto="UDP", packets=1.0, byts=0.0, dur=0.0))
    return out


def camouflaged_scan(n_ports: int = 40, noise: int = 200,
                     rng: Optional[random.Random] = None, start: float = 0.0,
                     src: str = "45.33.32.163", dst: str = "10.0.0.50") -> List[Dict]:
    """Scan probes interleaved with benign-looking larger flows from the same
    source (camouflage)."""
    rng = rng or random.Random(9)
    out = []
    t = start
    ports = rng.sample(range(1, 65535), n_ports)
    scan_i = 0
    for _ in range(n_ports + noise):
        t += rng.uniform(0.01, 0.1)
        if rng.random() < 0.3 and scan_i < len(ports):
            out.append(_record(t, src, dst, ports[scan_i], packets=1.0, byts=0.0, dur=0.0))
            scan_i += 1
        else:
            pkts = rng.randint(6, 40)
            out.append(_record(t, src, f"93.184.216.{rng.randint(1,5)}",
                               rng.choice([80, 443]), packets=pkts,
                               byts=pkts * rng.randint(200, 1400), dur=rng.uniform(0.1, 3.0)))
    out.sort(key=lambda r: r["timestamp"])
    return out


def sparse_traffic(n: int = 5, rng: Optional[random.Random] = None,
                   start: float = 0.0, src: str = "10.0.0.77") -> List[Dict]:
    """A few probe-like flows -- insufficient evidence; must NOT trigger."""
    rng = rng or random.Random(10)
    out = []
    t = start
    for i in range(n):
        t += rng.uniform(10, 30)
        out.append(_record(t, src, f"10.0.0.{100 + i}", rng.choice(_COMMON_PORTS),
                           packets=1.0, byts=0.0, dur=0.0))
    return out


def repeated_persistent_scan(rounds: int = 4, per_round: int = 6,
                             gap: float = 70.0, rng: Optional[random.Random] = None,
                             start: float = 0.0, src: str = "45.33.32.164",
                             dst: str = "10.0.0.60") -> List[Dict]:
    """Same source scans a few new ports every window, across several windows."""
    rng = rng or random.Random(11)
    out = []
    t = start
    used = set()
    for _ in range(rounds):
        for _ in range(per_round):
            t += rng.uniform(0.1, 0.5)
            p = rng.randint(1, 65535)
            while p in used:
                p = rng.randint(1, 65535)
            used.add(p)
            out.append(_record(t, src, dst, p, packets=1.0, byts=0.0, dur=0.0))
        t += gap
    return out


def multi_source_low_rate(n_sources: int = 10, per_source: int = 3,
                          rng: Optional[random.Random] = None, start: float = 0.0,
                          dst: str = "10.0.0.70") -> List[Dict]:
    """Ten sources each probe a few ports.  This component is single-source; it
    is expected to NOT flag the global campaign (documented limitation)."""
    rng = rng or random.Random(12)
    out = []
    t = start
    for s in range(n_sources):
        src = f"185.220.{s}.{rng.randint(1,254)}"
        for _ in range(per_source):
            t += rng.uniform(0.5, 3.0)
            out.append(_record(t, src, dst, rng.randint(1, 65535),
                               packets=1.0, byts=0.0, dur=0.0))
    out.sort(key=lambda r: r["timestamp"])
    return out


SCENARIOS = {
    "A_benign": benign_traffic,
    "B_fast_vertical": vertical_scan,
    "C_fast_horizontal": horizontal_scan,
    "D_mixed": mixed_scan,
    "E_slow_vertical": slow_vertical_scan,
    "F_slow_horizontal": slow_horizontal_scan,
    "G_benign_high_fanout": benign_high_fanout,
    "H_udp_scan": udp_scan,
    "I_camouflaged": camouflaged_scan,
    "J_sparse": sparse_traffic,
    "K_repeated_persistent": repeated_persistent_scan,
    "L_multi_source_low_rate": multi_source_low_rate,
}
