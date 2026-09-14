from scapy.all import rdpcap, IP
from collections import defaultdict


def windowed_generic_features(pcap_path, window_size=1.0, baseline_windows=3):
    """
    Branch C (generic volumetric / spoofed-source catch-all) feature
    extraction. Protocol-agnostic -- uses only the shared feature layer,
    no TCP-flag or UDP-port logic.

    Note on ttl_deviation: it catches IDENTITY IMPERSONATION (spoofing a
    known/previously-seen IP), not novel/random addresses -- a brand-new
    fake source has no baseline to deviate from. fan_in and
    max_source_share are what carry the signal for a --rand-source-style
    flood using thousands of never-before-seen fake addresses.
    """
    packets = rdpcap(pcap_path)
    if len(packets) == 0:
        return []

    ip_packets = [p for p in packets if IP in p]
    if len(ip_packets) == 0:
        return []

    start_time = float(ip_packets[0].time)
    windows_srcs = defaultdict(lambda: defaultdict(int))
    ttl_by_window_src = defaultdict(lambda: defaultdict(list))

    for pkt in ip_packets:
        t = float(pkt.time) - start_time
        idx = int(t // window_size)
        src_ip = pkt[IP].src
        ttl = pkt[IP].ttl
        windows_srcs[idx][src_ip] += 1
        ttl_by_window_src[idx][src_ip].append(ttl)

    sorted_idx = sorted(windows_srcs.keys())
    baseline_ttls = defaultdict(list)
    for idx in sorted_idx[:baseline_windows]:
        for src, ttls in ttl_by_window_src[idx].items():
            baseline_ttls[src].extend(ttls)
    baseline_avg = {s: sum(t) / len(t) for s, t in baseline_ttls.items()}

    results = []
    for idx in sorted_idx:
        srcs = windows_srcs[idx]
        total = sum(srcs.values())
        fan_in = len(srcs)
        max_source_share = max(srcs.values()) / total if total else 0.0
        rate = total / window_size

        deviations = []
        for src, ttls in ttl_by_window_src[idx].items():
            if src in baseline_avg:
                obs = sum(ttls) / len(ttls)
                deviations.append(abs(obs - baseline_avg[src]))
        ttl_deviation = sum(deviations) / len(deviations) if deviations else 0.0

        results.append({
            "window_start": round(idx * window_size, 2),
            "total_pkts": total,
            "rate": round(rate, 1),
            "fan_in": fan_in,
            "max_source_share": round(max_source_share, 4),
            "ttl_deviation": round(ttl_deviation, 2),
        })
    return results


if __name__ == "__main__":
    benign = windowed_generic_features("captures/benign.pcap")
    attack = windowed_generic_features("captures/generic_flood.pcap")
    print("=== benign.pcap (first 3 windows) ===")
    for row in benign[:3]:
        print(row)
    print("\n=== generic_flood.pcap (first 3 windows) ===")
    for row in attack[:3]:
        print(row)