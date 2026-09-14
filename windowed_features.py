from scapy.all import rdpcap, TCP, IP
from collections import defaultdict


def classify_flags(pkt):
    """Return a short string label for a TCP packet's flag combination."""
    if TCP not in pkt:
        return None
    flags = pkt[TCP].flags
    syn = flags & 0x02 != 0
    ack = flags & 0x10 != 0
    fin = flags & 0x01 != 0
    rst = flags & 0x04 != 0

    if syn and not ack:
        return "SYN_ONLY"
    elif syn and ack:
        return "SYN_ACK"
    elif fin:
        return "FIN"
    elif rst:
        return "RST"
    elif ack:
        return "ACK"
    else:
        return "OTHER"


def windowed_features(pcap_path, window_size=1.0, baseline_windows=3):
    """
    Bucket packets into fixed-size time windows and compute per-window
    SYN-flood-relevant counts, plus two extra evidence features:

      - packet_rate: packets/sec in this window (raw volumetric signal)
      - ttl_deviation: average |observed_ttl - baseline_ttl| per source IP,
        where baseline_ttl is learned per-source from the first
        `baseline_windows` windows. Near-zero in a non-spoofed lab setup
        (expected/correct here); would spike on a real spoofed attack
        where forged packets don't match the real host's TTL fingerprint.
    """
    packets = rdpcap(pcap_path)
    if len(packets) == 0:
        return []

    start_time = float(packets[0].time)

    windows = defaultdict(lambda: {
        "total": 0, "SYN_ONLY": 0, "ACK": 0, "FIN": 0, "SYN_ACK": 0, "RST": 0
    })
    ttl_by_window_src = defaultdict(lambda: defaultdict(list))

    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue
        window_idx = int((float(pkt.time) - start_time) // window_size)
        label = classify_flags(pkt)
        if label:
            windows[window_idx]["total"] += 1
            windows[window_idx][label] += 1

        src_ip = pkt[IP].src
        ttl = pkt[IP].ttl
        ttl_by_window_src[window_idx][src_ip].append(ttl)

    sorted_indices = sorted(windows.keys())

    baseline_ttls = defaultdict(list)
    for idx in sorted_indices[:baseline_windows]:
        for src, ttls in ttl_by_window_src[idx].items():
            baseline_ttls[src].extend(ttls)
    baseline_avg = {
        src: sum(ttls) / len(ttls)
        for src, ttls in baseline_ttls.items()
    }

    results = []
    for idx in sorted_indices:
        w = windows[idx]
        ratio = w["SYN_ONLY"] / (w["ACK"] + 1)
        packet_rate = w["total"] / window_size

        deviations = []
        for src, ttls in ttl_by_window_src[idx].items():
            if src in baseline_avg:
                obs_avg = sum(ttls) / len(ttls)
                deviations.append(abs(obs_avg - baseline_avg[src]))
        ttl_deviation = sum(deviations) / len(deviations) if deviations else 0.0

        results.append({
            "window_start": round(idx * window_size, 2),
            "total_pkts": w["total"],
            "syn_only": w["SYN_ONLY"],
            "ack": w["ACK"],
            "ratio": round(ratio, 3),
            "packet_rate": round(packet_rate, 1),
            "ttl_deviation": round(ttl_deviation, 2),
        })
    return results


if __name__ == "__main__":
    for name in ["captures/benign.pcap", "captures/syn_flood.pcap"]:
        print(f"\n=== {name} ===")
        for row in windowed_features(name):
            print(row)