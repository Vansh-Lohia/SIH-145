from scapy.all import rdpcap, TCP, IP
from collections import defaultdict

def classify_flags(pkt):
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

def windowed_features(pcap_path, window_size=1.0):
    """
    Bucket packets into fixed-size time windows and compute per-window
    SYN-flood-relevant counts. Keyed loosely on dest_ip for now — in the
    real pipeline this becomes (dest_ip, protocol) per the design doc.
    """
    packets = rdpcap(pcap_path)
    if len(packets) == 0:
        return []

    start_time = float(packets[0].time)
    windows = defaultdict(lambda: {"total": 0, "SYN_ONLY": 0, "ACK": 0, "FIN": 0, "SYN_ACK": 0, "RST": 0})

    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue
        window_idx = int((float(pkt.time) - start_time) // window_size)
        label = classify_flags(pkt)
        if label:
            windows[window_idx]["total"] += 1
            windows[window_idx][label] += 1

    results = []
    for idx in sorted(windows.keys()):
        w = windows[idx]
        # ratio: SYN-only attempts vs completed sessions (ACK-carrying), avoid div-by-zero
        ratio = w["SYN_ONLY"] / (w["ACK"] + 1)
        results.append({
            "window_start": round(idx * window_size, 2),
            "total_pkts": w["total"],
            "syn_only": w["SYN_ONLY"],
            "ack": w["ACK"],
            "ratio": round(ratio, 3)
        })
    return results

if __name__ == "__main__":
    for name in ["captures/benign.pcap", "captures/syn_flood.pcap"]:
        print(f"\n=== {name} ===")
        for row in windowed_features(name):
            print(row)