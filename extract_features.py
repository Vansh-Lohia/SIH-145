from scapy.all import rdpcap, TCP

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

def count_flags(pcap_path):
    packets = rdpcap(pcap_path)
    counts = {}
    for pkt in packets:
        label = classify_flags(pkt)
        if label:
            counts[label] = counts.get(label, 0) + 1
    return counts, len(packets)

if __name__ == "__main__":
    for name in ["captures/benign.pcap", "captures/syn_flood.pcap"]:
        counts, total = count_flags(name)
        print(f"\n{name}  (total packets: {total})")
        for label, c in sorted(counts.items(), key=lambda x: -x[1]):
            print(f"  {label:10s} {c}")