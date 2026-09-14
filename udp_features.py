from scapy.all import rdpcap, UDP, IP
from collections import defaultdict

ABUSED_PORTS = {53, 123, 1900, 11211, 19, 161}  # DNS, NTP, SSDP, memcached, chargen, SNMP


def windowed_udp_features(pcap_path, window_size=1.0, victim_ip=None,
                           large_pkt_threshold=150, lookback=30.0,
                           baseline_windows=3):
    """
    Bucket UDP packets into time windows and compute Branch B (UDP
    reflection/amplification) features per window.

    Branch-specific:
      - rate: UDP packets/sec (feed to CUSUM as the hot-path signal)
      - avg_size: average UDP payload size (reflection responses skew large)
      - port_score: fraction of packets touching a known-abused-service port
      - orphan_score: fraction of large inbound responses to `victim_ip`
        with no matching prior outbound query within `lookback` seconds

    Shared feature layer (same mechanism as Branch A, applied to UDP traffic):
      - fan_in: distinct source IPs seen this window
      - max_source_share: (packets from top source) / (total packets)
      - ttl_deviation: average |observed_ttl - baseline_ttl| per source,
        baseline learned from the first `baseline_windows` windows
    """
    packets = rdpcap(pcap_path)
    if len(packets) == 0:
        return []

    udp_packets = [p for p in packets if IP in p and UDP in p]
    if len(udp_packets) == 0:
        return []

    if victim_ip is None:
        dest_counts = defaultdict(int)
        for p in udp_packets:
            dest_counts[p[IP].dst] += 1
        victim_ip = max(dest_counts, key=dest_counts.get)

    start_time = float(udp_packets[0].time)
    windows = defaultdict(lambda: {"total": 0, "bytes": 0, "port_match": 0})
    outbound_queries = []
    inbound_responses_per_window = defaultdict(list)
    windows_srcs = defaultdict(lambda: defaultdict(int))
    ttl_by_window_src = defaultdict(lambda: defaultdict(list))

    for pkt in udp_packets:
        t = float(pkt.time) - start_time
        idx = int(t // window_size)
        src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport
        size = len(pkt[UDP])
        ttl = pkt[IP].ttl

        windows[idx]["total"] += 1
        windows[idx]["bytes"] += size
        if src_port in ABUSED_PORTS or dst_port in ABUSED_PORTS:
            windows[idx]["port_match"] += 1

        windows_srcs[idx][src_ip] += 1
        ttl_by_window_src[idx][src_ip].append(ttl)

        if src_ip == victim_ip:
            outbound_queries.append((t, dst_ip, dst_port))
        if dst_ip == victim_ip and size >= large_pkt_threshold:
            inbound_responses_per_window[idx].append((t, src_ip, src_port, size))

    sorted_indices = sorted(windows.keys())

    baseline_ttls = defaultdict(list)
    for idx in sorted_indices[:baseline_windows]:
        for src, ttls in ttl_by_window_src[idx].items():
            baseline_ttls[src].extend(ttls)
    baseline_avg = {s: sum(t) / len(t) for s, t in baseline_ttls.items()}

    results = []
    for idx in sorted_indices:
        w = windows[idx]
        rate = w["total"] / window_size
        avg_size = w["bytes"] / w["total"] if w["total"] else 0
        port_score = w["port_match"] / w["total"] if w["total"] else 0

        responses = inbound_responses_per_window[idx]
        orphan_count = 0
        for (t, r_src_ip, r_src_port, size) in responses:
            matched = any(
                dst_ip == r_src_ip and dst_port == r_src_port and 0 <= (t - qt) <= lookback
                for qt, dst_ip, dst_port in outbound_queries
            )
            if not matched:
                orphan_count += 1
        orphan_score = orphan_count / len(responses) if responses else 0.0

        srcs = windows_srcs[idx]
        total_src_pkts = sum(srcs.values())
        fan_in = len(srcs)
        max_source_share = max(srcs.values()) / total_src_pkts if total_src_pkts else 0.0

        deviations = []
        for src, ttls in ttl_by_window_src[idx].items():
            if src in baseline_avg:
                obs_avg = sum(ttls) / len(ttls)
                deviations.append(abs(obs_avg - baseline_avg[src]))
        ttl_deviation = sum(deviations) / len(deviations) if deviations else 0.0

        results.append({
            "window_start": round(idx * window_size, 2),
            "total_pkts": w["total"],
            "rate": round(rate, 1),
            "avg_size": round(avg_size, 1),
            "port_score": round(port_score, 3),
            "orphan_score": round(orphan_score, 3),
            "fan_in": fan_in,
            "max_source_share": round(max_source_share, 3),
            "ttl_deviation": round(ttl_deviation, 2),
        })
    return results


if __name__ == "__main__":
    print(f"\n=== captures/dns_flood3.pcap ===")
    for row in windowed_udp_features("captures/dns_flood3.pcap", victim_ip="172.18.0.2"):
        print(row)