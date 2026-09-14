import json
from cusum_detector import cusum_detect
from udp_features import windowed_udp_features


def prepare_for_cusum(udp_rows):
    return [
        {
            "window_start": r["window_start"],
            "total_pkts": r["total_pkts"],
            "ratio": r["rate"],
            "packet_rate": r["rate"],
            "ttl_deviation": r["ttl_deviation"],
            "orphan_score": r.get("orphan_score", 0.0),
            "port_score": r.get("port_score", 0.0),
        }
        for r in udp_rows
    ]


def blend_confidence(alerts, source_rows, w_cusum=0.6, w_orphan=0.2, w_port=0.2):
    """
    cusum_detect() only knows about the rate signal (it's the shared,
    branch-agnostic detector). This layers in Branch B's other two
    features -- orphan_score and port_score -- into a final confidence,
    matching the weighted-fusion formula from the design doc.
    """
    for alert, row in zip(alerts, source_rows):
        cusum_conf = alert["confidence"]
        orphan = row.get("orphan_score", 0.0)
        port = row.get("port_score", 0.0)

        blended = w_cusum * cusum_conf + w_orphan * orphan + w_port * port
        alert["confidence"] = round(min(blended, 1.0), 3)
        alert["evidence"]["orphan_score"] = orphan
        alert["evidence"]["port_score"] = port
    return alerts


if __name__ == "__main__":
    quiet_rows = windowed_udp_features("captures/legit_udp.pcap", victim_ip="172.18.0.2")
    attack_rows = windowed_udp_features("captures/dns_flood3.pcap", victim_ip="172.18.0.2")
    combined_rows = quiet_rows + attack_rows

    prepared = prepare_for_cusum(combined_rows)

    alerts = cusum_detect(prepared, baseline_windows=len(quiet_rows), dest_ip="172.18.0.2",
                           protocol="UDP", threat_class="udp_reflection_amplification",
                           ratio_field_name="udp_rate")
    alerts = blend_confidence(alerts, prepared)

    for a in alerts:
        print(json.dumps(a, indent=2))

    with open("udp_alerts_output.json", "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"\nSaved {len(alerts)} UDP alert records to udp_alerts_output.json")