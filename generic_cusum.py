import json
from adaptive_cusum import cusum_detect_adaptive
from generic_features import windowed_generic_features


def run_generic_branch(dest_ip="10.0.0.5"):
    benign = windowed_generic_features("captures/benign.pcap")
    attack = windowed_generic_features("captures/generic_flood.pcap")
    rows = [{**r, "ratio": r["rate"]} for r in (benign + attack)]

    results = cusum_detect_adaptive(rows, initial_baseline_windows=5,
                                     relearn_every=10, relearn_window=10)

    alerts = []
    for i, (r, row) in enumerate(zip(results, rows)):
        confidence = round(min(r["cusum"] / 5.0, 1.0), 3) if r["cusum"] else 0.0
        alerts.append({
            "flow_id": f"{dest_ip}-GENERIC-w{i}",
            "threat_class": "generic_volumetric_spoofed",
            "confidence": confidence,
            "alert": r["alert"],
            "evidence": {
                "packet_rate_per_sec": row["rate"],
                "fan_in": row["fan_in"],
                "max_source_share": row["max_source_share"],
                "ttl_deviation": row["ttl_deviation"],
                "cusum_value": r["cusum"],
            },
        })
    return alerts


if __name__ == "__main__":
    alerts = run_generic_branch()
    for a in alerts:
        print(json.dumps(a, indent=2))

    with open("generic_alerts_output.json", "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"\nSaved {len(alerts)} generic-volumetric alert records to generic_alerts_output.json")