import math
import json
from datetime import datetime, timedelta


def cusum_detect(rows, baseline_windows=5, k=0.5, threshold=5.0,
                  dest_ip="10.0.0.5", protocol="TCP",
                  threat_class="volumetric_ddos_syn_flood",
                  ratio_field_name="syn_ack_ratio"):
    """
    Runs CUSUM change-point detection on the SYN-only/ACK ratio, and emits
    one structured alert record per window in the schema the problem
    statement requires: timestamp, flow identifier, threat class,
    confidence score, and supporting evidence.
    """
    ratios = [r["ratio"] for r in rows]
    log_ratios = [math.log1p(r) for r in ratios]

    baseline_vals = log_ratios[:baseline_windows]
    mu = sum(baseline_vals) / len(baseline_vals)
    variance = sum((x - mu) ** 2 for x in baseline_vals) / len(baseline_vals)
    sigma = math.sqrt(variance) if variance > 0 else 0.01

    cusum = 0.0
    alerts = []
    sim_start = datetime.utcnow()

    for i, row in enumerate(rows):
        x = log_ratios[i]
        deviation = (x - mu) / sigma
        if deviation <= 0:
            cusum = 0.0
        else:
            cusum = max(0.0, cusum + deviation - k)
        fired = cusum > threshold

        confidence = round(min(cusum / threshold, 1.0), 3) if fired else round(
            min(cusum / threshold, 0.99), 3
        )

        record = {
            "timestamp": (sim_start + timedelta(seconds=i)).isoformat() + "Z",
            "flow_id": f"{dest_ip}-{protocol}-w{i}",
            "threat_class": threat_class,
            "confidence": confidence,
            "alert": fired,
            "evidence": {
                ratio_field_name: row["ratio"],
                "packet_rate_per_sec": row["packet_rate"],
                "ttl_deviation": row["ttl_deviation"],
                "cusum_value": round(cusum, 2),
                "total_packets": row["total_pkts"],
            },
        }
        alerts.append(record)

    return alerts


if __name__ == "__main__":
    from windowed_features import windowed_features

    benign = windowed_features("captures/benign.pcap")
    flood = windowed_features("captures/syn_flood.pcap")
    combined_rows = benign + flood

    alerts = cusum_detect(combined_rows, baseline_windows=5)

    for a in alerts:
        print(json.dumps(a, indent=2))

    with open("alerts_output.json", "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"\nSaved {len(alerts)} alert records to alerts_output.json")