import math

def cusum_detect(ratios, baseline_windows=5, k=0.5, threshold=5.0):
    """
    ratios: list of per-window ratio values, in time order
    baseline_windows: how many initial windows to use for learning 'normal'
    k: slack parameter — how much deviation to tolerate before it counts
    threshold: cumulative sum level that triggers an alert
    """
    log_ratios = [math.log1p(r) for r in ratios]

    baseline_vals = log_ratios[:baseline_windows]
    mu = sum(baseline_vals) / len(baseline_vals)
    variance = sum((x - mu) ** 2 for x in baseline_vals) / len(baseline_vals)
    sigma = math.sqrt(variance) if variance > 0 else 0.01  # avoid div-by-zero on a too-clean baseline

    cusum = 0.0
    results = []
    for i, x in enumerate(log_ratios):
        deviation = (x - mu) / sigma
        cusum = max(0.0, cusum + deviation - k)
        alert = cusum > threshold
        results.append({
            "window": i,
            "ratio": round(ratios[i], 3),
            "cusum": round(cusum, 2),
            "ALERT": alert
        })
    return results


if __name__ == "__main__":
    from windowed_features import windowed_features  # reuse your existing function

    benign = windowed_features("captures/benign.pcap")
    flood = windowed_features("captures/syn_flood.pcap")

    # simulate one continuous stream: benign traffic, then attack begins
    combined_ratios = [w["ratio"] for w in benign] + [w["ratio"] for w in flood]

    detection = cusum_detect(combined_ratios, baseline_windows=5)
    for row in detection:
        print(row)