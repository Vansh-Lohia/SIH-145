import math


def cusum_detect_adaptive(rows, initial_baseline_windows=5, k=0.5, threshold=5.0,
                           relearn_every=10, relearn_window=10):
    """
    Same CUSUM change-point logic as cusum_detect(), but the baseline
    (mu, sigma) is periodically RE-ESTIMATED from recent traffic instead
    of being learned once and frozen forever.

    Only non-alerting windows feed back into the rolling baseline buffer,
    so a sustained attack can't slowly get relearned as "normal."
    """
    mu, sigma = None, None
    recent_normal_log_values = []
    cusum = 0.0
    results = []

    for i, row in enumerate(rows):
        x = math.log1p(row["ratio"])

        if mu is None:
            recent_normal_log_values.append(x)
            results.append({"window": i, "ratio": row["ratio"], "cusum": 0.0,
                             "alert": False, "mu": None, "sigma": None,
                             "phase": "bootstrapping"})
            if len(recent_normal_log_values) >= initial_baseline_windows:
                mu = sum(recent_normal_log_values) / len(recent_normal_log_values)
                var = sum((v - mu) ** 2 for v in recent_normal_log_values) / len(recent_normal_log_values)
                sigma = math.sqrt(var) if var > 0 else 0.01
            continue

        deviation = (x - mu) / sigma
        if deviation <= 0:
            cusum = 0.0
        else:
            cusum = max(0.0, cusum + deviation - k)
        fired = cusum > threshold

        if not fired:
            recent_normal_log_values.append(x)
            recent_normal_log_values = recent_normal_log_values[-relearn_window:]

        if i % relearn_every == 0 and len(recent_normal_log_values) >= 3:
            mu = sum(recent_normal_log_values) / len(recent_normal_log_values)
            var = sum((v - mu) ** 2 for v in recent_normal_log_values) / len(recent_normal_log_values)
            sigma = math.sqrt(var) if var > 0 else 0.01

        results.append({"window": i, "ratio": row["ratio"], "cusum": round(cusum, 2),
                         "alert": fired, "mu": round(mu, 3), "sigma": round(sigma, 3),
                         "phase": "active"})

    return results


if __name__ == "__main__":
    rows = (
        [{"ratio": 0.5} for _ in range(10)] +
        [{"ratio": 50.0} for _ in range(5)] +
        [{"ratio": 0.5} for _ in range(15)] +
        [{"ratio": 60.0} for _ in range(5)] +
        [{"ratio": 0.5} for _ in range(5)]
    )

    results = cusum_detect_adaptive(rows, initial_baseline_windows=5, relearn_every=5, relearn_window=8)

    for r in results:
        marker = " <-- ALERT" if r["alert"] else ""
        print(f"w{r['window']:>2} ratio={r['ratio']:>5} cusum={r['cusum']:>7} "
              f"mu={r['mu']} sigma={r['sigma']} [{r['phase']}]{marker}")

    alert_windows = [r["window"] for r in results if r["alert"]]
    print(f"\nAlert windows: {alert_windows}")