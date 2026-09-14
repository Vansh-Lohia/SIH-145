import json
import matplotlib.pyplot as plt


def plot_detection(alerts_path="alerts_output.json", threshold=5.0, save_path="detection_plot.png"):
    with open(alerts_path) as f:
        alerts = json.load(f)

    windows = list(range(len(alerts)))
    ratios = [a["evidence"]["syn_ack_ratio"] for a in alerts]
    cusum_vals = [a["evidence"]["cusum_value"] for a in alerts]
    fired_idx = [i for i, a in enumerate(alerts) if a["alert"]]
    first_alert = fired_idx[0] if fired_idx else None

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 7), sharex=True)

    ax1.plot(windows, ratios, marker="o", color="#2b6cb0", linewidth=1.5, markersize=4)
    ax1.set_yscale("log")
    ax1.set_ylabel("SYN-only : ACK ratio (log scale)")
    ax1.set_title("Branch A — SYN Flood Detection: Feature Signal & CUSUM Response")
    ax1.grid(True, which="both", alpha=0.3)

    ax2.plot(windows, cusum_vals, marker="o", color="#c53030", linewidth=1.5, markersize=4)
    ax2.axhline(y=threshold, color="black", linestyle="--", linewidth=1, label=f"Alert threshold ({threshold})")
    ax2.set_ylabel("CUSUM value")
    ax2.set_xlabel("Window index (1 window = 1 second)")
    ax2.grid(True, alpha=0.3)
    ax2.legend(loc="upper left")

    if first_alert is not None:
        for ax in (ax1, ax2):
            ax.axvline(x=first_alert, color="darkorange", linestyle=":", linewidth=2)
        ax2.annotate(
            f"ALERT fires\n(window {first_alert})",
            xy=(first_alert, cusum_vals[first_alert]),
            xytext=(first_alert + 1, cusum_vals[first_alert] * 0.6 if cusum_vals[first_alert] > 0 else 5),
            fontsize=9, color="darkorange", fontweight="bold",
        )

    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    print(f"Saved plot to {save_path}")
    if first_alert is not None:
        print(f"Alert first fired at window {first_alert} "
              f"({alerts[first_alert]['timestamp']}), "
              f"confidence={alerts[first_alert]['confidence']}")
    else:
        print("No alert fired in this dataset.")


if __name__ == "__main__":
    plot_detection()