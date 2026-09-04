"""
demo_data.py
============
Generates a small SYNTHETIC dataset matching the required schema
(StartTime/SrcAddr/Sport/DstAddr/Dport/Proto/Dur/State/TotPkts/TotBytes/
SrcBytes/Label/Scenario), purely so the pipeline can be executed
end-to-end and smoke-tested right now.

*** THIS IS NOT REAL CTU-13 DATA AND PRODUCES NO SCIENTIFICALLY VALID
RESULTS. *** It exists only because the CTU-13 sample actually audited
earlier in this project is missing StartTime/SrcAddr/Sport/DstAddr/
Dport (see config.py docstring) and could not be used to demonstrate
the windowing/feature/labeling logic. Once you have re-sourced the real
CTU-13 CSVs with those columns restored, point run_pipeline.py at the
real files with --data-dir instead of --demo and ignore this module.

The generator creates, per synthetic "scenario":
  - a handful of regular-interval "beacon" conversations, labelled with
    a CC-tagged Botnet string (-> label_bucket 'positive_candidate')
  - a handful of irregular-interval "normal" conversations, labelled
    From-Normal-* (-> label_bucket 'normal')
  - a handful of many-destination "noisy" conversations from the same
    hosts, labelled with an excluded Botnet sub-pattern (SPAM) to
    exercise the excluded/stress-test path
  - some genuinely periodic BUT benign conversations (simulated NTP-like
    heartbeats), also From-Normal-*, to exercise the "periodic negative"
    case the label strategy is specifically designed to handle correctly
"""

from __future__ import annotations
import numpy as np
import pandas as pd


def _make_conversation(rng, start, n_flows, interval_mean, interval_jitter,
                        src_addr, dst_addr, dport, proto, label,
                        byte_mean=500, byte_jitter=50):
    times = [start]
    for _ in range(n_flows - 1):
        gap = max(0.5, rng.normal(interval_mean, interval_jitter))
        times.append(times[-1] + pd.Timedelta(seconds=gap))
    tot_bytes = np.clip(rng.normal(byte_mean, byte_jitter, n_flows), 40, None)
    tot_pkts = np.clip((tot_bytes / 60).round(), 1, None)
    src_bytes = tot_bytes * rng.uniform(0.3, 0.6, n_flows)
    dur = np.clip(rng.normal(0.8, 0.3, n_flows), 0.01, None)
    states = rng.choice(["CON", "FSPA_FSPA", "S_RA"], size=n_flows, p=[0.7, 0.2, 0.1])
    return pd.DataFrame({
        "StartTime": times,
        "SrcAddr": src_addr,
        "Sport": rng.integers(1024, 65535, n_flows).astype(str),
        "DstAddr": dst_addr,
        "Dport": str(dport),
        "Proto": proto,
        "Dur": dur,
        "State": states,
        "sTos": 0.0,
        "dTos": 0.0,
        "TotPkts": tot_pkts.astype(int),
        "TotBytes": tot_bytes.astype(int),
        "SrcBytes": src_bytes.astype(int),
        "Label": label,
    })


def generate_demo_scenario(scenario_name: str, seed: int,
                            n_beacon_conv: int = 3,
                            n_normal_conv: int = 3,
                            n_noisy_conv: int = 2,
                            n_periodic_benign_conv: int = 2,
                            flows_per_conv: int = 40) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    base_time = pd.Timestamp("2011-08-10 10:00:00")
    frames = []

    beacon_intervals = [30, 60, 120]
    for i in range(n_beacon_conv):
        src = f"10.0.{seed}.{10+i}"
        dst = f"91.203.{seed}.{5+i}"
        interval = beacon_intervals[i % len(beacon_intervals)]
        label = f"flow=From-Botnet-V{40+i}-TCP-CC{16+i}-HTTP-Not-Encrypted"
        frames.append(_make_conversation(
            rng, base_time, flows_per_conv, interval, interval * 0.05,
            src, dst, dport=8080 + i, proto="tcp", label=label,
        ))

    for i in range(n_normal_conv):
        src = f"10.0.{seed}.{60+i}"
        dst = f"172.16.{seed}.{20+i}"
        frames.append(_make_conversation(
            rng, base_time, flows_per_conv,
            interval_mean=rng.uniform(20, 500), interval_jitter=rng.uniform(50, 300),
            src_addr=src, dst_addr=dst, dport=443, proto="tcp",
            label="flow=From-Normal-V49-Stribrek",
        ))

    for i in range(n_noisy_conv):
        src = f"10.0.{seed}.{10+i}"  # SAME infected hosts as beacon convs
        for j in range(5):
            dst = f"203.0.{seed}.{j}"
            frames.append(_make_conversation(
                rng, base_time, 4,
                interval_mean=rng.uniform(5, 60), interval_jitter=rng.uniform(1, 20),
                src_addr=src, dst_addr=dst, dport=25, proto="tcp",
                label=f"flow=From-Botnet-V{40+i}-TCP-Attempt-SPAM",
            ))

    for i in range(n_periodic_benign_conv):
        src = f"10.0.{seed}.{90+i}"
        dst = f"129.6.15.{28+i}"  # NTP-pool-like address
        # NOTE (fix, Experiment 4): this block previously used a
        # "Background"-prefixed label, which bucket_label() correctly
        # routes to 'background' -- and labeling.py's strict rule then
        # EXCLUDES 'background' windows from both train and eval
        # entirely. That meant the one traffic pattern the label
        # strategy was specifically designed to reject (periodic-but-
        # benign heartbeat traffic) was never actually present in the
        # confirmed negative class, so the reported FPR=0.0 provided no
        # real evidence about it. Using a "From-Normal-" label instead
        # correctly buckets these as 'normal', so labeling.py accepts
        # them into the confirmed NEGATIVE class (per the agreed rule:
        # a periodic-but-benign window is still a negative example).
        frames.append(_make_conversation(
            rng, base_time, flows_per_conv, interval_mean=64, interval_jitter=2,
            src_addr=src, dst_addr=dst, dport=123, proto="udp",
            label=f"flow=From-Normal-V{90+i}-NTP-heartbeat",
            byte_mean=90, byte_jitter=5,
        ))

    df = pd.concat(frames, ignore_index=True)
    df["Scenario"] = scenario_name
    return df


def generate_demo_dataset() -> pd.DataFrame:
    scenarios = [
        ("1-Neris-DEMO", 1), ("3-Rbot-DEMO", 2), ("8-Murlo-DEMO", 3),
        ("10-Rbot-DEMO", 4), ("9-Neris-DEMO", 5), ("5-Virut-DEMO", 6),
        ("11-Rbot-DEMO", 7), ("13-Virut-DEMO", 8), ("12-NsisAy-DEMO", 9),
        ("7-Sogou-DEMO", 10), ("2-Neris-DEMO", 11), ("6-Menti-DEMO", 12),
    ]
    frames = [generate_demo_scenario(name, seed) for name, seed in scenarios]
    return pd.concat(frames, ignore_index=True)
