"""
Central configuration for the C2 beaconing baseline pipeline.

IMPORTANT — dataset prerequisite
---------------------------------
This pipeline requires CTU-13 flow records with the following columns
present (this is the schema *after* re-sourcing from the original
CTU-13 .binetflow CSVs; the earlier parquet sample audited in this
project was missing StartTime/SrcAddr/Sport/DstAddr/Dport and cannot
be used as-is — see /areas/sih-c2-detection.md style notes from the
audit conversation):

    StartTime   datetime-parseable flow start timestamp
    SrcAddr     source IP (string)
    Sport       source port (numeric or string)
    DstAddr     destination IP (string)
    Dport       destination port (numeric or string)
    Proto       protocol string (tcp/udp/icmp/...)
    Dur         flow duration, seconds (float)
    State       Argus connection-state string
    sTos, dTos  type-of-service bytes (float, nullable)
    TotPkts     total packets (int)
    TotBytes    total bytes (int)
    SrcBytes    bytes sent by source (int)
    Label       CTU-13 ground-truth label string
    Scenario    scenario identifier, e.g. "1-Neris-20110810" (used for
                the scenario-based split — derive from filename if not
                present as a column)

Column names are matched case-insensitively and common CTU-13 aliases
(dur/proto/dir/state/stos/dtos/tot_pkts/tot_bytes/src_bytes/label,
StartTime/SrcAddr/Sport/DstAddr/Dport/Proto) are normalised in
preprocessing.py.
"""

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Required raw columns (post-normalisation, see preprocessing.normalise_columns)
# ---------------------------------------------------------------------------
REQUIRED_COLUMNS = [
    "start_time", "src_addr", "sport", "dst_addr", "dport", "proto",
    "dur", "state", "tot_pkts", "tot_bytes", "src_bytes", "label",
]

OPTIONAL_COLUMNS = ["stos", "dtos", "scenario"]


# ---------------------------------------------------------------------------
# Label taxonomy (grounded in the label audit performed earlier in this
# project — see /areas/sih-c2-detection.md)
# ---------------------------------------------------------------------------

# Botnet labels carrying an explicit CTU-13 "CC<number>" C2-server tag,
# or an explicit IRC/P2P channel tag. This is the *label-evidence* half
# of the positive-class definition; the *empirical* half (periodicity
# check on the resulting window) is applied later in windowing.py /
# labeling.py.
POSITIVE_LABEL_PATTERNS = [
    r"-CC\d+-",           # explicit numbered C2 server tag
    r"-IRC-",             # IRC-based C2 channel
    r"P2P",               # P2P C2 channel
]

# Botnet-labelled but NOT used as positives (ambiguous / non-beaconing
# malicious activity: scanning attempts, spam relay, ad-fraud, ICMP,
# bare DNS lookups). Held out into a separate stress-test bucket rather
# than forced into either class.
EXCLUDED_BOTNET_PATTERNS = [
    r"TCP-Attempt", r"UDP-Attempt",
    r"SPAM",
    r"HTTP-Ad-", r"HTTP-Adobe",
    r"-ICMP", r"ICMP-",
    r"UDP-DNS",
]

NORMAL_LABEL_PATTERN = r"From-Normal-"
BACKGROUND_LABEL_PATTERN = r"Background"
BOTNET_LABEL_PATTERN = r"Botnet"


# ---------------------------------------------------------------------------
# Windowing parameters (see the windowing-methodology discussion earlier
# in this project). Not tuned — starting points to be validated
# empirically once real inter-arrival distributions are available.
# ---------------------------------------------------------------------------
@dataclass
class WindowConfig:
    window_seconds: int = 900          # 15-minute window (middle-ground default)
    step_seconds: int = 180            # step = window/5, overlapping windows
    min_flows_for_prediction: int = 3  # hard floor; below this -> no prediction
    min_flows_for_confidence: int = 6  # below this, flag low-confidence
    inactivity_expiry_seconds: int = 3600  # conv_id state eviction (real-time mode)


# ---------------------------------------------------------------------------
# Scenario-based split (explicit, not random — see splitting.py).
# CTU-13 scenario numbers grouped so that malware *families* do not
# straddle the split (Neris: 1,2,9 | Rbot: 3,4,10,11 | Virut: 5,13 |
# Menti: 6 | Sogou: 7 | Murlo: 8 | NsisAy: 12).
# ---------------------------------------------------------------------------
@dataclass
class SplitConfig:
    train_scenarios: tuple = ("3-Rbot", "4-Rbot", "1-Neris", "2-Neris",
                               "8-Murlo", "6-Menti")
    val_scenarios: tuple = ("10-Rbot", "9-Neris", "5-Virut")
    test_scenarios: tuple = ("11-Rbot", "13-Virut", "12-NsisAy", "7-Sogou")


WINDOW_CFG = WindowConfig()
SPLIT_CFG = SplitConfig()

RANDOM_SEED = 42
