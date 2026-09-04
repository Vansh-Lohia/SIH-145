"""Splitters enforcing the evaluation rules (CLAUDE.md §7).

These are the guardrail against the environment artifact that collapsed our DGA module
(recall 95.6% -> ~0% under a held-out-family test). They operate on the group labels
(`pcap`, `family`, `environment`) carried through the pipeline from the labels sidecar
(CLAUDE.md §8).

A "record" here is any object exposing `.pcap`, `.family`, `.label` (e.g. a FeatureBundle),
or a mapping with those keys.
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any


def _get(rec: Any, attr: str, default: str = "") -> str:
    if isinstance(rec, dict):
        return str(rec.get(attr, default))
    return str(getattr(rec, attr, default))


def split_by_capture_file(
    records: list[Any], test_fraction: float = 0.3, seed: int = 0
) -> tuple[list[Any], list[Any]]:
    """Random split, but NEVER split flows from one pcap across train/test (rule 1).

    Whole capture files go to one side or the other.
    """
    import random

    pcaps = sorted({_get(r, "pcap") for r in records})
    rng = random.Random(seed)
    rng.shuffle(pcaps)
    n_test = max(1, int(len(pcaps) * test_fraction))
    test_pcaps = set(pcaps[:n_test])
    train = [r for r in records if _get(r, "pcap") not in test_pcaps]
    test = [r for r in records if _get(r, "pcap") in test_pcaps]
    return train, test


def leave_one_family_out(records: list[Any]) -> Iterator[tuple[list[Any], list[Any], str]]:
    """Yield (train, test, held_out_family) for each malicious family (rule 2).

    Benign records go into EVERY training and test split (they have no held-out family);
    the held-out malicious family appears only in test. This is the HEADLINE protocol.
    """
    families = sorted({_get(r, "family") for r in records
                       if _get(r, "label") == "malicious" and _get(r, "family")})
    benign = [r for r in records if _get(r, "label") == "benign"]

    # Deterministic benign split so the benign side isn't identical between train/test.
    # split_by_capture_file degenerates when benign spans too few pcaps (e.g. one file):
    # test_fraction rounds up to "at least 1 pcap", which can put the WHOLE benign pool into
    # test and silently leave train with zero benign examples. Detected here rather than
    # left to surface as a mysteriously-bad (or mysteriously-perfect) downstream score: fall
    # back to a session-level split of the benign pool, with a clear warning that this
    # deviates from strict pcap-level splitting (rule 1) because there isn't enough pcap
    # diversity on the benign side to do better.
    benign_train, benign_test = split_by_capture_file(benign, test_fraction=0.3, seed=13) \
        if benign else ([], [])
    if benign and (not benign_train or not benign_test):
        import random
        import warnings
        warnings.warn(
            f"leave_one_family_out: benign spans only {len({_get(r, 'pcap') for r in benign})} "
            "pcap(s), so split_by_capture_file put them all on one side (train would have "
            "gotten zero benign examples). Falling back to a session-level 70/30 split of "
            "the benign pool -- this deviates from strict pcap-level splitting (rule 1) and "
            "should be treated as a data-collection gap (add more benign captures), not fixed "
            "by this fallback alone.", stacklevel=2)
        rng = random.Random(13)
        shuffled = list(benign)
        rng.shuffle(shuffled)
        split = int(len(shuffled) * 0.7)
        benign_train, benign_test = shuffled[:split], shuffled[split:]

    for held in families:
        mal_train = [r for r in records
                     if _get(r, "label") == "malicious" and _get(r, "family") not in ("", held)]
        mal_test = [r for r in records
                    if _get(r, "label") == "malicious" and _get(r, "family") == held]
        train = mal_train + benign_train
        test = mal_test + benign_test
        if train and test:
            yield train, test, held


def temporal_split(
    records: list[Any], cutoff_ts: float, ts_attr: str = "start_ts"
) -> tuple[list[Any], list[Any]]:
    """Older -> train, newer -> test (rule 3)."""
    def ts(r: Any) -> float:
        v = r.get(ts_attr) if isinstance(r, dict) else getattr(r, ts_attr, 0.0)
        return float(v or 0.0)

    train = [r for r in records if ts(r) < cutoff_ts]
    test = [r for r in records if ts(r) >= cutoff_ts]
    return train, test
