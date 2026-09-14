"""Unit tests for the LightGBM baseline's JA4 target encoder (models/baseline_lgbm.py)."""
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from encdetect.models.baseline_lgbm import Ja4TargetEncoder  # noqa: E402


def test_known_rare_hash_smooths_toward_training_prior():
    """A hash seen a few times in training should smooth toward the dataset prior --
    standard target-encoding behaviour, unaffected by the unseen-hash fix below."""
    ja4s = ["A"] * 2 + ["B"] * 100
    y = np.array([1, 1] + [0] * 100)  # A: 2/2 malicious: B: 0/100 malicious
    enc = Ja4TargetEncoder(smoothing=10.0).fit(ja4s, y)
    # A's raw rate is 1.0 but only 2 observations -> pulled well below 1.0 toward the prior.
    assert enc.table["A"] < 0.9
    assert enc.table["A"] > enc.prior  # still pulled toward 1.0 relative to the ~0.02 prior


def test_unseen_hash_does_not_inherit_dataset_class_imbalance():
    """Regression test for a real false positive found 2026-09-14: a benign CTU-Normal-28
    session, whose exact JA4 never appeared in training, scored 0.9999 malicious because the
    encoder's unseen-hash fallback was the training set's raw malicious fraction (~0.93,
    itself just an artifact of downloading far more malicious than benign captures -- CLAUDE.md
    §7 rule 4 notes real traffic is the opposite, ~99.9% benign). An unfamiliar fingerprint
    carries no information either way and must not silently encode "look how imbalanced our
    downloaded corpus happened to be" as if it were evidence of malice.
    """
    # a heavily imbalanced training set, mirroring the real corpus (three big malicious
    # captures, one small benign one)
    ja4s = ["MAL"] * 900 + ["BEN"] * 100
    y = np.array([1] * 900 + [0] * 100)
    enc = Ja4TargetEncoder().fit(ja4s, y)
    assert enc.prior > 0.85  # confirm this fixture is actually imbalanced, like the real data

    unseen = enc.transform(["NEVER_SEEN_BEFORE"])[0]
    assert unseen == 0.5, (
        f"unseen JA4 encoded as {unseen}, expected the neutral 0.5 -- an unfamiliar "
        "fingerprint must not inherit the training set's raw class imbalance as a prior."
    )


def test_unseen_value_is_configurable():
    enc = Ja4TargetEncoder(unseen_value=0.1).fit(["A"], np.array([1]))
    assert enc.transform(["NEVER_SEEN"])[0] == 0.1
