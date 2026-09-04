"""
train.py
========
Trains the first reproducible baseline model: Logistic Regression, no
hyperparameter tuning (fixed defaults), class-imbalance handled via
`class_weight="balanced"` rather than resampling (resampling would be a
tuning decision; balanced class weights is the minimal, defensible
default for a first baseline).

Only rows with label in {'positive', 'negative'} are used for fitting —
'excluded' windows (see labeling.py) are never part of the training
signal; they are scored separately in evaluate.py as a stress-test set.

The StandardScaler is fit ONLY on the training split, then applied to
val/test — fitting on combined data would leak val/test feature
distribution into preprocessing.
"""

from __future__ import annotations
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from config import RANDOM_SEED
from features import FEATURE_NAMES


@dataclass
class TrainedModel:
    model: LogisticRegression
    scaler: StandardScaler
    feature_names: list


def _prepare_xy(df: pd.DataFrame):
    df = df[df["label"].isin(["positive", "negative"])].copy()
    X = df[FEATURE_NAMES].fillna(0.0).values
    y = (df["label"] == "positive").astype(int).values
    return X, y, df


def train_logistic_regression(train_df: pd.DataFrame) -> TrainedModel:
    X_train, y_train, _ = _prepare_xy(train_df)

    if len(np.unique(y_train)) < 2:
        raise ValueError(
            "Training split has only one class present after filtering to "
            "positive/negative windows — cannot fit a classifier. Check "
            "the scenario split configuration and label thresholds."
        )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    # No hyperparameter tuning per the task requirements: fixed defaults,
    # only class_weight is set (imbalance handling, not a tuned choice).
    model = LogisticRegression(
        class_weight="balanced",
        max_iter=1000,
        random_state=RANDOM_SEED,
    )
    model.fit(X_train_scaled, y_train)

    return TrainedModel(model=model, scaler=scaler, feature_names=FEATURE_NAMES)


def predict_proba(trained: TrainedModel, df: pd.DataFrame) -> np.ndarray:
    """Predict P(positive) for every row in df (any label, including
    'excluded' — used for the stress-test evaluation)."""
    X = df[trained.feature_names].fillna(0.0).values
    X_scaled = trained.scaler.transform(X)
    return trained.model.predict_proba(X_scaled)[:, 1]
