"""
data_loading.py
================
Responsible ONLY for reading raw per-scenario CTU-13 flow files off disk
into pandas DataFrames, tagged with their scenario identifier. Does not
clean, normalise, or interpret any column — see preprocessing.py for that.

Supports .parquet and .csv/.binetflow inputs. Column names are left
exactly as found in the file; normalise_columns() in preprocessing.py
handles renaming/aliasing.
"""

from __future__ import annotations
import glob
import os
from typing import List

import pandas as pd


def _scenario_id_from_filename(path: str) -> str:
    """Derive a scenario id like '1-Neris-20110810' from a filename such as
    '1-Neris-20110810.binetflow.parquet' or '1-Neris-20110810.binetflow.csv'.
    Falls back to the bare filename stem if the pattern doesn't match.
    """
    base = os.path.basename(path)
    for suffix in (".binetflow.parquet", ".binetflow.csv", ".binetflow",
                   ".parquet", ".csv"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    return base


def _read_one(path: str) -> pd.DataFrame:
    if path.endswith(".parquet"):
        df = pd.read_parquet(path)
    else:
        df = pd.read_csv(path)
    df["scenario"] = _scenario_id_from_filename(path)
    df["__source_file__"] = path
    return df


def load_scenarios(data_dir: str, pattern: str = "*.parquet") -> pd.DataFrame:
    """Load every scenario file under data_dir matching `pattern` and
    concatenate into a single DataFrame with a 'scenario' column.

    Parameters
    ----------
    data_dir : directory containing one file per CTU-13 scenario
    pattern  : glob pattern, e.g. "*.parquet" or "*.binetflow.csv"

    Returns
    -------
    pd.DataFrame with all scenarios concatenated, plus 'scenario' and
    '__source_file__' columns.
    """
    paths = sorted(glob.glob(os.path.join(data_dir, pattern)))
    if not paths:
        raise FileNotFoundError(
            f"No files matching {pattern!r} found under {data_dir!r}. "
            f"Check the path and pattern."
        )
    frames: List[pd.DataFrame] = []
    for p in paths:
        frames.append(_read_one(p))
    combined = pd.concat(frames, ignore_index=True)
    return combined


def load_single_scenario(path: str) -> pd.DataFrame:
    """Load a single scenario file (used by tests / ad-hoc inspection)."""
    return _read_one(path)
