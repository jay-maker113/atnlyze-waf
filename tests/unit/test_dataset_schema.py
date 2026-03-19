"""
tests/unit/test_dataset_schema.py

CI-safe schema tests for v2 processed CSVs.
No model loading, no file generation — pure structural validation.

Runs against:
  data/processed/v2_train.csv
  data/processed/v2_val.csv
  data/processed/v2_test.csv

These files do not exist yet (created in Phase 2). Tests are skipped
automatically if files are missing — they become blocking once Phase 2
is complete.

Also validates that ATTACK_TYPES in utils.py is internally consistent.
That check runs always, no file dependency.
"""

import os
import pytest
import pandas as pd

from atnlyze.utils import ATTACK_TYPES

V2_TRAIN = "data/processed/v2_train.csv"
V2_VAL   = "data/processed/v2_val.csv"
V2_TEST  = "data/processed/v2_test.csv"
V2_FILES = [V2_TRAIN, V2_VAL, V2_TEST]

# Required columns for baseline CSVs (text + label + attack_type)
BASELINE_COLS = {"text", "label", "attack_type"}

# Required columns for bert CSVs
BERT_COLS = {"raw_text", "structured_text", "label", "attack_type"}


# ── ATTACK_TYPES sanity (always runs — no file dependency) ────────────────────

def test_attack_types_is_frozenset():
    assert isinstance(ATTACK_TYPES, frozenset), \
        "ATTACK_TYPES must be frozenset — mutable set risks accidental modification"


def test_attack_types_contains_unknown():
    assert "unknown" in ATTACK_TYPES, \
        "'unknown' must be in ATTACK_TYPES — labeler uses it as fallback"


def test_attack_types_all_lowercase():
    for t in ATTACK_TYPES:
        assert t == t.lower(), \
            f"Attack type '{t}' is not lowercase — all types must be lowercase"


def test_attack_types_no_empty_strings():
    assert "" not in ATTACK_TYPES, \
        "Empty string found in ATTACK_TYPES"


def test_attack_types_expected_members():
    """
    Confirm all 11 canonical attack types are present.
    If this fails after adding/removing a type, update this test too.
    """
    expected = {
        "sqli", "xss", "cmdi", "lfi", "rfi",
        "php", "scanner", "path", "nosql", "ldap", "unknown"
    }
    missing = expected - ATTACK_TYPES
    extra   = ATTACK_TYPES - expected
    assert not missing, f"ATTACK_TYPES is missing expected members: {missing}"
    assert not extra,   f"ATTACK_TYPES has unexpected members: {extra} — update this test if intentional"


# ── v2 CSV tests (skipped until Phase 2 produces the files) ───────────────────

def v2_files_exist():
    return all(os.path.exists(f) for f in V2_FILES)


v2_skip = pytest.mark.skipif(
    not v2_files_exist(),
    reason="v2 CSVs not generated yet — run Phase 2 pipeline first"
)


@v2_skip
def test_v2_files_exist_and_nonempty():
    for path in V2_FILES:
        assert os.path.exists(path), f"{path} missing"
        df = pd.read_csv(path)
        assert len(df) > 0, f"{path} is empty"


@v2_skip
def test_v2_baseline_columns():
    """text, label, attack_type must all be present."""
    for path in V2_FILES:
        df = pd.read_csv(path)
        missing = BASELINE_COLS - set(df.columns)
        assert not missing, f"{path} missing columns: {missing}"


@v2_skip
def test_v2_labels_are_binary():
    for path in V2_FILES:
        df = pd.read_csv(path)
        assert df["label"].isnull().sum() == 0, \
            f"Null labels in {path}"
        assert set(df["label"].unique()).issubset({0, 1}), \
            f"Non-binary labels in {path}: {df['label'].unique()}"


@v2_skip
def test_v2_attack_type_values_valid():
    """Every attack_type value must be a member of ATTACK_TYPES."""
    for path in V2_FILES:
        df = pd.read_csv(path)
        invalid = set(df["attack_type"].dropna().unique()) - ATTACK_TYPES
        assert not invalid, \
            f"{path} contains invalid attack_type values: {invalid}"


@v2_skip
def test_v2_no_null_attack_type_on_malicious():
    """
    Malicious rows must never have a null attack_type.
    Benign rows are allowed null (attack_type=NaN is acceptable for label=0).
    """
    for path in V2_FILES:
        df = pd.read_csv(path)
        malicious = df[df["label"] == 1]
        null_count = malicious["attack_type"].isnull().sum()
        assert null_count == 0, \
            f"{path}: {null_count} malicious rows have null attack_type"


@v2_skip
def test_v2_no_empty_text():
    for path in V2_FILES:
        df = pd.read_csv(path)
        empty = df["text"].isnull().sum() + (df["text"].str.strip() == "").sum()
        assert empty == 0, f"{path}: {empty} empty text rows"


@v2_skip
def test_v2_class_balance_not_degenerate():
    """
    Attack rate must be between 20% and 80% in train.
    Outside this range the dataset is broken, not just imbalanced.
    """
    df = pd.read_csv(V2_TRAIN)
    rate = df["label"].mean()
    assert 0.20 <= rate <= 0.80, \
        f"v2_train attack rate {rate:.2%} is outside 20-80% — check pipeline"


@v2_skip
def test_v2_no_train_test_overlap():
    """ModSec source-based split means zero text overlap between train and test."""
    train = set(pd.read_csv(V2_TRAIN)["text"])
    val   = set(pd.read_csv(V2_VAL)["text"])
    test  = set(pd.read_csv(V2_TEST)["text"])

    assert not (train & test), \
        f"{len(train & test)} samples overlap between v2_train and v2_test"
    assert not (train & val), \
        f"{len(train & val)} samples overlap between v2_train and v2_val"
    assert not (val & test), \
        f"{len(val & test)} samples overlap between v2_val and v2_test"


@v2_skip
def test_v2_modsec_in_test_only():
    """
    Source-based split guardrail: ModSec samples must only appear in test,
    never in train or val. Requires a 'source' column in the v2 CSVs.
    Skip gracefully if 'source' column is absent (optional column).
    """
    test_df = pd.read_csv(V2_TEST)
    if "source" not in test_df.columns:
        pytest.skip("'source' column not present — skipping ModSec split check")

    for path in [V2_TRAIN, V2_VAL]:
        df = pd.read_csv(path)
        if "source" not in df.columns:
            pytest.skip("'source' column not present — skipping ModSec split check")
        modsec_in_split = (df["source"] == "modsec").sum()
        assert modsec_in_split == 0, \
            f"{path}: {modsec_in_split} ModSec rows found outside test set"