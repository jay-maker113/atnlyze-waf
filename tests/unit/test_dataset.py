"""
tests/unit/test_dataset.py

Tests the production data pipeline — CSV loading, label integrity, and
structured text format — NOT the legacy WAFDataset hash-encoding path.

WAFDataset (hash-based encoding) is not used in production.
The real training pipeline reads CSVs directly in trainer.py via TfidfVectorizer.
These tests verify the data that actually feeds that pipeline.
"""

import os
import pandas as pd
import pytest


TRAIN_CSV = "data/processed/train.csv"
VAL_CSV   = "data/processed/val.csv"
TEST_CSV  = "data/processed/test.csv"
TRAIN_BERT_CSV = "data/processed/train_bert.csv"
TEST_HARD_CSV  = "data/processed/test_hard_bert.csv"


# ── Baseline CSV integrity

def test_train_csv_exists_and_has_content():
    assert os.path.exists(TRAIN_CSV), f"{TRAIN_CSV} not found — run build_dataset.py"
    df = pd.read_csv(TRAIN_CSV)
    assert len(df) > 0
    assert list(df.columns) == ["text", "label"]


def test_csv_splits_have_correct_columns():
    for path in [TRAIN_CSV, VAL_CSV, TEST_CSV]:
        assert os.path.exists(path), f"{path} not found"
        df = pd.read_csv(path)
        assert "text" in df.columns
        assert "label" in df.columns


def test_labels_are_binary():
    """Labels must be 0 or 1 only — no nulls, no other values."""
    for path in [TRAIN_CSV, VAL_CSV, TEST_CSV]:
        df = pd.read_csv(path)
        assert df["label"].isnull().sum() == 0, f"Null labels in {path}"
        assert set(df["label"].unique()).issubset({0, 1}), \
            f"Non-binary labels in {path}: {df['label'].unique()}"


def test_no_empty_text_rows():
    """Empty log lines should have been filtered by build_dataset.py."""
    for path in [TRAIN_CSV, VAL_CSV, TEST_CSV]:
        df = pd.read_csv(path)
        empty = df["text"].isnull().sum() + (df["text"].str.strip() == "").sum()
        assert empty == 0, f"{empty} empty text rows found in {path}"


def test_train_val_test_no_overlap():
    """
    Samples must not leak across splits. Overlap would inflate test metrics.
    Checks text column only — labels are derived from text so checking text is sufficient.
    """
    train = set(pd.read_csv(TRAIN_CSV)["text"])
    val   = set(pd.read_csv(VAL_CSV)["text"])
    test  = set(pd.read_csv(TEST_CSV)["text"])

    train_val_overlap = train & val
    train_test_overlap = train & test
    val_test_overlap = val & test

    assert len(train_val_overlap) == 0, \
        f"{len(train_val_overlap)} samples overlap between train and val"
    assert len(train_test_overlap) == 0, \
        f"{len(train_test_overlap)} samples overlap between train and test"
    assert len(val_test_overlap) == 0, \
        f"{len(val_test_overlap)} samples overlap between val and test"


def test_class_balance_not_degenerate():
    """
    Attack rate should be between 20% and 60%.
    Outside this range either the labeler or crawler has a serious problem.
    """
    df = pd.read_csv(TRAIN_CSV)
    attack_rate = df["label"].mean()
    assert 0.20 <= attack_rate <= 0.60, \
        f"Attack rate {attack_rate:.2%} is outside expected 20-60% range"


# ── Transformer BERT CSV integrity

def test_bert_csv_has_structured_text_column():
    assert os.path.exists(TRAIN_BERT_CSV), \
        f"{TRAIN_BERT_CSV} not found — run build_transformer_dataset.py"
    df = pd.read_csv(TRAIN_BERT_CSV)
    assert "structured_text" in df.columns
    assert "raw_text" in df.columns
    assert "label" in df.columns


def test_structured_text_format():
    """
    Every structured_text row must contain all six field markers.
    This is the single-source-of-truth format from utils.build_structured_text().
    """
    df = pd.read_csv(TRAIN_BERT_CSV)
    required_markers = ["[method]", "[path]", "[query]", "[ua]", "[referer]", "[status]"]
    for marker in required_markers:
        missing = (~df["structured_text"].str.contains(marker, regex=False)).sum()
        assert missing == 0, \
            f"{missing} rows in train_bert.csv missing marker '{marker}'"


def test_hard_test_set_same_size_as_test_set():
    """
    test_hard_bert.csv must have the same number of samples and class distribution
    as test_bert.csv — it's a 1:1 replacement with evasion applied, not a new set.
    """
    assert os.path.exists(TEST_HARD_CSV), \
        f"{TEST_HARD_CSV} not found — run build_hard_test_set.py"
    test_df = pd.read_csv("data/processed/test_bert.csv")
    hard_df = pd.read_csv(TEST_HARD_CSV)
    assert len(test_df) == len(hard_df), \
        f"Size mismatch: test_bert={len(test_df)}, test_hard_bert={len(hard_df)}"
    assert (test_df["label"] == 0).sum() == (hard_df["label"] == 0).sum(), \
        "Benign count differs between test_bert.csv and test_hard_bert.csv"
    assert (test_df["label"] == 1).sum() == (hard_df["label"] == 1).sum(), \
        "Malicious count differs between test_bert.csv and test_hard_bert.csv"