"""
scripts/build_transformer_dataset.py

Converts v2 train/val/test CSVs into BERT-ready format with structured text.

Input:  data/processed/v2_train.csv, v2_val.csv, v2_test.csv
        Columns: text, label, attack_type, source

Output: data/processed/v2_train_bert.csv
        data/processed/v2_val_bert.csv
        data/processed/v2_test_bert.csv
        Columns: raw_text, structured_text, label, attack_type, source

CRITICAL ORDER OF OPERATIONS — DO NOT CHANGE:
    1. safe_parse() runs on the ORIGINAL log line (preserves HTTP/1.1 case)
    2. normalize_input() runs AFTER parsing
    Reversing this lowercases HTTP/1.1 → http/1.1, breaks the parser regex,
    causes 20%+ sample loss. This bug was fixed in Chat 1 — never reintroduce it.
"""

import os
import sys
import pandas as pd
from tqdm import tqdm

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from atnlyze.parser import parse_log_line
from atnlyze.inference import normalize_input
from atnlyze.utils import build_structured_text, ATTACK_TYPES

INPUT_DIR  = "data/processed"
OUTPUT_DIR = "data/processed"

SPLITS = [
    ("v2_train", "v2_train_bert"),
    ("v2_val",   "v2_val_bert"),
    ("v2_test",  "v2_test_bert"),
]


def safe_parse(line: str) -> dict | None:
    """
    Parse the ORIGINAL log line before any normalization.
    Fixes doubled quotes from CSV encoding only — does NOT normalize case.
    """
    line = line.strip()
    line = line.replace('""', '"')
    return parse_log_line(line)


def process_split(in_name: str, out_name: str):
    in_path  = os.path.join(INPUT_DIR,  f"{in_name}.csv")
    out_path = os.path.join(OUTPUT_DIR, f"{out_name}.csv")

    if not os.path.exists(in_path):
        print(f"SKIPPED: {in_path} not found.")
        return

    df = pd.read_csv(in_path)
    print(f"\n{in_name}: {len(df)} rows")

    raw_texts        = []
    structured_texts = []
    labels           = []
    attack_types     = []
    sources          = []

    drop_count   = 0
    drop_reasons = []

    for _, row in tqdm(df.iterrows(), total=len(df), desc=f"  parsing {in_name}"):
        original    = str(row["text"])
        label       = int(row["label"])
        attack_type = str(row["attack_type"])
        source      = str(row["source"])

        # Step 1: parse ORIGINAL — HTTP/1.1 case preserved, regex works
        parsed = safe_parse(original)
        if not parsed:
            drop_count += 1
            drop_reasons.append(("no_parse", original[:100]))
            continue

        if not parsed.get("method") or not parsed.get("path"):
            drop_count += 1
            drop_reasons.append(("missing_fields", original[:100]))
            continue

        # Step 2: normalize AFTER successful parse
        raw_normalized = normalize_input(original)
        structured     = build_structured_text(parsed)

        raw_texts.append(raw_normalized)
        structured_texts.append(structured)
        labels.append(label)
        attack_types.append(attack_type)
        sources.append(source)

    out_df = pd.DataFrame({
        "raw_text":        raw_texts,
        "structured_text": structured_texts,
        "label":           labels,
        "attack_type":     attack_types,
        "source":          sources,
    })

    out_df.to_csv(out_path, index=False)

    drop_pct = drop_count / len(df) * 100 if len(df) else 0
    print(f"  {len(out_df)} clean rows saved, {drop_count} dropped ({drop_pct:.1f}% loss)")

    if drop_count > 0:
        reason_counts: dict[str, int] = {}
        for reason, _ in drop_reasons:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
        print(f"  Drop breakdown: {reason_counts}")
        print(f"  First 3 dropped:")
        for reason, sample in drop_reasons[:3]:
            print(f"    [{reason}] {repr(sample)}")

    # Post-parse validation
    assert out_df["label"].isnull().sum() == 0, "Null labels after parse"
    assert set(out_df["label"].unique()).issubset({0, 1}), "Non-binary labels after parse"
    invalid_types = set(out_df["attack_type"].unique()) - ATTACK_TYPES
    assert not invalid_types, f"Invalid attack_type values after parse: {invalid_types}"

    # Verify structured text format — all 6 markers present
    required_markers = ["[method]", "[path]", "[query]", "[ua]", "[referer]", "[status]"]
    for marker in required_markers:
        missing = (~out_df["structured_text"].str.contains(marker, regex=False)).sum()
        assert missing == 0, f"{missing} rows missing marker '{marker}' in {out_name}"

    print(f"  Validation passed. ✓")
    print(f"  Label dist: benign={(out_df['label']==0).sum()}, "
          f"malicious={(out_df['label']==1).sum()}")
    print(f"  Sources: {out_df['source'].value_counts().to_dict()}")


def main():
    print("Building BERT-ready datasets from v2 CSVs...")
    print("Critical: parse before normalize — HTTP/1.1 case preserved.\n")

    for in_name, out_name in SPLITS:
        process_split(in_name, out_name)

    print("\nDone. Output files:")
    for _, out_name in SPLITS:
        path = os.path.join(OUTPUT_DIR, f"{out_name}.csv")
        if os.path.exists(path):
            size = os.path.getsize(path) / (1024 * 1024)
            print(f"  {path}  ({size:.1f} MB)")


if __name__ == "__main__":
    main()