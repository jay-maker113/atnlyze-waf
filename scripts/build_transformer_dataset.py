"""
scripts/build_transformer_dataset.py

Converts train/val/test CSVs into BERT-ready format with structured text.

CRITICAL ORDER OF OPERATIONS:
    1. safe_parse() runs on the ORIGINAL log line (preserves HTTP/1.1 case)
    2. normalize_input() runs AFTER parsing (for the raw_text column and structured text)

    Do NOT call normalize_input() before parse_log_line(). It lowercases HTTP/1.1
    to http/1.1, which breaks the parser regex and causes 20%+ sample loss.
"""

import pandas as pd
from atnlyze.parser import parse_log_line
from atnlyze.inference import normalize_input
from atnlyze.utils import build_structured_text  # single source of truth — do not redefine here

INPUT_DIR = "data/processed"
OUTPUT_DIR = "data/processed"


def safe_parse(line: str):
    """
    Parse the ORIGINAL log line before any normalization.
    Fixes doubled quotes from CSV encoding only — does NOT normalize case.
    """
    line = line.strip()
    line = line.replace('""', '"')   # fix CSV quote escaping
    return parse_log_line(line)


def process_split(split):
    df = pd.read_csv(f"{INPUT_DIR}/{split}.csv")

    raw_texts = []
    structured_texts = []
    labels = []

    drop_count = 0
    drop_reasons = []

    for _, row in df.iterrows():
        original = row["text"]

        # Step 1: parse the ORIGINAL line — HTTP/1.1 case preserved, regex works
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

        raw_texts.append(raw_normalized)
        structured_texts.append(build_structured_text(parsed))
        labels.append(row["label"])

    out_df = pd.DataFrame({
        "raw_text": raw_texts,
        "structured_text": structured_texts,
        "label": labels
    })

    out_df.to_csv(f"{OUTPUT_DIR}/{split}_bert.csv", index=False)
    print(f"{split}: {len(out_df)} clean samples saved, {drop_count} dropped "
          f"({drop_count / len(df) * 100:.1f}% loss)")

    if drop_count > 0:
        reason_counts = {}
        for reason, _ in drop_reasons:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
        print(f"  Drop breakdown:")
        for reason, count in reason_counts.items():
            print(f"    [{reason}]: {count} rows")
        print(f"  First 5 dropped samples:")
        for reason, sample in drop_reasons[:5]:
            print(f"    [{reason}] {repr(sample)}")


if __name__ == "__main__":
    for split in ["train", "val", "test"]:
        process_split(split)