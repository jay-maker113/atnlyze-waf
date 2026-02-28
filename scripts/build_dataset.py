"""
scripts/build_dataset.py

Loads benign.log and malicious.log from each app, merges them,
shuffles, and splits into train/val/test CSVs for the baseline model.

Output: data/processed/train.csv, val.csv, test.csv
Columns: text (raw log line), label (0=benign, 1=malicious)

Split: 70% train, 15% val, 15% test — stratified on label.
"""

import os
import pandas as pd
from sklearn.model_selection import train_test_split

RAW_DIR = "data/raw"
OUT_DIR = "data/processed"

APPS = ["dvwa", "juice_shop", "webgoat"]


def load_logs(app: str, label: str) -> list:
    path = os.path.join(RAW_DIR, app, f"{label}.log")
    if not os.path.exists(path):
        print(f"  WARNING: {path} not found, skipping.")
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    # Strip whitespace and drop empty lines — echo "" leaves a blank line at top
    cleaned = [
        (line.strip(), 1 if label == "malicious" else 0)
        for line in lines
        if line.strip()  # skip empty lines
    ]
    print(f"  {app}/{label}.log: {len(cleaned)} lines loaded")
    return cleaned


def main():
    data = []

    print("Loading logs...")
    for app in APPS:
        data += load_logs(app, "benign")
        data += load_logs(app, "malicious")

    df = pd.DataFrame(data, columns=["text", "label"])

    # Detect label conflicts — same text labeled both benign and malicious.
    # This happens when a log line matches a malicious pattern but also appears
    # in benign.log (e.g., a benign request whose path happens to match a regex).
    # Resolution: malicious wins — false negatives are worse than false positives for a WAF.
    conflicts = df.groupby("text")["label"].nunique()
    conflict_texts = conflicts[conflicts > 1].index
    if len(conflict_texts) > 0:
        print(f"\nWARNING: {len(conflict_texts)} lines have conflicting labels — resolving as malicious")
        df.loc[df["text"].isin(conflict_texts), "label"] = 1

    # Deduplicate after conflict resolution
    before = len(df)
    df = df.drop_duplicates(subset=["text"])
    after = len(df)
    if before != after:
        print(f"Dropped {before - after} duplicate lines ({after} unique samples remain)")

    print(f"\nTotal samples : {len(df)}")
    print(f"Benign  (0)   : {(df['label'] == 0).sum()}")
    print(f"Malicious (1) : {(df['label'] == 1).sum()}")
    print(f"Attack rate   : {(df['label'] == 1).sum() / len(df) * 100:.1f}%")

    # 70/15/15 split, stratified
    train, temp = train_test_split(
        df, test_size=0.3, stratify=df["label"], random_state=42
    )
    val, test = train_test_split(
        temp, test_size=0.5, stratify=temp["label"], random_state=42
    )

    os.makedirs(OUT_DIR, exist_ok=True)

    train.to_csv(os.path.join(OUT_DIR, "train.csv"), index=False)
    val.to_csv(os.path.join(OUT_DIR, "val.csv"), index=False)
    test.to_csv(os.path.join(OUT_DIR, "test.csv"), index=False)

    print(f"\nSplit:")
    print(f"  train : {len(train)} samples")
    print(f"  val   : {len(val)} samples")
    print(f"  test  : {len(test)} samples")
    print(f"\nSaved to {OUT_DIR}/")


if __name__ == "__main__":
    main()