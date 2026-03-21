"""
scripts/build_dataset.py

Builds v2 train/val/test CSVs from all data sources.

Sources:
    Docker traffic  — data/raw/dvwa/, juice_shop/, webgoat/, root
                      labeled via label_logs.is_malicious()
    CSIC 2010       — data/raw/csic/csic_labeled.csv  (pre-labeled sidecar)
    ModSec logs     — data/raw/modsec/modsec_labeled.csv (pre-labeled sidecar)

Split strategy (source-based — not random across all sources):
    ModSec  → test set ONLY (genuinely unseen distribution, OOD eval)
    Docker + CSIC → 70/15/15 stratified split on label

Output:
    data/processed/v2_train.csv
    data/processed/v2_val.csv
    data/processed/v2_test.csv
    data/processed/v2_metadata.json

Columns in all CSVs: text, label, attack_type, source

Acceptance assertions (fail loudly — never silently produce a bad dataset):
    - All splits non-empty
    - Attack rate 20-80% in train
    - Zero text overlap between train/val/test
    - ModSec samples only in test
    - All attack_type values in ATTACK_TYPES
    - Zero nulls in key columns
"""

import os
import sys
import json
import subprocess
import importlib.util
import pathlib
import pandas as pd
from sklearn.model_selection import train_test_split
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from atnlyze.utils import ATTACK_TYPES

# Load label_logs by file path — scripts/ is not a package
_ll_path = pathlib.Path(__file__).parent / "traffic" / "label_logs.py"
_spec = importlib.util.spec_from_file_location("label_logs", _ll_path)
_ll = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ll)
is_malicious = _ll.is_malicious

RAW_DIR        = "data/raw"
OUT_DIR        = "data/processed"
DOCKER_APPS    = ["dvwa", "juice_shop", "webgoat"]
DOCKER_ROOT    = RAW_DIR  # root access.log for scanner probes
CSIC_SIDECAR   = "data/raw/csic/csic_labeled.csv"
MODSEC_SIDECAR = "data/raw/modsec/modsec_labeled.csv"
RANDOM_SEED    = 42


# ── Loaders ───────────────────────────────────────────────────────────────────

def load_docker_logs() -> pd.DataFrame:
    """
    Reads benign.log and malicious.log from each Docker app dir + root.
    Runs is_malicious() on each line to get attack_type.
    Benign lines get attack_type='unknown'.
    """
    rows = []
    sources = [(app, os.path.join(RAW_DIR, app)) for app in DOCKER_APPS]
    sources.append(("docker_root", DOCKER_ROOT))

    for source_name, app_path in sources:
        for label_str in ("benign", "malicious"):
            log_file = os.path.join(app_path, f"{label_str}.log")
            if not os.path.exists(log_file):
                print(f"  WARNING: {log_file} not found, skipping.")
                continue

            label = 0 if label_str == "benign" else 1

            with open(log_file, encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                if label == 1:
                    _, _, attack_type = is_malicious(line)
                    attack_type = attack_type or "unknown"
                else:
                    attack_type = "unknown"

                rows.append({
                    "text":        line,
                    "label":       label,
                    "attack_type": attack_type,
                    "source":      "docker",
                })

    df = pd.DataFrame(rows)
    print(f"  Docker logs loaded: {len(df)} rows "
          f"(benign={(df['label']==0).sum()}, malicious={(df['label']==1).sum()})")
    return df


def load_csic() -> pd.DataFrame:
    if not os.path.exists(CSIC_SIDECAR):
        raise FileNotFoundError(
            f"{CSIC_SIDECAR} not found — run scripts/convert_csic.py first"
        )
    df = pd.read_csv(CSIC_SIDECAR)
    for col in ("text", "label", "attack_type", "source"):
        assert col in df.columns, f"CSIC sidecar missing column: {col}"
    print(f"  CSIC loaded: {len(df)} rows "
          f"(benign={(df['label']==0).sum()}, malicious={(df['label']==1).sum()})")
    return df


def load_modsec() -> pd.DataFrame:
    if not os.path.exists(MODSEC_SIDECAR):
        raise FileNotFoundError(
            f"{MODSEC_SIDECAR} not found — run scripts/convert_modsec.py first"
        )
    df = pd.read_csv(MODSEC_SIDECAR)
    for col in ("text", "label", "attack_type", "source"):
        assert col in df.columns, f"ModSec sidecar missing column: {col}"
    print(f"  ModSec loaded: {len(df)} rows (all malicious)")
    return df


# ── Git commit hash ───────────────────────────────────────────────────────────

def get_git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        return "unknown"


# ── Acceptance assertions ─────────────────────────────────────────────────────

def assert_dataset(train: pd.DataFrame, val: pd.DataFrame, test: pd.DataFrame):
    print("\nRunning acceptance assertions...")

    assert len(train) > 0, "ASSERTION FAILED: train is empty"
    assert len(val)   > 0, "ASSERTION FAILED: val is empty"
    assert len(test)  > 0, "ASSERTION FAILED: test is empty"

    rate = train["label"].mean()
    assert 0.20 <= rate <= 0.80, \
        f"ASSERTION FAILED: train attack rate {rate:.2%} outside 20-80%"

    train_texts = set(train["text"])
    val_texts   = set(val["text"])
    test_texts  = set(test["text"])

    assert not (train_texts & val_texts), \
        f"ASSERTION FAILED: {len(train_texts & val_texts)} samples overlap train/val"
    assert not (train_texts & test_texts), \
        f"ASSERTION FAILED: {len(train_texts & test_texts)} samples overlap train/test"
    assert not (val_texts & test_texts), \
        f"ASSERTION FAILED: {len(val_texts & test_texts)} samples overlap val/test"

    for split_name, split_df in [("train", train), ("val", val)]:
        modsec_count = (split_df["source"] == "modsec").sum()
        assert modsec_count == 0, \
            f"ASSERTION FAILED: {modsec_count} ModSec rows found in {split_name}"

    all_types = set(pd.concat([train, val, test])["attack_type"].dropna().unique())
    invalid = all_types - ATTACK_TYPES
    assert not invalid, \
        f"ASSERTION FAILED: invalid attack_type values: {invalid}"

    for split_name, split_df in [("train", train), ("val", val), ("test", test)]:
        for col in ("text", "label", "attack_type", "source"):
            null_count = split_df[col].isnull().sum()
            assert null_count == 0, \
                f"ASSERTION FAILED: {null_count} nulls in {split_name}.{col}"

    print("  All assertions passed. ✓")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    print("Loading data sources...")
    docker_df = load_docker_logs()
    csic_df   = load_csic()
    modsec_df = load_modsec()

    # Combine Docker + CSIC — ModSec held out entirely for test
    trainval_df = pd.concat([docker_df, csic_df], ignore_index=True)

    before = len(trainval_df)
    trainval_df = trainval_df.drop_duplicates(subset=["text"])
    after = len(trainval_df)
    if before != after:
        print(f"  Deduped {before - after} duplicate rows from Docker+CSIC")

    # Label conflict resolution — malicious wins
    conflicts = trainval_df.groupby("text")["label"].nunique()
    conflict_texts = conflicts[conflicts > 1].index
    if len(conflict_texts) > 0:
        print(f"  WARNING: {len(conflict_texts)} label conflicts — resolving as malicious")
        trainval_df.loc[trainval_df["text"].isin(conflict_texts), "label"] = 1

    print(f"\nDocker+CSIC combined: {len(trainval_df)} rows "
          f"(benign={(trainval_df['label']==0).sum()}, "
          f"malicious={(trainval_df['label']==1).sum()})")

    # 70/15/15 stratified split
    train_df, temp_df = train_test_split(
        trainval_df,
        test_size=0.30,
        stratify=trainval_df["label"],
        random_state=RANDOM_SEED,
    )
    val_df, test_base_df = train_test_split(
        temp_df,
        test_size=0.50,
        stratify=temp_df["label"],
        random_state=RANDOM_SEED,
    )

    # Append ModSec to test only
    test_df = pd.concat([test_base_df, modsec_df], ignore_index=True)
    test_df = test_df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

    # Assertions before writing — fail loudly
    assert_dataset(train_df, val_df, test_df)

    # Write CSVs
    train_df.to_csv(os.path.join(OUT_DIR, "v2_train.csv"), index=False)
    val_df.to_csv(os.path.join(OUT_DIR,   "v2_val.csv"),   index=False)
    test_df.to_csv(os.path.join(OUT_DIR,  "v2_test.csv"),  index=False)

    # Write metadata — attack_type_counts on malicious rows only
    all_df        = pd.concat([train_df, val_df, test_df])
    malicious_all = all_df[all_df["label"] == 1]

    source_counts = {
        src: int((all_df["source"] == src).sum())
        for src in ["docker", "csic", "modsec"]
    }
    class_counts = {
        "benign":    int((all_df["label"] == 0).sum()),
        "malicious": int((all_df["label"] == 1).sum()),
    }
    attack_type_counts = {
        t: int((malicious_all["attack_type"] == t).sum())
        for t in sorted(ATTACK_TYPES)
    }

    metadata = {
        "version":            "v2",
        "date":               datetime.now(timezone.utc).isoformat(),
        "git_commit":         get_git_commit(),
        "source_counts":      source_counts,
        "class_counts":       class_counts,
        "attack_type_counts": attack_type_counts,
        "split_sizes": {
            "train": len(train_df),
            "val":   len(val_df),
            "test":  len(test_df),
        },
        "split_strategy": (
            "ModSec → test only (OOD holdout). "
            "Docker+CSIC → 70/15/15 stratified on label."
        ),
        "modsec_in_test": int((test_df["source"] == "modsec").sum()),
    }

    meta_path = os.path.join(OUT_DIR, "v2_metadata.json")
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)

    # Summary
    print(f"\n{'='*55}")
    print(f"  v2 dataset build complete")
    print(f"{'='*55}")
    print(f"  train : {len(train_df):>7} rows  "
          f"(benign={(train_df['label']==0).sum()}, "
          f"malicious={(train_df['label']==1).sum()})")
    print(f"  val   : {len(val_df):>7} rows  "
          f"(benign={(val_df['label']==0).sum()}, "
          f"malicious={(val_df['label']==1).sum()})")
    print(f"  test  : {len(test_df):>7} rows  "
          f"(benign={(test_df['label']==0).sum()}, "
          f"malicious={(test_df['label']==1).sum()})")
    print(f"\n  Attack type counts (malicious rows only):")
    for t, c in sorted(attack_type_counts.items(), key=lambda x: -x[1]):
        if c > 0:
            print(f"    {t:10}: {c}")
    print(f"\n  Source counts:")
    for src, c in source_counts.items():
        print(f"    {src:10}: {c}")
    print(f"\n  Output:")
    print(f"    {OUT_DIR}/v2_train.csv")
    print(f"    {OUT_DIR}/v2_val.csv")
    print(f"    {OUT_DIR}/v2_test.csv")
    print(f"    {meta_path}")


if __name__ == "__main__":
    main()