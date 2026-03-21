"""
scripts/evaluate_baseline.py

Evaluates the TF-IDF + LogisticRegression baseline on:
  - data/processed/v2_test.csv           (v2 test set — full)
  - data/processed/v2_test_hard_bert.csv (adversarial evasion test set)

Per-source and per-attack-type breakdowns included.
ModSec OOD holdout reported separately — that's the honest eval surface.
"""

import pandas as pd
import joblib
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score,
    classification_report
)

BASELINE_MODEL = "models/baseline.joblib"
VECTORIZER     = "models/vectorizer.joblib"


def evaluate(model, vectorizer, df: pd.DataFrame, text_col: str, label: str):
    texts  = df[text_col].tolist()
    labels = df["label"].tolist()

    X     = vectorizer.transform(texts)
    probs = model.predict_proba(X)[:, 1]
    preds = (probs >= 0.5).astype(int)

    accuracy              = accuracy_score(labels, preds)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, average="binary"
    )
    try:
        roc_auc = roc_auc_score(labels, probs)
    except ValueError:
        roc_auc = float("nan")

    print(f"\n{'='*55}")
    print(f"  {label}")
    print(f"  Samples: {len(df)} "
          f"(benign={sum(l==0 for l in labels)}, "
          f"malicious={sum(l==1 for l in labels)})")
    print(f"{'='*55}")
    print(f"  Accuracy  : {accuracy:.4f}")
    print(f"  Precision : {precision:.4f}")
    print(f"  Recall    : {recall:.4f}")
    print(f"  F1 Score  : {f1:.4f}")
    roc_auc_str = f"{roc_auc:.4f}" if not pd.isna(roc_auc) else "N/A (single class)"
    print(f"  ROC AUC   : {roc_auc_str}")
    print()
    print(classification_report(labels, preds, target_names=["benign", "malicious"]))


def evaluate_by_source(model, vectorizer, df: pd.DataFrame, text_col: str):
    for source in ["docker", "csic", "modsec"]:
        subset = df[df["source"] == source]
        if len(subset) == 0:
            continue
        evaluate(model, vectorizer, subset, text_col, f"Baseline — source: {source}")


def evaluate_by_attack_type(model, vectorizer, df: pd.DataFrame, text_col: str):
    malicious = df[df["label"] == 1].copy()
    if "attack_type" not in malicious.columns:
        print("  [skip] attack_type column not present")
        return

    print(f"\n{'='*55}")
    print(f"  Per-attack-type metrics (malicious rows only)")
    print(f"{'='*55}")
    print(f"  {'Type':<12} {'N':>6} {'Precision':>10} {'Recall':>8} {'F1':>8}")
    print(f"  {'-'*50}")

    for atype in sorted(malicious["attack_type"].unique()):
        subset = malicious[malicious["attack_type"] == atype]
        if len(subset) < 5:
            continue
        texts  = df.loc[subset.index, text_col].tolist()
        labels = subset["label"].tolist()
        X      = vectorizer.transform(texts)
        probs  = model.predict_proba(X)[:, 1]
        preds  = (probs >= 0.5).astype(int)
        p, r, f1, _ = precision_recall_fscore_support(
            labels, preds, average="binary", zero_division=0
        )
        print(f"  {atype:<12} {len(subset):>6} {p:>10.4f} {r:>8.4f} {f1:>8.4f}")


def main():
    print("Loading baseline model and vectorizer...")
    model      = joblib.load(BASELINE_MODEL)
    vectorizer = joblib.load(VECTORIZER)
    print("Loaded.")

    # ── Full v2 test set
    try:
        df = pd.read_csv("data/processed/v2_test.csv")
        evaluate(model, vectorizer, df, "text", "v2 test set (all sources)")
        evaluate_by_source(model, vectorizer, df, "text")
        evaluate_by_attack_type(model, vectorizer, df, "text")
    except FileNotFoundError:
        print("SKIPPED: v2_test.csv not found.")

    # ── ModSec OOD holdout — reported separately
    try:
        df_full = pd.read_csv("data/processed/v2_test.csv")
        modsec  = df_full[df_full["source"] == "modsec"]
        if len(modsec) > 0:
            evaluate(model, vectorizer, modsec, "text",
                     "ModSec OOD holdout (genuinely unseen distribution)")
    except FileNotFoundError:
        pass

    # ── Adversarial hard test set
    try:
        hard_df = pd.read_csv("data/processed/v2_test_hard_bert.csv")
        evaluate(model, vectorizer, hard_df, "raw_text",
                 "Adversarial hard test (evasion mutations applied)")
        evaluate_by_attack_type(model, vectorizer, hard_df, "raw_text")
    except FileNotFoundError:
        print("\nSKIPPED: v2_test_hard_bert.csv not found — run build_hard_test_set.py first.")


if __name__ == "__main__":
    main()
