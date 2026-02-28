"""
scripts/evaluate_baseline.py

Evaluates the TF-IDF + LogisticRegression baseline on both:
  - data/processed/test.csv        (normal test set)
  - data/processed/test_hard_bert.csv  (adversarial evasion test set)

The gap between these two scores is the honest measure of baseline fragility.
A model that memorized regex patterns will score high on normal, low on hard.
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

TEST_SETS = [
    ("Normal test set",      "data/processed/test.csv",           "text"),
    ("Adversarial test set", "data/processed/test_hard_bert.csv", "raw_text"),
]


def evaluate(model, vectorizer, df: pd.DataFrame, text_col: str, label: str):
    texts  = df[text_col].tolist()
    labels = df["label"].tolist()

    X = vectorizer.transform(texts)
    probs = model.predict_proba(X)[:, 1]
    preds = (probs >= 0.5).astype(int)

    accuracy  = accuracy_score(labels, preds)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, average="binary"
    )
    roc_auc = roc_auc_score(labels, probs)

    print(f"\n{'='*50}")
    print(f"  {label}")
    print(f"  Samples: {len(df)} "
          f"(benign={sum(l==0 for l in labels)}, "
          f"malicious={sum(l==1 for l in labels)})")
    print(f"{'='*50}")
    print(f"  Accuracy  : {accuracy:.4f}")
    print(f"  Precision : {precision:.4f}")
    print(f"  Recall    : {recall:.4f}")
    print(f"  F1 Score  : {f1:.4f}")
    print(f"  ROC AUC   : {roc_auc:.4f}")
    print()
    print(classification_report(
        labels, preds,
        target_names=["benign", "malicious"]
    ))


def main():
    print("Loading baseline model and vectorizer...")
    model      = joblib.load(BASELINE_MODEL)
    vectorizer = joblib.load(VECTORIZER)
    print("Loaded.")

    for label, path, text_col in TEST_SETS:
        try:
            df = pd.read_csv(path)
            evaluate(model, vectorizer, df, text_col, label)
        except FileNotFoundError:
            print(f"\nSKIPPED: {path} not found — run the relevant build script first.")


if __name__ == "__main__":
    main()