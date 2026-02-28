"""
scripts/evaluate_transformer.py

Evaluates the fine-tuned DistilBERT transformer WAF on both:
  - data/processed/test_bert.csv       (normal test set — same distribution as training)
  - data/processed/test_hard_bert.csv  (adversarial evasion test set — honest eval surface)

The gap between these two scores is the honest measure of transformer robustness.
Compare against evaluate_baseline.py results to validate the thesis:
  "Transformer learns attack semantics, not just keyword patterns."

Usage:
    python scripts/evaluate_transformer.py

Requires:
    - models/bert_waf/ directory with config.json, model.safetensors, tokenizer files
    - data/processed/test_bert.csv and test_hard_bert.csv
"""

import torch
import pandas as pd
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score,
    classification_report,
)
from tqdm import tqdm

MODEL_DIR = "models/bert_waf"
BATCH_SIZE = 16
MAX_LENGTH = 128

TEST_SETS = [
    ("Normal test set",      "data/processed/test_bert.csv",      "structured_text"),
    ("Adversarial test set", "data/processed/test_hard_bert.csv", "structured_text"),
]


def load_model(model_dir: str):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")
    tokenizer = DistilBertTokenizerFast.from_pretrained(model_dir)
    model = DistilBertForSequenceClassification.from_pretrained(model_dir)
    model.to(device)
    model.eval()
    return tokenizer, model, device


def run_inference(tokenizer, model, device, texts: list) -> list:
    """Batched inference. Returns list of malicious class probabilities."""
    probs_all = []
    for i in tqdm(range(0, len(texts), BATCH_SIZE), desc="Inferring", leave=False):
        batch = texts[i : i + BATCH_SIZE]
        inputs = tokenizer(
            batch,
            padding=True,
            truncation=True,
            max_length=MAX_LENGTH,
            return_tensors="pt",
        )
        inputs = {k: v.to(device) for k, v in inputs.items()}
        with torch.no_grad():
            logits = model(**inputs).logits
        probs = torch.softmax(logits, dim=1)[:, 1]
        probs_all.extend(probs.cpu().numpy().tolist())
    return probs_all


def evaluate(tokenizer, model, device, df: pd.DataFrame, text_col: str, label: str):
    texts = df[text_col].tolist()
    labels = df["label"].tolist()

    probs = run_inference(tokenizer, model, device, texts)
    preds = [1 if p >= 0.5 else 0 for p in probs]

    accuracy = accuracy_score(labels, preds)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, average="binary"
    )
    roc_auc = roc_auc_score(labels, probs)

    print(f"\n{'='*50}")
    print(f"  {label}")
    print(f"  Samples: {len(df)} "
          f"(benign={sum(l == 0 for l in labels)}, "
          f"malicious={sum(l == 1 for l in labels)})")
    print(f"{'='*50}")
    print(f"  Accuracy  : {accuracy:.4f}")
    print(f"  Precision : {precision:.4f}")
    print(f"  Recall    : {recall:.4f}")
    print(f"  F1 Score  : {f1:.4f}")
    print(f"  ROC AUC   : {roc_auc:.4f}")
    print()
    print(classification_report(labels, preds, target_names=["benign", "malicious"]))

    return {"accuracy": accuracy, "precision": precision, "recall": recall,
            "f1": f1, "roc_auc": roc_auc}


def main():
    print(f"Loading transformer from {MODEL_DIR} ...")
    tokenizer, model, device = load_model(MODEL_DIR)
    print("Loaded.\n")

    results = {}
    for label, path, text_col in TEST_SETS:
        try:
            df = pd.read_csv(path)
            results[label] = evaluate(tokenizer, model, device, df, text_col, label)
        except FileNotFoundError:
            print(f"\nSKIPPED: {path} not found.")

    # Summary comparison table
    if len(results) == 2:
        print("\n" + "=" * 50)
        print("  SUMMARY — Normal vs Adversarial")
        print("=" * 50)
        print(f"  {'Metric':<12} {'Normal':>10} {'Adversarial':>12} {'Gap':>8}")
        print(f"  {'-'*44}")
        for metric in ("accuracy", "precision", "recall", "f1", "roc_auc"):
            normal_val = results["Normal test set"][metric]
            hard_val   = results["Adversarial test set"][metric]
            gap        = normal_val - hard_val
            print(f"  {metric:<12} {normal_val:>10.4f} {hard_val:>12.4f} {gap:>8.4f}")
        print()
        print("  Interpretation:")
        f1_gap = results["Normal test set"]["f1"] - results["Adversarial test set"]["f1"]
        if f1_gap < 0.01:
            print("  F1 gap < 0.01 — transformer is robust to these evasion techniques.")
        elif f1_gap < 0.05:
            print("  F1 gap < 0.05 — mild degradation on adversarial. Acceptable for thesis.")
        else:
            print(f"  F1 gap = {f1_gap:.4f} — notable degradation. "
                  "Consider harder evasion techniques or more augmentation.")


if __name__ == "__main__":
    main()