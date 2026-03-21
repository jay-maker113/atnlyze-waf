"""
scripts/evaluate_transformer.py

Evaluates the fine-tuned DistilBERT transformer WAF on:
  - data/processed/v2_test_bert.csv       (v2 test set — full)
  - data/processed/v2_test_hard_bert.csv  (adversarial evasion test set)

Per-source and per-attack-type breakdowns included.
ModSec OOD holdout reported separately — that's the honest eval surface.

Compare against evaluate_baseline.py results to validate the thesis:
  "Transformer learns attack semantics, not just keyword patterns."
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

MODEL_DIR  = "models/bert_waf"
BATCH_SIZE = 16
MAX_LENGTH = 128


def load_model(model_dir: str):
    device    = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")
    tokenizer = DistilBertTokenizerFast.from_pretrained(model_dir)
    model     = DistilBertForSequenceClassification.from_pretrained(model_dir)
    model.to(device)
    model.eval()
    return tokenizer, model, device


def run_inference(tokenizer, model, device, texts: list) -> list:
    probs_all = []
    for i in tqdm(range(0, len(texts), BATCH_SIZE), desc="Inferring", leave=False):
        batch  = texts[i : i + BATCH_SIZE]
        inputs = tokenizer(
            batch, padding=True, truncation=True,
            max_length=MAX_LENGTH, return_tensors="pt",
        )
        inputs = {k: v.to(device) for k, v in inputs.items()}
        with torch.no_grad():
            logits = model(**inputs).logits
        probs = torch.softmax(logits, dim=1)[:, 1]
        probs_all.extend(probs.cpu().numpy().tolist())
    return probs_all


def evaluate(tokenizer, model, device,
             df: pd.DataFrame, text_col: str, label: str) -> dict:
    texts  = df[text_col].tolist()
    labels = df["label"].tolist()

    probs = run_inference(tokenizer, model, device, texts)
    preds = [1 if p >= 0.5 else 0 for p in probs]

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

    return {
        "accuracy": accuracy, "precision": precision,
        "recall": recall, "f1": f1, "roc_auc": roc_auc
    }


def evaluate_by_source(tokenizer, model, device,
                       df: pd.DataFrame, text_col: str):
    for source in ["docker", "csic", "modsec"]:
        subset = df[df["source"] == source]
        if len(subset) == 0:
            continue
        evaluate(tokenizer, model, device, subset, text_col,
                 f"Transformer — source: {source}")


def evaluate_by_attack_type(tokenizer, model, device,
                             df: pd.DataFrame, text_col: str):
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
        probs  = run_inference(tokenizer, model, device, texts)
        preds  = [1 if p >= 0.5 else 0 for p in probs]
        p, r, f1, _ = precision_recall_fscore_support(
            labels, preds, average="binary", zero_division=0
        )
        print(f"  {atype:<12} {len(subset):>6} {p:>10.4f} {r:>8.4f} {f1:>8.4f}")


def main():
    print(f"Loading transformer from {MODEL_DIR} ...")
    tokenizer, model, device = load_model(MODEL_DIR)
    print("Loaded.\n")

    # ── Full v2 test set
    try:
        df = pd.read_csv("data/processed/v2_test_bert.csv")
        normal_results = evaluate(
            tokenizer, model, device, df,
            "structured_text", "v2 test set (all sources)"
        )
        evaluate_by_source(tokenizer, model, device, df, "structured_text")
        evaluate_by_attack_type(tokenizer, model, device, df, "structured_text")
    except FileNotFoundError:
        print("SKIPPED: v2_test_bert.csv not found.")
        normal_results = None

    # ── ModSec OOD holdout — reported separately
    try:
        df_full = pd.read_csv("data/processed/v2_test_bert.csv")
        modsec  = df_full[df_full["source"] == "modsec"]
        if len(modsec) > 0:
            evaluate(tokenizer, model, device, modsec,
                     "structured_text",
                     "ModSec OOD holdout (genuinely unseen distribution)")
    except FileNotFoundError:
        pass

    # ── Adversarial hard test set
    hard_results = None
    try:
        hard_df      = pd.read_csv("data/processed/v2_test_hard_bert.csv")
        hard_results = evaluate(
            tokenizer, model, device, hard_df,
            "structured_text", "Adversarial hard test (evasion mutations applied)"
        )
        evaluate_by_attack_type(
            tokenizer, model, device, hard_df, "structured_text"
        )
    except FileNotFoundError:
        print("\nSKIPPED: v2_test_hard_bert.csv not found — run build_hard_test_set.py first.")

    # ── Normal vs Adversarial summary — the thesis differentiator
    if normal_results and hard_results:
        print("\n" + "=" * 55)
        print("  SUMMARY — Normal vs Adversarial")
        print("  (gap = transformer robustness to evasion)")
        print("=" * 55)
        print(f"  {'Metric':<12} {'Normal':>10} {'Adversarial':>12} {'Gap':>8}")
        print(f"  {'-'*46}")
        for metric in ("accuracy", "precision", "recall", "f1", "roc_auc"):
            nv  = normal_results[metric]
            hv  = hard_results[metric]
            gap = nv - hv
            print(f"  {metric:<12} {nv:>10.4f} {hv:>12.4f} {gap:>8.4f}")
        print()
        f1_gap = normal_results["f1"] - hard_results["f1"]
        if f1_gap < 0.01:
            print("  F1 gap < 0.01 — transformer is robust to these evasion techniques.")
        elif f1_gap < 0.05:
            print("  F1 gap < 0.05 — mild degradation on adversarial. Acceptable for thesis.")
        else:
            print(f"  F1 gap = {f1_gap:.4f} — notable degradation. "
                  "Consider harder evasion or more augmentation.")


if __name__ == "__main__":
    main()
