"""
scripts/export_onnx.py

Exports the fine-tuned DistilBERT WAF model to ONNX format for fast CPU inference.

Why ONNX:
    PyTorch inference runs through the Python interpreter with dynamic graph overhead.
    ONNX Runtime executes a static, optimized computation graph in pure C++.
    Result: 3-5x speedup on CPU, byte-identical outputs, no retraining needed.

Output format (external data — torch >= 2.1 default with dynamo=False):
    models/bert_waf_onnx/model.onnx        (~0.8 MB  — graph structure)
    models/bert_waf_onnx/model.onnx.data   (~267 MB  — weights)
    models/bert_waf_onnx/tokenizer/        — tokenizer files

DEPLOYMENT NOTE: model.onnx and model.onnx.data must always stay in the same
directory. ONNX Runtime loads both automatically. Moving only model.onnx will
produce wrong predictions with no error.

Usage:
    pip install onnx onnxruntime
    python scripts/export_onnx.py

After export, run benchmark:
    python scripts/benchmark_onnx.py
"""

import os
import shutil
import torch
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification

PYTORCH_MODEL_DIR = "models/bert_waf"
ONNX_OUTPUT_DIR   = "models/bert_waf_onnx"
ONNX_MODEL_PATH   = os.path.join(ONNX_OUTPUT_DIR, "model.onnx")
TOKENIZER_OUT_DIR = os.path.join(ONNX_OUTPUT_DIR, "tokenizer")

MAX_LENGTH = 128
MIN_EXPECTED_MB = 200  # combined weights must exceed this or export is broken


def get_export_size_mb(onnx_path: str) -> float:
    """
    Returns total size of the ONNX export in MB.
    Handles both single-file and external data format:
      - Single file: just model.onnx
      - External data: model.onnx + model.onnx.data (torch>=2.1 default)
    """
    total = os.path.getsize(onnx_path)
    data_file = onnx_path + ".data"
    if os.path.exists(data_file):
        total += os.path.getsize(data_file)
    return total / (1024 * 1024)


def export():
    os.makedirs(ONNX_OUTPUT_DIR, exist_ok=True)

    print(f"Loading PyTorch model from {PYTORCH_MODEL_DIR} ...")
    tokenizer = DistilBertTokenizerFast.from_pretrained(PYTORCH_MODEL_DIR)
    model = DistilBertForSequenceClassification.from_pretrained(PYTORCH_MODEL_DIR)
    model.eval()

    # Dummy input for tracing — shape matters, content does not
    dummy_input_ids      = torch.zeros(1, MAX_LENGTH, dtype=torch.long)
    dummy_attention_mask = torch.ones(1, MAX_LENGTH, dtype=torch.long)

    print(f"Exporting to {ONNX_MODEL_PATH} ...")

    with torch.no_grad():
        torch.onnx.export(
            model,
            (dummy_input_ids, dummy_attention_mask),
            ONNX_MODEL_PATH,
            input_names=["input_ids", "attention_mask"],
            output_names=["logits"],
            dynamic_axes={
                "input_ids":      {0: "batch_size", 1: "sequence_length"},
                "attention_mask": {0: "batch_size", 1: "sequence_length"},
                "logits":         {0: "batch_size"},
            },
            opset_version=18,
            do_constant_folding=True,
            dynamo=False,
        )

    # Validate combined size — works for both single-file and external data format
    total_mb = get_export_size_mb(ONNX_MODEL_PATH)
    data_file = ONNX_MODEL_PATH + ".data"
    if os.path.exists(data_file):
        print(f"  model.onnx      : {os.path.getsize(ONNX_MODEL_PATH)/(1024*1024):.1f} MB (graph)")
        print(f"  model.onnx.data : {os.path.getsize(data_file)/(1024*1024):.1f} MB (weights)")
        print(f"  Combined        : {total_mb:.1f} MB")
    else:
        print(f"  model.onnx      : {total_mb:.1f} MB (single file)")

    if total_mb < MIN_EXPECTED_MB:
        print(f"\nERROR: Combined export size {total_mb:.1f} MB is below {MIN_EXPECTED_MB} MB.")
        print("Weights were likely not exported. Check torch/onnx versions.")
        return

    print(f"Copying tokenizer to {TOKENIZER_OUT_DIR} ...")
    if os.path.exists(TOKENIZER_OUT_DIR):
        shutil.rmtree(TOKENIZER_OUT_DIR)
    tokenizer.save_pretrained(TOKENIZER_OUT_DIR)

    print(f"\nExport complete.  ✓")
    print(f"  Tokenizer : {TOKENIZER_OUT_DIR}/")
    if os.path.exists(data_file):
        print(f"  NOTE: Keep model.onnx and model.onnx.data in the same directory.")
    print(f"\nNext step: python scripts/benchmark_onnx.py")


if __name__ == "__main__":
    export()