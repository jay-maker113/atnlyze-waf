"""
scripts/quantize_onnx.py

Applies INT8 dynamic quantization to the exported ONNX model.
Reduces model size ~4x, improves CPU inference speed 2-4x.
No retraining required.

Run after export_onnx.py:
    python scripts/quantize_onnx.py

Then run benchmark_onnx.py to verify speedup and accuracy preservation.
If accuracy drops > 0.5% F1, revert by deleting model_int8.onnx.
"""

import os
import shutil
from onnxruntime.quantization import quantize_dynamic, QuantType

ONNX_MODEL_PATH    = "models/bert_waf_onnx/model.onnx"
QUANTIZED_PATH     = "models/bert_waf_onnx/model_int8.onnx"
BACKUP_PATH        = "models/bert_waf_onnx/model_fp32_backup.onnx"


def main():
    if not os.path.exists(ONNX_MODEL_PATH):
        print(f"ERROR: {ONNX_MODEL_PATH} not found. Run export_onnx.py first.")
        return

    # Backup original before quantizing
    if not os.path.exists(BACKUP_PATH):
        shutil.copy(ONNX_MODEL_PATH, BACKUP_PATH)
        print(f"Backed up original to {BACKUP_PATH}")
    else:
        print(f"Backup already exists at {BACKUP_PATH}")

    original_mb   = os.path.getsize(ONNX_MODEL_PATH) / (1024 * 1024)
    print(f"Original model size : {original_mb:.1f} MB")
    print(f"Quantizing to INT8...")

    quantize_dynamic(
        ONNX_MODEL_PATH,
        QUANTIZED_PATH,
        weight_type=QuantType.QInt8,
        # Quantize all supported operator types
        # MatMul and Gemm are the expensive ones in transformer attention
        #optimize_model=True,
    )

    quantized_mb = os.path.getsize(QUANTIZED_PATH) / (1024 * 1024)
    print(f"Quantized model size: {quantized_mb:.1f} MB")
    print(f"Size reduction      : {original_mb/quantized_mb:.1f}x")
    print()

    # Swap in quantized model as the active model
    shutil.copy(QUANTIZED_PATH, ONNX_MODEL_PATH)
    print(f"Swapped {QUANTIZED_PATH} → {ONNX_MODEL_PATH}")
    print()
    print("Next steps:")
    print("  1. python scripts/benchmark_onnx.py  — verify speedup + accuracy")
    print("  2. If accuracy drops > 0.5% F1, restore backup:")
    print(f"     copy {BACKUP_PATH} {ONNX_MODEL_PATH}")


if __name__ == "__main__":
    main()