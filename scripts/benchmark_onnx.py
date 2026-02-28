"""
scripts/benchmark_onnx.py

Benchmarks PyTorch vs ONNX Runtime inference latency on the same inputs.
Reports per-sample latency and speedup ratio.

Usage:
    python scripts/benchmark_onnx.py

Requires export_onnx.py to have been run first.
"""

import time
import numpy as np
import torch
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
import onnxruntime as ort

PYTORCH_MODEL_DIR = "models/bert_waf"
ONNX_MODEL_PATH   = "models/bert_waf_onnx/model.onnx"
MAX_LENGTH        = 128
WARMUP_RUNS       = 5    # discard — JIT/ORT compilation happens here
BENCHMARK_RUNS    = 50   # measure these

# Representative samples — mix of benign and malicious, different lengths
BENCHMARK_INPUTS = [
    "[method] get [path] /dvwa/login.php [query] - [ua] mozilla/5.0 [referer] - [status] 200",
    "[method] get [path] /dvwa/vulnerabilities/sqli/ [query] id=1 union select user,password from users-- [ua] sqlmap/1.7 [referer] - [status] 200",
    "[method] get [path] /dvwa/vulnerabilities/xss_r/ [query] name=<script>alert(1)</script> [ua] mozilla/5.0 [referer] - [status] 200",
    "[method] get [path] /dvwa/vulnerabilities/fi/ [query] page=../../../etc/passwd [ua] curl/8.0 [referer] - [status] 200",
    "[method] get [path] /juice/rest/products/search [query] q=apple [ua] mozilla/5.0 [referer] - [status] 200",
]


# ── PyTorch inference

def load_pytorch(model_dir: str):
    tokenizer = DistilBertTokenizerFast.from_pretrained(model_dir)
    model = DistilBertForSequenceClassification.from_pretrained(model_dir)
    model.eval()
    return tokenizer, model


def pytorch_predict(tokenizer, model, text: str) -> float:
    inputs = tokenizer(
        text, truncation=True, padding=True,
        max_length=MAX_LENGTH, return_tensors="pt"
    )
    with torch.no_grad():
        logits = model(**inputs).logits
    return torch.softmax(logits, dim=1)[0][1].item()


def benchmark_pytorch(tokenizer, model) -> list:
    latencies = []
    for _ in range(WARMUP_RUNS):
        pytorch_predict(tokenizer, model, BENCHMARK_INPUTS[0])
    for text in BENCHMARK_INPUTS * (BENCHMARK_RUNS // len(BENCHMARK_INPUTS) + 1):
        t0 = time.perf_counter()
        pytorch_predict(tokenizer, model, text)
        latencies.append((time.perf_counter() - t0) * 1000)  # ms
    return latencies[:BENCHMARK_RUNS]


# ── ONNX Runtime inference

def load_onnx(onnx_path: str, tokenizer_dir: str):
    tokenizer = DistilBertTokenizerFast.from_pretrained(tokenizer_dir)
    # Use CPUExecutionProvider — no CUDA needed
    sess_options = ort.SessionOptions()
    sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    session = ort.InferenceSession(
        onnx_path,
        sess_options=sess_options,
        providers=["CPUExecutionProvider"],
    )
    return tokenizer, session


def onnx_predict(tokenizer, session, text: str) -> float:
    inputs = tokenizer(
        text, truncation=True, padding=True,
        max_length=MAX_LENGTH, return_tensors="np"  # ONNX Runtime takes numpy
    )
    ort_inputs = {
        "input_ids":      inputs["input_ids"].astype(np.int64),
        "attention_mask": inputs["attention_mask"].astype(np.int64),
    }
    logits = session.run(["logits"], ort_inputs)[0]
    # Softmax manually — avoid importing torch just for this
    exp_logits = np.exp(logits - logits.max(axis=1, keepdims=True))
    probs = exp_logits / exp_logits.sum(axis=1, keepdims=True)
    return float(probs[0][1])


def benchmark_onnx(tokenizer, session) -> list:
    latencies = []
    for _ in range(WARMUP_RUNS):
        onnx_predict(tokenizer, session, BENCHMARK_INPUTS[0])
    for text in BENCHMARK_INPUTS * (BENCHMARK_RUNS // len(BENCHMARK_INPUTS) + 1):
        t0 = time.perf_counter()
        onnx_predict(tokenizer, session, text)
        latencies.append((time.perf_counter() - t0) * 1000)
    return latencies[:BENCHMARK_RUNS]


# ── Correctness check

def verify_outputs_match(pt_tok, pt_model, onnx_tok, onnx_sess):
    """
    ONNX export must produce byte-identical (within float tolerance) outputs.
    If this fails, the export is broken — do not use the ONNX model.
    """
    print("Verifying output correctness (PyTorch vs ONNX)...")
    max_diff = 0.0
    for text in BENCHMARK_INPUTS:
        pt_prob   = pytorch_predict(pt_tok, pt_model, text)
        onnx_prob = onnx_predict(onnx_tok, onnx_sess, text)
        diff = abs(pt_prob - onnx_prob)
        max_diff = max(max_diff, diff)
        status = "✓" if diff < 1e-4 else "✗ MISMATCH"
        print(f"  {status}  PyTorch={pt_prob:.6f}  ONNX={onnx_prob:.6f}  diff={diff:.2e}")
    if max_diff > 1e-4:
        raise RuntimeError(
            f"Output mismatch too large ({max_diff:.2e}). "
            "Do not use this ONNX model — re-export with export_onnx.py."
        )
    print(f"  Max diff: {max_diff:.2e} — outputs match. ONNX export is valid.\n")


# ── Main

def print_stats(name: str, latencies: list):
    arr = np.array(latencies)
    print(f"  {name}")
    print(f"    Mean   : {arr.mean():.1f} ms")
    print(f"    Median : {np.median(arr):.1f} ms")
    print(f"    P95    : {np.percentile(arr, 95):.1f} ms")
    print(f"    P99    : {np.percentile(arr, 99):.1f} ms")
    print(f"    Min    : {arr.min():.1f} ms")
    print(f"    Max    : {arr.max():.1f} ms")


def main():
    import os
    if not os.path.exists(ONNX_MODEL_PATH):
        print(f"ERROR: {ONNX_MODEL_PATH} not found.")
        print("Run first: python scripts/export_onnx.py")
        return

    print("Loading PyTorch model...")
    pt_tok, pt_model = load_pytorch(PYTORCH_MODEL_DIR)

    print("Loading ONNX Runtime session...")
    onnx_tok, onnx_sess = load_onnx(
        ONNX_MODEL_PATH,
        tokenizer_dir="models/bert_waf_onnx/tokenizer"
    )

    print()
    verify_outputs_match(pt_tok, pt_model, onnx_tok, onnx_sess)

    print(f"Benchmarking ({BENCHMARK_RUNS} runs each, {WARMUP_RUNS} warmup discarded)...\n")

    pt_latencies   = benchmark_pytorch(pt_tok, pt_model)
    onnx_latencies = benchmark_onnx(onnx_tok, onnx_sess)

    print("=" * 50)
    print("  LATENCY RESULTS")
    print("=" * 50)
    print_stats("PyTorch (baseline)", pt_latencies)
    print()
    print_stats("ONNX Runtime (optimized)", onnx_latencies)
    print()

    speedup = np.median(pt_latencies) / np.median(onnx_latencies)
    print(f"  Speedup (median): {speedup:.1f}x")
    print()

    # Cascade architecture estimate
    uncertain_fraction = 0.20
    baseline_ms = 2.0  # TF-IDF is ~2ms
    onnx_median = np.median(onnx_latencies)
    cascade_avg = baseline_ms + (uncertain_fraction * onnx_median)
    print("=" * 50)
    print("  CASCADE ARCHITECTURE ESTIMATE")
    print("=" * 50)
    print(f"  Assumption: {uncertain_fraction*100:.0f}% of requests reach transformer")
    print(f"  Baseline (TF-IDF)     : ~{baseline_ms:.0f} ms  (all requests)")
    print(f"  Transformer (ONNX)    : ~{onnx_median:.0f} ms  (uncertain only)")
    print(f"  Weighted average      : ~{cascade_avg:.1f} ms per request")
    print(f"\n  Pure transformer      : ~{onnx_median:.0f} ms per request")
    print(f"  Improvement           : {onnx_median/cascade_avg:.1f}x via cascade")


if __name__ == "__main__":
    main()