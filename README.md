<div align="center">

<img src="https://img.shields.io/badge/AtnLyze-WAF-1a9850?style=for-the-badge&logo=shield&logoColor=white" alt="AtnLyze WAF"/>

# 🛡️ AtnLyze WAF
### Transformer-Based Web Application Firewall for Real-Time HTTP Traffic Classification

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![DistilBERT](https://img.shields.io/badge/DistilBERT-HuggingFace-FFD21E?style=flat-square&logo=huggingface&logoColor=black)](https://huggingface.co)
[![ONNX](https://img.shields.io/badge/ONNX-Runtime-005CED?style=flat-square&logo=onnx&logoColor=white)](https://onnxruntime.ai)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

---

**AtnLyze WAF** replaces brittle regex rule sets with a fine-tuned **DistilBERT** transformer that understands the *semantic intent* behind HTTP requests — classifying traffic across **11 distinct attack categories** in real time with **zero manual signature maintenance**.

</div>

---

## 📊 Performance at a Glance

| Metric | Value |
|--------|-------|
| 🎯 **F1-Score (Standard Test)** | **91.45%** |
| 🔴 **F1-Score (Adversarial Test)** | **91.46%** |
| 🧪 **OOD Recall (ModSecurity logs)** | **82.13%** |
| ⚡ **ONNX Median Latency (CPU)** | **35.8 ms** |
| 🚀 **ONNX Speedup vs PyTorch** | **2.1× faster** |
| 📦 **Model Size (ONNX INT8)** | **64 MB** (75% reduction) |
| 🔒 **Adversarial Robustness Gap** | **< 0.01%** |

> All benchmarks run on CPU-only hardware (no GPU required). Dataset: **40,652 test samples** across **11 attack categories**.

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        HTTP Traffic                              │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │    Nginx    │  ← Reverse Proxy + Access Logging
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │   FastAPI   │  ← API Gateway (Gunicorn + Uvicorn)
                    └──────┬──────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
    ┌──────▼──────┐        │      ┌────────▼────────┐
    │  TF-IDF +   │        │      │   DistilBERT    │
    │     LR      │        │      │  (ONNX INT8)    │
    │  Baseline   │        │      │   Transformer   │
    └──────┬──────┘        │      └────────┬────────┘
           │               │               │
           └───────────────▼───────────────┘
                    ┌──────┴──────┐
                    │  Decision   │  ← Score fusion + confidence zone
                    │   Engine   │     (Uncertain: 0.4 – 0.6 flagged)
                    └──────┬──────┘
                           │
           ┌───────────────┼───────────────┐
           │                               │
    ┌──────▼──────┐                ┌───────▼───────┐
    │   React     │                │   ntfy.sh     │
    │  Dashboard  │                │  Push Alerts  │
    │ (SSE Live)  │                │  (score>0.9)  │
    └─────────────┘                └───────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Docker Desktop (for Nginx + traffic simulation)
- Node.js 18+ (for React dashboard)

### 1. Clone & Setup

```bash
git clone https://github.com/your-username/atnlyze-waf.git
cd atnlyze-waf

# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS

pip install -r requirements.txt
pip install -e .
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env — set your LAN IP if demoing on mobile
```

### 3. Start Docker (Nginx + Traffic Targets)

```bash
docker compose -f docker/docker-compose.yml up -d
```

### 4. Start Backend

```bash
.\.venv\Scripts\uvicorn.exe src.atnlyze.api.app:app --host 0.0.0.0 --port 8001
```

Health check → `http://localhost:8001/health`

### 5. Start Frontend

```bash
cd frontend
npx vite --host 0.0.0.0 --port 5173
```

Dashboard → `http://localhost:5173`

---

## 🧠 Dual-Engine Inference Pipeline

```
HTTP Request
    │
    ▼
┌─────────────────┐
│  Nginx Log Line  │  "GET /admin?id=1 OR 1=1 HTTP/1.1 ..."
└────────┬─────────┘
         │ idempotent URL + HTML decode (anti-evasion)
         ▼
┌─────────────────┐
│  Structured Text │  "method=GET path=/admin query=id=1 OR 1=1 ..."
└────┬────────┬───┘
     │        │
     ▼        ▼
┌────────┐  ┌──────────────────┐
│ TF-IDF │  │ DistilBERT       │
│  + LR  │  │ Tokenizer → ONNX │
│Baseline│  │ INT8 Inference   │
└────┬───┘  └────────┬─────────┘
     │               │
     └───────┬───────┘
             ▼
     ┌───────────────┐
     │ Score Fusion  │  Both scores compared
     │ + Confidence  │  Disagreement → flagged (0.4-0.6 zone)
     └───────┬───────┘
             │
    ┌────────┴─────────┐
    │                  │
    ▼                  ▼
BLOCK/ALLOW     Attack Category
              (sqli / xss / cmdi / ...)
```

---

## 📁 Project Structure

```
atnlyze-waf/
├── src/
│   └── atnlyze/
│       ├── api/                   # FastAPI routes, SSE, demo control
│       ├── model/                 # DistilBERT fine-tuning & ONNX export
│       ├── inference.py           # Baseline TF-IDF + LR inference
│       ├── inference_transformer_onnx.py  # ONNX INT8 inference engine
│       ├── parser.py              # Nginx log line parser
│       ├── tokenizer.py           # DistilBERT tokenizer wrapper
│       └── utils.py               # Idempotent decode + attack detection
│
├── scripts/
│   ├── train_baseline.py          # Train TF-IDF + LR baseline
│   ├── train_transformer.py       # Fine-tune DistilBERT
│   ├── evaluate_baseline.py       # Evaluate baseline on test sets
│   ├── evaluate_transformer.py    # Evaluate transformer (standard + adversarial + OOD)
│   ├── export_onnx.py             # Export PyTorch → ONNX
│   ├── quantize_onnx.py           # INT8 dynamic quantization
│   ├── benchmark_onnx.py          # Latency benchmark (PyTorch vs ONNX)
│   ├── build_dataset.py           # Dataset construction pipeline
│   └── augment_attacks.py         # Adversarial payload augmentation
│
├── frontend/                      # React 18 + Vite dashboard
├── docker/                        # Nginx + docker-compose targets
├── notebooks/                     # EDA and analysis notebooks
├── data/                          # Processed datasets (gitignored)
├── models/                        # Saved weights (gitignored)
├── tests/                         # Pytest unit + integration tests
├── DEMO.md                        # Exhibition runbook
└── .env.example                   # Environment template
```

---

## 🎯 Attack Categories Detected

| Category | F1-Score | Category | F1-Score |
|----------|----------|----------|----------|
| Path Traversal | 1.0000 | LFI | 0.9304 |
| LDAP Injection | 1.0000 | CMDi | 0.9046 |
| Unknown/Anomaly | 0.9929 | SQLi | 0.8997 |
| RFI | 0.9912 | Scanner | 0.8532 |
| XSS | 0.9639 | PHP Injection | 0.6090 |
| | | NoSQL | N/A* |

> *NoSQL: No MongoDB endpoints in any training source — excluded from evaluation.

---

## 📈 Model Training Pipeline

```bash
# 1. Build unified dataset
python scripts/build_dataset.py

# 2. Augment with adversarial payloads
python scripts/augment_attacks.py

# 3. Train baseline (TF-IDF + Logistic Regression)
python scripts/train_baseline.py

# 4. Fine-tune DistilBERT transformer
python scripts/train_transformer.py

# 5. Export to ONNX
python scripts/export_onnx.py

# 6. Quantize to INT8
python scripts/quantize_onnx.py

# 7. Evaluate
python scripts/evaluate_transformer.py
python scripts/evaluate_baseline.py

# 8. Benchmark latency
python scripts/benchmark_onnx.py
```

---

## ⚡ ONNX Optimization Results

| Metric | PyTorch (FP32) | ONNX (INT8) | Improvement |
|--------|---------------|-------------|-------------|
| Mean Latency | 80.6 ms | 37.0 ms | **2.2×** |
| Median Latency | 75.2 ms | 35.8 ms | **2.1×** |
| P95 Latency | 115.2 ms | 50.7 ms | **2.3×** |
| P99 Latency | 185.7 ms | 54.2 ms | **3.4×** |
| Model Size | 255 MB | 64 MB | **75% smaller** |

> Benchmarked over **45 runs** on CPU-only hardware (no GPU).

---

## ⚙️ Model Specifications & Scalability

- **Model Parameters:** Built on DistilBERT natively containing **66 million parameters** (66,362,880 exact). With INT8 quantization, the exact 66M structural capacity is retained while the disk footprint shrinks to **64 MB**.
- **RAM per Request:** The optimized architecture yields an extremely lightweight runtime. A single 512-token inference creates a peak memory footprint of only **~15 MB** above the pre-loaded baseline, which is instantly garbage-collected post-inference.
- **Concurrency & Scaling:** The asynchronous FastAPI/Gunicorn backend easily sustains multiple concurrent users without dropping requests. A single standard laptop CPU core natively processes **~30 requests/second**. Due to its stateless design, defending an enterprise API with 5,000+ requests/sec simply scales horizontally across a standard Kubernetes cluster.

---

## 🖥️ Live Dashboard Features

The React dashboard connects via **Server-Sent Events (SSE)** for zero-poll real-time updates:

- 📡 **Live request stream** — every classified request displayed instantly
- 📊 **Attack type distribution** — live donut chart
- 📈 **Model telemetry** — per-engine scores, confidence zone tracking
- 🔔 **Push alerts** — high-confidence detections (score > 0.9) routed to ntfy.sh
- 🧮 **Score drift panel** — adversarial confidence band monitoring (0.4 – 0.6)

---

## 🔬 Evaluation Highlights

```
Binary Classification (n = 40,652):
  ┌──────────────┬────────────────┐
  │ True Negative│  False Positive│
  │   6,324      │      14        │← near-perfect precision
  ├──────────────┼────────────────┤
  │ False Negative│ True Positive │
  │   5,393      │   28,921       │
  └──────────────┴────────────────┘

  Precision : 0.9995   Recall : 0.8428
  F1-Score  : 0.9145   ROC AUC: 0.9682
```

**Adversarial Robustness** — Standard vs Adversarial F1 gap: **< 0.01%**
This proves the model understands *semantic structure*, not surface-level patterns.

**Out-of-Distribution Generalization** — Tested on real ModSecurity audit logs (never seen during training):
- OOD F1: **90.19%**
- OOD Recall: **82.13%**

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **ML / AI** | DistilBERT (HuggingFace), Scikit-learn, ONNX Runtime |
| **Backend** | Python 3.11, FastAPI, Uvicorn, Gunicorn |
| **Frontend** | React 18, Vite, Recharts, Axios |
| **Infrastructure** | Docker, Nginx, ntfy.sh |
| **Training** | PyTorch, Google Colab (A100 GPU) |
| **Data** | CSIC 2010, ModSecurity Audit Logs, Synthetic augmentation |

---

## 📋 API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | System health check |
| `/predict` | POST | Classify a single log line |
| `/stats` | GET | Real-time WAF statistics |
| `/stream` | GET | SSE event stream (live feed) |
| `/demo/start_benign` | POST | Start benign traffic simulation |
| `/demo/start_attack` | POST | Start attack traffic simulation |
| `/demo/stop` | POST | Stop all traffic |
| `/demo/status` | GET | Current demo state |
| `/demo/reset` | POST | Reset all statistics |

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

---

## 📖 Documentation

- [`DEMO.md`](DEMO.md) — Full exhibition runbook with startup order, failure fallbacks, and rehearsal checklist
- [`scripts/`](scripts/) — All training, evaluation, and export scripts with inline documentation

---

## 🎓 Academic Context

> **Project ID:** IU/IITE/CSE/2026/UDP083
> **Author:** Jay Vagadia (IU2241230451)
> **Guide:** Dr. Shweta Brahmbhatt, Assistant Professor
> **Institution:** Department of Computer Science & Engineering, IITE, Indus University, Ahmedabad

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Made with 🛡️ by **Jay Vagadia** · [Indus University](https://indusuni.ac.in)

*"Semantic understanding over surface-level pattern matching."*

</div>