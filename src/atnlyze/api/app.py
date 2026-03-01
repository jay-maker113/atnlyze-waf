from typing import Literal

from fastapi import FastAPI, Query
from pydantic import BaseModel
import os
from contextlib import asynccontextmanager

from atnlyze.inference import WAFInferenceEngine, normalize_input
# from atnlyze.inference_transformer import TransformerWAFInferenceEngine
from atnlyze.inference_transformer_onnx import ONNXTransformerWAFInferenceEngine
from atnlyze.parser import parse_log_line
from atnlyze.utils import build_structured_text


MODEL_PATH = os.getenv("MODEL_PATH", "models/baseline.joblib")
VECTORIZER_PATH = os.getenv("VECTORIZER_PATH", "models/vectorizer.joblib")
THRESHOLD = float(os.getenv("THRESHOLD", "0.5"))

baseline_engine = None
transformer_engine = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global baseline_engine, transformer_engine
    baseline_engine = WAFInferenceEngine(
        model_path=MODEL_PATH,
        vectorizer_path=VECTORIZER_PATH,
        threshold=THRESHOLD
    )
    transformer_engine = ONNXTransformerWAFInferenceEngine(
        onnx_dir="models/bert_waf_onnx",
        threshold=THRESHOLD
    )

    # transformer_engine = TransformerWAFInferenceEngine(
    #     model_dir="models/bert_waf",
    #     threshold=THRESHOLD
    # )
    yield

app = FastAPI(title="AtnLyze WAF", lifespan=lifespan)


class PredictRequest(BaseModel):
    log_line: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/predict")
def predict(
    req: PredictRequest,
    # Literal enforces runtime validation via Pydantic — returns 422 on unknown values.
    # Query(enum=[...]) with bare str type is OpenAPI documentation only, not enforced.
    engine: Literal["baseline", "transformer", "both"] = Query("baseline"),
):
    raw_input = req.log_line
    parsed = parse_log_line(raw_input)

    # Baseline was trained on normalized raw log text — feed it exactly that.
    text_for_baseline = normalize_input(parsed["raw"] if parsed else raw_input)

    # Transformer was trained on structured token format from build_transformer_dataset.py.
    # Feeding it raw text is a training/serving skew bug — always build structured text here.
    if parsed and parsed.get("method") and parsed.get("path"):
        text_for_transformer = build_structured_text(parsed)
    else:
        # Parse failed — fallback to normalized raw, but this will degrade accuracy.
        # If this happens frequently, fix parse_log_line() to handle those log formats.
        text_for_transformer = normalize_input(raw_input)

    response = {}

    if engine in ("baseline", "both"):
        response["baseline"] = baseline_engine.analyze_log_line(text_for_baseline)

    if engine in ("transformer", "both"):
        response["transformer"] = transformer_engine.analyze(text_for_transformer)

    return response
