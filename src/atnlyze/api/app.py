from fastapi import FastAPI
from pydantic import BaseModel
import os
from contextlib import asynccontextmanager

from atnlyze.inference import WAFInferenceEngine

MODEL_PATH = os.getenv("MODEL_PATH", "models/baseline.joblib")
VECTORIZER_PATH = os.getenv("VECTORIZER_PATH", "models/vectorizer.joblib")
THRESHOLD = float(os.getenv("THRESHOLD", 0.5))

engine = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine
    engine = WAFInferenceEngine(
        model_path=MODEL_PATH,
        vectorizer_path=VECTORIZER_PATH,
        threshold=THRESHOLD
    )
    yield


app = FastAPI(title="AtnLyze WAF", lifespan=lifespan)


class PredictRequest(BaseModel):
    log_line: str


class PredictResponse(BaseModel):
    label: str
    score: float
    decision: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    result = engine.analyze_log_line(req.log_line)
    return result
