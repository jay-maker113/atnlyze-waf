"""
src/atnlyze/api/app.py

FastAPI WAF inference gateway.

Endpoints:
  POST /predict        - classify a log line (baseline / transformer / both)
  GET  /stats          - in-memory traffic counters + score distribution
  POST /stats/reset    - clear counters for clean demo start
  GET  /stream         - SSE stream of real-time WAF decisions
"""

from typing import Literal
from fastapi import FastAPI, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import asyncio
import json
import logging
import os
import subprocess
import sys
import threading
import time
from collections import deque
from contextlib import asynccontextmanager

import httpx
from dotenv import load_dotenv

from atnlyze.inference import WAFInferenceEngine, normalize_input
from atnlyze.inference_transformer_onnx import ONNXTransformerWAFInferenceEngine
from atnlyze.parser import parse_log_line
from atnlyze.utils import ATTACK_TYPES, build_structured_text, detect_attack_type

load_dotenv()

logger = logging.getLogger(__name__)

MODEL_PATH      = os.getenv("MODEL_PATH",      "models/baseline.joblib")
VECTORIZER_PATH = os.getenv("VECTORIZER_PATH", "models/vectorizer.joblib")
THRESHOLD       = float(os.getenv("THRESHOLD", "0.5"))
ALERT_THRESHOLD = float(os.getenv("ALERT_THRESHOLD", "0.9"))
NTFY_TOPIC      = os.getenv("NTFY_TOPIC", "")
NTFY_URL        = "https://ntfy.sh"
ALERT_COOLDOWN  = 60  # seconds between notifications

baseline_engine    = None
transformer_engine = None
_event_loop: asyncio.AbstractEventLoop | None = None

_last_alert_time: float = 0.0
_alert_lock = threading.Lock()
_demo_processes: dict[str, subprocess.Popen] = {}
_demo_lock = threading.Lock()


# ── In-memory stats store ─────────────────────────────────────────────────────

class WAFStats:
    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        with self._lock:
            self.total   = 0
            self.blocked = 0
            self.allowed = 0
            self.score_bins = [0] * 10
            self.attack_type_counts = {t: 0 for t in ATTACK_TYPES}
            self.recent_events: deque = deque(maxlen=100)

    def record(self, score: float, decision: str,
               attack_type: str, path: str, model: str):
        with self._lock:
            self.total += 1
            if decision == "block":
                self.blocked += 1
                atype = attack_type if attack_type in ATTACK_TYPES else "unknown"
                self.attack_type_counts[atype] += 1
            else:
                self.allowed += 1
            bin_idx = min(int(score * 10), 9)
            self.score_bins[bin_idx] += 1
            self.recent_events.append({
                "timestamp":   time.time(),
                "path":        path[:80] if path else "-",
                "score":       round(score, 4),
                "decision":    decision,
                "attack_type": attack_type,
                "model":       model,
            })

    def snapshot(self) -> dict:
        with self._lock:
            block_rate = (self.blocked / self.total * 100) if self.total else 0.0
            return {
                "total":              self.total,
                "blocked":            self.blocked,
                "allowed":            self.allowed,
                "block_rate":         round(block_rate, 2),
                "attack_type_counts": dict(self.attack_type_counts),
                "score_distribution": {
                    f"{i/10:.1f}-{(i+1)/10:.1f}": self.score_bins[i]
                    for i in range(10)
                },
                "recent_events": list(self.recent_events),
            }


_stats = WAFStats()


# ── SSE client registry ───────────────────────────────────────────────────────

class SSERegistry:
    def __init__(self):
        self._lock    = threading.Lock()
        self._queues: dict[int, asyncio.Queue] = {}
        self._next_id = 0

    def register(self, queue: asyncio.Queue) -> int:
        with self._lock:
            client_id = self._next_id
            self._next_id += 1
            self._queues[client_id] = queue
        return client_id

    def deregister(self, client_id: int):
        with self._lock:
            self._queues.pop(client_id, None)

    def push(self, event: dict):
        payload = json.dumps(event)
        with self._lock:
            queues = list(self._queues.values())
        loop = _event_loop
        if loop is None or not loop.is_running():
            return
        for queue in queues:
            def _put(q=queue, p=payload):
                try:
                    q.put_nowait(p)
                except asyncio.QueueFull:
                    pass
            loop.call_soon_threadsafe(_put)

    @property
    def client_count(self) -> int:
        with self._lock:
            return len(self._queues)


_sse_registry = SSERegistry()


# ── ntfy alert functions ──────────────────────────────────────────────────────

async def send_attack_alert(score: float, attack_type: str, path: str):
    """
    Push notification for high-confidence attack blocks.
    Fire-and-forget - failure logged, never re-raised.
    Shared 60-second cooldown with probing alert.
    """
    if not NTFY_TOPIC:
        return
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(
                f"{NTFY_URL}/{NTFY_TOPIC}",
                content=f"{attack_type.upper()} blocked - score {score:.2f} - {path}",
                headers={
                    "Title":    "AtnLyze WAF - Attack Blocked",
                    "Priority": "urgent",
                    "Tags":     "warning,shield",
                },
            )
        logger.info(f"ntfy alert sent: {attack_type} score={score:.2f}")
    except Exception as e:
        logger.error(f"ntfy attack alert failed: {e}")


async def send_probing_alert(ambiguous_rate: float):
    """
    Push notification when 0.4-0.6 confidence zone exceeds 30% of traffic.
    This is the adversarial distribution shift detection signal -
    systematic model probing looks like a sustained spike in this zone.
    """
    if not NTFY_TOPIC:
        return
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(
                f"{NTFY_URL}/{NTFY_TOPIC}",
                content=(
                    f"Model probing detected - {ambiguous_rate:.1f}% of traffic "
                    f"in ambiguous confidence zone (0.4-0.6). "
                    f"Possible systematic evasion attempt."
                ),
                headers={
                    "Title":    "AtnLyze WAF - Possible Model Probing",
                    "Priority": "high",
                    "Tags":     "rotating_light,chart_with_upwards_trend",
                },
            )
        logger.info(f"ntfy probing alert sent: ambiguous_rate={ambiguous_rate:.1f}%")
    except Exception as e:
        logger.error(f"ntfy probing alert failed: {e}")


def _schedule_alert(coro):
    """
    Schedule an async alert coroutine from a sync threadpool context.
    Uses run_coroutine_threadsafe - the only safe way to do this from /predict.
    """
    global _last_alert_time
    with _alert_lock:
        now = time.time()
        if now - _last_alert_time < ALERT_COOLDOWN:
            coro.close()
            return
        _last_alert_time = now

    loop = _event_loop
    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(coro, loop)
    else:
        coro.close()


# ── App lifecycle ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global baseline_engine, transformer_engine, _event_loop
    _event_loop = asyncio.get_running_loop()
    baseline_engine = WAFInferenceEngine(
        model_path=MODEL_PATH,
        vectorizer_path=VECTORIZER_PATH,
        threshold=THRESHOLD,
    )
    transformer_engine = ONNXTransformerWAFInferenceEngine(
        onnx_dir="models/bert_waf_onnx",
        threshold=THRESHOLD,
    )
    yield
    with _demo_lock:
        for proc in _demo_processes.values():
            if proc.poll() is None:
                proc.terminate()
        _demo_processes.clear()
    _event_loop = None


app = FastAPI(title="AtnLyze WAF", lifespan=lifespan)


# ── Models ────────────────────────────────────────────────────────────────────

class PredictRequest(BaseModel):
    log_line: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/predict")
def predict(
    req: PredictRequest,
    engine: Literal["baseline", "transformer", "both"] = Query("baseline"),
):
    raw_input = req.log_line
    parsed    = parse_log_line(raw_input)

    text_for_baseline = normalize_input(parsed["raw"] if parsed else raw_input)

    if parsed and parsed.get("method") and parsed.get("path"):
        text_for_transformer = build_structured_text(parsed)
    else:
        text_for_transformer = normalize_input(raw_input)

    response = {}

    if engine in ("baseline", "both"):
        response["baseline"] = baseline_engine.analyze_log_line(text_for_baseline)

    if engine in ("transformer", "both"):
        response["transformer"] = transformer_engine.analyze(text_for_transformer)

    primary = response.get("transformer") or response.get("baseline")
    if primary:
        attack_source = text_for_transformer if parsed else text_for_baseline
        attack_type   = detect_attack_type(attack_source)
        path          = parsed.get("path", "-") if parsed else "-"

        _stats.record(
            score=primary["score"],
            decision=primary["decision"],
            attack_type=attack_type,
            path=path,
            model=primary.get("model", engine),
        )

        # SSE push
        if _sse_registry.client_count > 0:
            _sse_registry.push({
                "timestamp":   time.time(),
                "path":        (path or "-")[:80],
                "score":       primary["score"],
                "decision":    primary["decision"],
                "attack_type": attack_type,
                "model":       primary.get("model", engine),
            })

        # ntfy attack alert - high confidence blocks only
        if (primary["decision"] == "block"
                and primary["score"] >= ALERT_THRESHOLD
                and NTFY_TOPIC):
            _schedule_alert(
                send_attack_alert(primary["score"], attack_type, path or "-")
            )

    return response


@app.get("/stats")
async def get_stats():
    snapshot = _stats.snapshot()

    # Adversarial distribution shift detection
    # 0.4-0.6 zone > 30% of total traffic = possible model probing
    if NTFY_TOPIC and snapshot["total"] >= 50:
        ambiguous = (
            snapshot["score_distribution"].get("0.4-0.5", 0) +
            snapshot["score_distribution"].get("0.5-0.6", 0)
        )
        ambiguous_rate = (ambiguous / snapshot["total"]) * 100
        if ambiguous_rate > 30:
            asyncio.create_task(send_probing_alert(ambiguous_rate))

    return snapshot


@app.post("/stats/reset")
def reset_stats():
    _stats.reset()
    return {"status": "reset", "message": "All counters cleared."}


@app.post("/demo/start-benign")
def demo_start_benign():
    """Start benign_crawler.py as a background subprocess."""
    with _demo_lock:
        if "benign" in _demo_processes:
            proc = _demo_processes["benign"]
            if proc.poll() is None:
                return {"status": "already_running", "pid": proc.pid}

        proc = subprocess.Popen(
            [sys.executable, "scripts/traffic/benign_crawler.py"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _demo_processes["benign"] = proc

        if "feed" not in _demo_processes or _demo_processes["feed"].poll() is not None:
            feed = subprocess.Popen(
                [sys.executable, "scripts/traffic/live_waf_feed.py"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _demo_processes["feed"] = feed

        return {"status": "started", "pid": proc.pid}


@app.post("/demo/start-attack")
def demo_start_attack():
    """Start attack_runner.py as a background subprocess."""
    with _demo_lock:
        if "attack" in _demo_processes:
            proc = _demo_processes["attack"]
            if proc.poll() is None:
                return {"status": "already_running", "pid": proc.pid}

        proc = subprocess.Popen(
            [sys.executable, "scripts/traffic/attack_runner.py"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _demo_processes["attack"] = proc
        return {"status": "started", "pid": proc.pid}


@app.post("/demo/stop")
def demo_stop():
    """Terminate all running demo subprocesses."""
    stopped = []
    with _demo_lock:
        for name, proc in list(_demo_processes.items()):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                stopped.append(name)
        _demo_processes.clear()
    return {"status": "stopped", "processes": stopped}


@app.get("/demo/status")
def demo_status():
    """Check which demo processes are currently running."""
    with _demo_lock:
        return {
            name: "running" if proc.poll() is None else "stopped"
            for name, proc in _demo_processes.items()
        }


@app.get("/stream")
async def stream(request: Request):
    """
    SSE stream of real-time WAF decisions.
    One queue per client, maxsize=100, drop policy on full.

    Connect from browser:
        const es = new EventSource('http://localhost:8001/stream');
        es.onmessage = e => console.log(JSON.parse(e.data));
    """
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    client_id = _sse_registry.register(queue)

    async def event_generator():
        try:
            yield "data: " + json.dumps({
                "type": "connected", "client_id": client_id
            }) + "\n\n"

            while True:
                if await request.is_disconnected():
                    break
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=1.0)
                    yield f"data: {payload}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            _sse_registry.deregister(client_id)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
        },
    )
