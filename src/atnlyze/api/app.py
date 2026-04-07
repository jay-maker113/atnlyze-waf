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
from fastapi.middleware.cors import CORSMiddleware
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
from collections import Counter, deque
from contextlib import asynccontextmanager

import httpx
from dotenv import load_dotenv

from atnlyze.inference import WAFInferenceEngine, normalize_input
from atnlyze.inference_transformer_onnx import ONNXTransformerWAFInferenceEngine
from atnlyze.parser import parse_log_line
from atnlyze.utils import ATTACK_TYPES, build_structured_text, detect_attack_type

load_dotenv()

logger = logging.getLogger(__name__)

MODEL_PATH = os.getenv("MODEL_PATH", "models/baseline.joblib")
VECTORIZER_PATH = os.getenv("VECTORIZER_PATH", "models/vectorizer.joblib")
THRESHOLD = float(os.getenv("THRESHOLD", "0.5"))
ALERT_THRESHOLD = float(os.getenv("ALERT_THRESHOLD", "0.9"))
NTFY_TOPIC = os.getenv("NTFY_TOPIC", "")
NTFY_URL = "https://ntfy.sh"
ALERT_COOLDOWN = 60  # seconds between notifications

baseline_engine = None
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
            self.total = 0
            self.blocked = 0
            self.allowed = 0
            self.score_bins = [0] * 10
            self.engine_score_bins = {
                "baseline": [0] * 10,
                "transformer": [0] * 10,
            }
            self.attack_type_counts = {t: 0 for t in ATTACK_TYPES}
            self.recent_events: deque = deque(maxlen=100)
            self.recent_decisions: deque = deque()
            self.recent_alerts: deque = deque()
            self.recent_scores: deque = deque()
            self.latency_samples_ms: deque = deque(maxlen=500)
            self.engine_latency_samples_ms = {
                "baseline": deque(maxlen=500),
                "transformer": deque(maxlen=500),
            }
            self.path_counts: Counter = Counter()
            self.second_buckets: Counter = Counter()
            self.high_confidence_blocks = 0
            self.uncertain_scores = 0
            self.current_rps_2s = 0.0
            self.peak_rps_2s = 0.0
            self.reset_started_at = time.time()
            self.engine_blocked = {
                "baseline": 0,
                "transformer": 0,
            }
            self.unknown_blocked = 0
            self.unknown_allowed = 0
            self.comparison_total = 0
            self.comparison_agreements = 0
            self.comparison_disagreements = 0
            self.recent_disagreement_events: deque = deque(maxlen=20)

    def record(self, score: float, decision: str,
               attack_type: str, path: str, model: str, latency_ms: float):
        with self._lock:
            now = time.time()
            self.total += 1
            if decision == "block":
                self.blocked += 1
                atype = attack_type if attack_type in ATTACK_TYPES else "unknown"
                self.attack_type_counts[atype] += 1
                if atype == "unknown":
                    self.unknown_blocked += 1
                if score >= ALERT_THRESHOLD:
                    self.high_confidence_blocks += 1
                    self.recent_alerts.append(now)
            else:
                self.allowed += 1
                if attack_type == "unknown":
                    self.unknown_allowed += 1
            if 0.4 <= score < 0.6:
                self.uncertain_scores += 1
            self.recent_decisions.append((now, decision))
            self.recent_scores.append((now, float(score)))
            recent_cutoff = now - 30
            previous_cutoff = now - 60
            while self.recent_decisions and self.recent_decisions[0][0] < recent_cutoff:
                self.recent_decisions.popleft()
            while self.recent_alerts and self.recent_alerts[0] < recent_cutoff:
                self.recent_alerts.popleft()
            while self.recent_scores and self.recent_scores[0][0] < previous_cutoff:
                self.recent_scores.popleft()
            bin_idx = min(int(score * 10), 9)
            self.score_bins[bin_idx] += 1
            self.latency_samples_ms.append(round(latency_ms, 2))
            clean_path = path[:80] if path else "-"
            self.path_counts[clean_path] += 1
            current_sec = int(now)
            self.second_buckets[current_sec] += 1
            stale_before = current_sec - 10
            for bucket_sec in list(self.second_buckets.keys()):
                if bucket_sec < stale_before:
                    del self.second_buckets[bucket_sec]
            current_rps_2s = (
                self.second_buckets.get(current_sec, 0) +
                self.second_buckets.get(current_sec - 1, 0)
            ) / 2.0
            self.current_rps_2s = round(current_rps_2s, 2)
            if current_rps_2s > self.peak_rps_2s:
                self.peak_rps_2s = round(current_rps_2s, 2)
            self.recent_events.append({
                "timestamp":   now,
                "path":        clean_path,
                "score":       round(score, 4),
                "decision":    decision,
                "attack_type": attack_type,
                "model":       model,
                "latency_ms":  round(latency_ms, 2),
            })

    def record_engine_result(self, engine_name: str, decision: str, latency_ms: float):
        with self._lock:
            if engine_name not in self.engine_latency_samples_ms:
                return
            self.engine_latency_samples_ms[engine_name].append(round(latency_ms, 2))
            if decision == "block":
                self.engine_blocked[engine_name] += 1

    def record_engine_score(self, engine_name: str, score: float):
        with self._lock:
            if engine_name not in self.engine_score_bins:
                return
            bin_idx = min(int(score * 10), 9)
            self.engine_score_bins[engine_name][bin_idx] += 1

    def record_engine_comparison(
        self,
        path: str,
        baseline_result: dict,
        transformer_result: dict,
    ):
        with self._lock:
            self.comparison_total += 1
            if baseline_result["decision"] == transformer_result["decision"]:
                self.comparison_agreements += 1
                return

            self.comparison_disagreements += 1
            self.recent_disagreement_events.append({
                "timestamp": time.time(),
                "path": (path or "-")[:80],
                "baseline_decision": baseline_result["decision"],
                "baseline_score": round(float(baseline_result["score"]), 4),
                "transformer_decision": transformer_result["decision"],
                "transformer_score": round(float(transformer_result["score"]), 4),
            })

    def snapshot(self) -> dict:
        with self._lock:
            block_rate = (self.blocked / self.total * 100) if self.total else 0.0
            latency_samples = sorted(self.latency_samples_ms)
            avg_latency_ms = (
                round(sum(latency_samples) / len(latency_samples), 2)
                if latency_samples else 0.0
            )
            if latency_samples:
                p50_index = min(len(latency_samples) - 1, max(0, int(len(latency_samples) * 0.50) - 1))
                p95_index = min(len(latency_samples) - 1, max(0, int(len(latency_samples) * 0.95) - 1))
                p50_latency_ms = latency_samples[p50_index]
                p95_latency_ms = latency_samples[p95_index]
            else:
                p50_latency_ms = 0.0
                p95_latency_ms = 0.0
            recent_total = len(self.recent_decisions)
            recent_blocked = sum(1 for _, decision in self.recent_decisions if decision == "block")
            recent_block_rate = (recent_blocked / recent_total * 100) if recent_total else 0.0
            now = time.time()
            recent_scores = [score for ts, score in self.recent_scores if ts >= now - 30]
            previous_scores = [score for ts, score in self.recent_scores if now - 60 <= ts < now - 30]
            recent_avg_confidence = (
                round(sum(recent_scores) / len(recent_scores), 4)
                if recent_scores else 0.0
            )
            previous_avg_confidence = (
                round(sum(previous_scores) / len(previous_scores), 4)
                if previous_scores else 0.0
            )
            confidence_drift_delta = round(recent_avg_confidence - previous_avg_confidence, 4)
            baseline_latency_samples = sorted(self.engine_latency_samples_ms["baseline"])
            transformer_latency_samples = sorted(self.engine_latency_samples_ms["transformer"])
            baseline_avg_latency_ms = (
                round(sum(baseline_latency_samples) / len(baseline_latency_samples), 2)
                if baseline_latency_samples else 0.0
            )
            transformer_avg_latency_ms = (
                round(sum(transformer_latency_samples) / len(transformer_latency_samples), 2)
                if transformer_latency_samples else 0.0
            )
            comparison_agreement_rate = (
                self.comparison_agreements / self.comparison_total * 100
                if self.comparison_total else 0.0
            )
            attack_diversity = sum(
                1 for attack_type, count in self.attack_type_counts.items()
                if attack_type != "unknown" and count > 0
            )
            return {
                "total":              self.total,
                "blocked":            self.blocked,
                "allowed":            self.allowed,
                "block_rate":         round(block_rate, 2),
                "avg_latency_ms":     avg_latency_ms,
                "p50_latency_ms":     round(p50_latency_ms, 2),
                "p95_latency_ms":     round(p95_latency_ms, 2),
                "current_rps_2s":     self.current_rps_2s,
                "peak_rps_2s":        self.peak_rps_2s,
                "recent_block_rate_30s": round(recent_block_rate, 2),
                "recent_window_seconds": 30,
                "recent_events_30s":  recent_total,
                "recent_alert_count_30s": len(self.recent_alerts),
                "recent_avg_confidence": recent_avg_confidence,
                "previous_avg_confidence": previous_avg_confidence,
                "confidence_drift_delta": confidence_drift_delta,
                "high_confidence_blocks": self.high_confidence_blocks,
                "uncertain_scores":   self.uncertain_scores,
                "engine_name":        "transformer-onnx",
                "uptime_since_reset_s": int(max(0, time.time() - self.reset_started_at)),
                "baseline_blocked":   self.engine_blocked["baseline"],
                "transformer_blocked": self.engine_blocked["transformer"],
                "baseline_avg_latency_ms": baseline_avg_latency_ms,
                "transformer_avg_latency_ms": transformer_avg_latency_ms,
                "comparison_total":   self.comparison_total,
                "comparison_agreement_count": self.comparison_agreements,
                "comparison_agreement_rate": round(comparison_agreement_rate, 2),
                "comparison_disagreement_count": self.comparison_disagreements,
                "recent_disagreement_events": list(self.recent_disagreement_events),
                "unique_paths_seen":  len(self.path_counts),
                "attack_diversity":   attack_diversity,
                "unknown_blocked":    self.unknown_blocked,
                "unknown_allowed":    self.unknown_allowed,
                "top_targeted_paths": self.path_counts.most_common(5),
                "attack_type_counts": dict(self.attack_type_counts),
                "score_distribution": {
                    f"{i/10:.1f}-{(i+1)/10:.1f}": self.score_bins[i]
                    for i in range(10)
                },
                "baseline_score_distribution": {
                    f"{i/10:.1f}-{(i+1)/10:.1f}": self.engine_score_bins["baseline"][i]
                    for i in range(10)
                },
                "transformer_score_distribution": {
                    f"{i/10:.1f}-{(i+1)/10:.1f}": self.engine_score_bins["transformer"][i]
                    for i in range(10)
                },
                "recent_events": list(self.recent_events),
            }


_stats = WAFStats()


# ── SSE client registry ───────────────────────────────────────────────────────

class SSERegistry:
    def __init__(self):
        self._lock = threading.Lock()
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://10.175.137.100:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    started_at = time.perf_counter()
    raw_input = req.log_line
    parsed = parse_log_line(raw_input)

    text_for_baseline = normalize_input(parsed["raw"] if parsed else raw_input)

    if parsed and parsed.get("method") and parsed.get("path"):
        text_for_transformer = build_structured_text(parsed)
    else:
        text_for_transformer = normalize_input(raw_input)

    response = {}
    baseline_latency_ms = None
    transformer_latency_ms = None

    if engine in ("baseline", "both"):
        baseline_started_at = time.perf_counter()
        response["baseline"] = baseline_engine.analyze_log_line(text_for_baseline)
        baseline_latency_ms = (time.perf_counter() - baseline_started_at) * 1000.0
        _stats.record_engine_result(
            "baseline",
            response["baseline"]["decision"],
            baseline_latency_ms,
        )
        _stats.record_engine_score("baseline", response["baseline"]["score"])

    if engine in ("transformer", "both"):
        transformer_started_at = time.perf_counter()
        response["transformer"] = transformer_engine.analyze(text_for_transformer)
        transformer_latency_ms = (time.perf_counter() - transformer_started_at) * 1000.0
        _stats.record_engine_result(
            "transformer",
            response["transformer"]["decision"],
            transformer_latency_ms,
        )
        _stats.record_engine_score("transformer", response["transformer"]["score"])

    primary = response.get("transformer") or response.get("baseline")
    if primary:
        attack_source = text_for_transformer if parsed else text_for_baseline
        attack_type = detect_attack_type(attack_source)
        path = parsed.get("path", "-") if parsed else "-"

        _stats.record(
            score=primary["score"],
            decision=primary["decision"],
            attack_type=attack_type,
            path=path,
            model=primary.get("model", engine),
            latency_ms=(time.perf_counter() - started_at) * 1000.0,
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

    if "baseline" in response and "transformer" in response:
        comparison_path = parsed.get("path", "-") if parsed else "-"
        _stats.record_engine_comparison(
            comparison_path,
            response["baseline"],
            response["transformer"],
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
            _schedule_alert(send_probing_alert(ambiguous_rate))

    return snapshot


@app.post("/stats/reset")
def reset_stats():
    _stats.reset()
    return {"status": "reset", "message": "All counters cleared."}


@app.post("/demo/start-benign")
def demo_start_benign():
    """Start benign_crawler.py as a background subprocess."""
    with _demo_lock:
        if "feed" not in _demo_processes or _demo_processes["feed"].poll() is not None:
            feed = subprocess.Popen(
                [sys.executable, "scripts/traffic/live_waf_feed.py"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _demo_processes["feed"] = feed

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

        return {"status": "started", "pid": proc.pid}


@app.post("/demo/start-attack")
def demo_start_attack():
    """Start attack_runner.py as a background subprocess."""
    with _demo_lock:
        if "feed" not in _demo_processes or _demo_processes["feed"].poll() is not None:
            feed = subprocess.Popen(
                [sys.executable, "scripts/traffic/live_waf_feed.py"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _demo_processes["feed"] = feed

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
