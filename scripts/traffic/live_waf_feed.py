"""
scripts/traffic/live_waf_feed.py

Tails Nginx access logs from all three Docker apps + root in real-time.
POSTs each new log line to /predict?engine=both.
Results flow through SSE to the dashboard via the existing stream endpoint.

Handles:
  - Log rotation (file replaced mid-session)
  - Missing files (app not started yet — retries silently)
  - Server not ready (waits for /health before starting)

Usage:
    python scripts/traffic/live_waf_feed.py

Runs until Ctrl+C. Start after uvicorn is running.
"""

import os
import time
import threading
import requests
import logging

logging.basicConfig(
    level=logging.INFO,
    format="[live_waf_feed] %(asctime)s %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

API_BASE    = os.getenv("API_BASE", "http://localhost:8001")
ENGINE      = "both"
POLL_INTERVAL = 0.5   # seconds between tail checks
RETRY_INTERVAL = 3.0  # seconds between reconnect attempts on missing file

LOG_FILES = [
    "data/raw/dvwa/access.log",
    "data/raw/juice_shop/access.log",
    "data/raw/webgoat/access.log",
    "data/raw/access.log",   # root — scanner probes
]


def wait_for_server(timeout: int = 30):
    """Block until /health returns 200 or timeout expires."""
    logger.info(f"Waiting for server at {API_BASE}/health ...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{API_BASE}/health", timeout=2)
            if r.status_code == 200:
                logger.info("Server ready.")
                return True
        except Exception:
            pass
        time.sleep(1)
    logger.error(f"Server not ready after {timeout}s — is uvicorn running?")
    return False


def send_line(line: str):
    """POST a single log line to /predict. Silently drops on error."""
    line = line.strip()
    if not line:
        return
    try:
        requests.post(
            f"{API_BASE}/predict?engine={ENGINE}",
            json={"log_line": line},
            timeout=10,
        )
    except Exception as e:
        logger.debug(f"predict failed: {e}")


def tail_file(log_path: str):
    """
    Tails a single log file indefinitely.
    Handles file not existing (waits), file rotation (detects inode change),
    and server errors (logged, continues).
    Runs in its own thread.
    """
    logger.info(f"Starting tail: {log_path}")
    file_inode  = None
    file_handle = None
    sent        = 0

    while True:
        try:
            if not os.path.exists(log_path):
                if file_handle:
                    file_handle.close()
                    file_handle = None
                    file_inode  = None
                time.sleep(RETRY_INTERVAL)
                continue

            current_inode = os.stat(log_path).st_ino

            # File rotated — reopen from beginning
            if file_inode is not None and current_inode != file_inode:
                logger.info(f"Log rotated: {log_path} — reopening")
                if file_handle:
                    file_handle.close()
                file_handle = None
                file_inode  = None

            # Open file if not open
            if file_handle is None:
                file_handle = open(log_path, "r", encoding="utf-8", errors="ignore")
                file_handle.seek(0, 2)  # seek to end — only tail new lines
                file_inode = current_inode
                logger.info(f"Tailing: {log_path}")

            # Read any new lines
            while True:
                line = file_handle.readline()
                if not line:
                    break
                send_line(line)
                sent += 1
                if sent % 100 == 0:
                    logger.info(f"{log_path}: {sent} lines sent")

        except Exception as e:
            logger.error(f"Error tailing {log_path}: {e}")
            if file_handle:
                try:
                    file_handle.close()
                except Exception:
                    pass
            file_handle = None
            file_inode  = None

        time.sleep(POLL_INTERVAL)


def main():
    if not wait_for_server():
        return

    logger.info(f"Starting live feed — tailing {len(LOG_FILES)} log files")
    logger.info(f"Sending to {API_BASE}/predict?engine={ENGINE}")

    threads = []
    for log_path in LOG_FILES:
        t = threading.Thread(
            target=tail_file,
            args=(log_path,),
            daemon=True,   # dies when main thread exits
            name=f"tail-{os.path.basename(os.path.dirname(log_path))}",
        )
        t.start()
        threads.append(t)

    logger.info("All tailers running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopped.")


if __name__ == "__main__":
    main()