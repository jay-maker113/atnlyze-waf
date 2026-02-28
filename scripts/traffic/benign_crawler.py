"""
scripts/traffic/benign_crawler.py

Simulates realistic benign user browsing across the three vulnerable apps.
Runs alongside attack_runner.py — both should be active simultaneously.

Run time: 90-120 minutes alongside attack_runner.py.
Target: you already have enough benign traffic. This just adds diversity.

Usage:
    python scripts/traffic/benign_crawler.py
"""

import requests
import time
import random

# Realistic browser UAs — diverse enough that benign traffic
# doesn't cluster on a single UA the model could learn as a benign signal
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
]

# Benign paths per app — realistic navigation a real user would do
DVWA_PATHS = [
    "/dvwa/",
    "/dvwa/index.php",
    "/dvwa/login.php",
    "/dvwa/about.php",
    "/dvwa/instructions.php",
    "/dvwa/setup.php",
    "/dvwa/vulnerabilities/brute/",
    "/dvwa/vulnerabilities/captcha/",
    "/dvwa/vulnerabilities/csrf/",
    "/dvwa/vulnerabilities/upload/",
    "/dvwa/security.php",
]

JUICE_PATHS = [
    "/juice/",
    "/juice/rest/products/search?q=apple",
    "/juice/rest/products/search?q=juice",
    "/juice/rest/products/search?q=banana",
    "/juice/rest/products/search?q=orange",
    "/juice/rest/user/whoami",
    "/juice/assets/public/images/JuiceShop_Logo.png",
    "/juice/rest/languages",
    "/juice/rest/admin/application-version",
]

WEBGOAT_PATHS = [
    "/webgoat/",
    "/webgoat/login",
    "/webgoat/register.mvc",
    "/webgoat/welcome.mvc",
    "/webgoat/service/lessonoverview.mvc",
    "/webgoat/start.mvc",
    "/webgoat/images/WebGoat.png",
]

ALL_BENIGN_PATHS = DVWA_PATHS + JUICE_PATHS + WEBGOAT_PATHS

BASE = "http://localhost"


def visit(path):
    try:
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        requests.get(BASE + path, headers=headers, timeout=5)
    except Exception:
        pass


def run():
    print(f"[benign_crawler] Starting. {len(ALL_BENIGN_PATHS)} paths loaded.")
    print(f"[benign_crawler] Press Ctrl+C to stop.\n")

    visited = 0
    while True:
        path = random.choice(ALL_BENIGN_PATHS)
        visit(path)
        visited += 1
        if visited % 50 == 0:
            print(f"[benign_crawler] {visited} requests sent so far...")
        time.sleep(random.uniform(1, 3))


if __name__ == "__main__":
    run()