"""
scripts/traffic/label_logs.py

Labels raw Nginx access logs as benign or malicious by pattern matching.
Writes benign.log and malicious.log per application into data/raw/<app>/.

IMPORTANT — known limitation:
    This labeler uses regex patterns as ground truth. The TF-IDF baseline
    trained on these labels will partially re-learn these same patterns.
    The transformer is less affected because it learns structural context,
    not token presence. This is an acceptable tradeoff for a self-contained
    data pipeline — the alternative is manual labeling or external ground truth.

    Consequence: never evaluate the baseline on data labeled by this script
    and claim it "detects attacks" — it detects what the labeler already knew.
    The adversarial test set (test_hard_bert.csv) is the only honest baseline eval.

Pattern coverage must match attack_runner.py exactly.
If you add new attack types to attack_runner.py, add patterns here too.
"""

import os
import re

BASE_DIR = "data/raw"

# Extracts the request portion only: the first quoted segment after the timestamp.
# Nginx log format: IP - - [timestamp] "METHOD /path HTTP/1.1" status bytes "referer" "ua"
# This isolates "METHOD /path HTTP/1.1" — excludes referer and user_agent fields.
_REQUEST_EXTRACTOR = re.compile(r'\[[\w/: +]+\]\s+"([^"]+)"')

# ── Patterns applied to the FULL log line ─────────────────────────────────────
# These are safe on the full line because they are specific enough to not
# false-positive on UA or referer content.
FULL_LINE_PATTERNS = [
    # ── SQL Injection ─────────────────────────────────────────────────────────
    # \b word boundaries fail on URL-encoded text (%20 for space, %27 for quote).
    # Bare keyword matches work on both raw and URL-encoded payloads.
    (r"(UNION.{0,40}SELECT)",                       "SQLi: UNION SELECT (raw+encoded)"),
    (r"(SELECT.{0,40}FROM)",                        "SQLi: SELECT FROM (raw+encoded)"),
    (r"(DROP.{0,20}TABLE)",                         "SQLi: DROP TABLE (raw+encoded)"),
    (r"(INSERT.{0,20}INTO)",                        "SQLi: INSERT INTO (raw+encoded)"),
    (r"(SLEEP\s*%28|SLEEP\s*\()",                   "SQLi: SLEEP() blind (raw+encoded)"),
    (r"(WAITFOR.{0,10}DELAY)",                      "SQLi: WAITFOR DELAY (MSSQL)"),
    (r"(BENCHMARK\s*%28|BENCHMARK\s*\()",           "SQLi: BENCHMARK() blind"),
    (r"(%27|')\s*(%20|\s)*(OR|AND)(%20|\s)",        "SQLi: quote + OR/AND (raw+encoded)"),
    (r"(OR%201=1|OR\s+1=1|AND%201=1|AND\s+1=1)",   "SQLi: numeric tautology"),
    (r"(--|%2D%2D|admin%27--|admin'--)",             "SQLi: comment termination"),
    (r"(\?[^\"]{0,100}%27)",                        "SQLi: encoded quote in query"),
    (r"(%23|%2523)",                                "SQLi: URL-encoded hash comment"),

    # ── Cross-Site Scripting (XSS) ────────────────────────────────────────────
    (r"(<script[\s>\/])",                           "XSS: script tag"),
    (r"(<\/script>)",                               "XSS: closing script tag"),
    (r"(<img[^>]{0,50}onerror\s*=)",               "XSS: img onerror"),
    (r"(<svg[^>]{0,50}onload\s*=)",                "XSS: svg onload"),
    (r"(<iframe[^>]{0,50}src\s*=)",                "XSS: iframe src"),
    (r"(<body[^>]{0,50}onload\s*=)",               "XSS: body onload"),
    (r"(javascript\s*:)",                           "XSS: javascript: protocol"),
    (r"(%3C\s*script|%3Cscript)",                  "XSS: URL-encoded script tag"),
    (r"(on\w+\s*=\s*[\"']?\s*(alert|document|window|eval))", "XSS: JS event handler"),

    # ── Path Traversal ────────────────────────────────────────────────────────
    (r"(\.\./|\.\.\\)",                             "Path traversal: ../"),
    (r"(\.\.%2f|%2e%2e%2f|%2e%2e/)",              "Path traversal: URL-encoded ../"),
    (r"(\.\.%5c|%2e%2e%5c)",                       "Path traversal: URL-encoded ..\\ "),
    (r"(%252e%252e|%252f)",                         "Path traversal: double URL-encoded"),
    (r"(/etc/passwd|/etc/shadow|/proc/self)",       "Path traversal: known Linux targets"),
    (r"(\.\..*etc.*(passwd|shadow))",               "Path traversal: traversal to /etc"),

    # ── Command Injection (safe on full line — specific enough) ───────────────
    (r"(;\s*(cat|ls|id|whoami|pwd|uname|wget|curl|bash|sh|python|perl|nc|ncat)\b)", "CMDi: semicolon + command"),
    (r"(\|\s*(cat|ls|id|whoami|pwd|uname|bash|sh)\b)",  "CMDi: pipe + command"),
    (r"(`[^`]{0,50}(id|whoami|ls|cat)[^`]{0,50}`)", "CMDi: backtick execution"),
    (r"(\$\([^)]{0,50}(id|whoami|ls|cat)[^)]{0,50}\))", "CMDi: $() subshell"),
    (r"(%3B.{0,20}(cat|ls|id|whoami))",            "CMDi: URL-encoded semicolon + cmd"),
    (r"(%7C.{0,20}(cat|ls|id|whoami))",            "CMDi: URL-encoded pipe + cmd"),
]

# ── Patterns applied to REQUEST PORTION ONLY ──────────────────────────────────
# Shellshock: () { :;}; pattern is too generic for the full line because
# it appears in our UA rotation. Extract the request field first, then test.
REQUEST_ONLY_PATTERNS = [
    (r"(\(\s*\)\s*\{[^}]{0,50}:\s*;\s*\})", "CMDi: Shellshock in request"),
]

# Compile all patterns once at import time
_COMPILED_FULL = [
    (re.compile(p, re.IGNORECASE), d) for p, d in FULL_LINE_PATTERNS
]
_COMPILED_REQUEST_ONLY = [
    (re.compile(p, re.IGNORECASE), d) for p, d in REQUEST_ONLY_PATTERNS
]


def is_malicious(line: str):
    """
    Returns (True, matched_description) or (False, None).

    Two-stage check:
    1. Run full-line patterns against the complete log line.
    2. Run request-only patterns against the extracted request field only,
       preventing UA/referer content from triggering those patterns.
    """
    # Stage 1: full line patterns
    for compiled, description in _COMPILED_FULL:
        if compiled.search(line):
            return True, description

    # Stage 2: request-only patterns — extract request field first
    m = _REQUEST_EXTRACTOR.search(line)
    if m:
        request_portion = m.group(1)  # e.g. "GET /path?query HTTP/1.1"
        for compiled, description in _COMPILED_REQUEST_ONLY:
            if compiled.search(request_portion):
                return True, description

    return False, None


def process_app(app_name: str):
    app_path = os.path.join(BASE_DIR, app_name)
    access_file = os.path.join(app_path, "access.log")
    benign_file = os.path.join(app_path, "benign.log")
    malicious_file = os.path.join(app_path, "malicious.log")

    if not os.path.exists(access_file):
        print(f"[{app_name}] access.log not found, skipping.")
        return

    with open(access_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    benign_lines = []
    malicious_lines = []
    pattern_hit_counts = {}

    for line in lines:
        matched, description = is_malicious(line)
        if matched:
            malicious_lines.append(line)
            pattern_hit_counts[description] = pattern_hit_counts.get(description, 0) + 1
        else:
            benign_lines.append(line)

    with open(benign_file, "w", encoding="utf-8") as f:
        f.writelines(benign_lines)

    with open(malicious_file, "w", encoding="utf-8") as f:
        f.writelines(malicious_lines)

    total = len(lines)
    print(f"\n[{app_name}]")
    print(f"  Total lines : {total}")
    print(f"  Benign      : {len(benign_lines)}")
    print(f"  Malicious   : {len(malicious_lines)}")

    if pattern_hit_counts:
        print(f"  Pattern breakdown:")
        for desc, count in sorted(pattern_hit_counts.items(), key=lambda x: -x[1]):
            print(f"    {count:>5}  {desc}")


if __name__ == "__main__":
    for app in ["dvwa", "juice_shop", "webgoat"]:
        process_app(app)

    print("\nDone. Check data/raw/<app>/benign.log and malicious.log.")