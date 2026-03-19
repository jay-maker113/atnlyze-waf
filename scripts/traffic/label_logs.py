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

is_malicious() returns: (bool, description, attack_type)
    attack_type is always a member of ATTACK_TYPES from utils.py.
    Never return a hardcoded string — always map through _DESCRIPTION_TO_TYPE.
"""

import os
import re

from atnlyze.utils import ATTACK_TYPES

BASE_DIR = "data/raw"

# Extracts the request portion only: the first quoted segment after the timestamp.
# Nginx log format: IP - - [timestamp] "METHOD /path HTTP/1.1" status bytes "referer" "ua"
# This isolates "METHOD /path HTTP/1.1" — excludes referer and user_agent fields.
_REQUEST_EXTRACTOR = re.compile(r'\[[\w/: +]+\]\s+"([^"]+)"')

# ── Patterns applied to the FULL log line ─────────────────────────────────────
# Safe on the full line because they are specific enough not to
# false-positive on UA or referer content.
FULL_LINE_PATTERNS = [

    # ── SQL Injection ──────────────────────────────────────────────────────────
    (r"(UNION.{0,40}SELECT)",                           "SQLi: UNION SELECT (raw+encoded)"),
    (r"(SELECT.{0,40}FROM)",                            "SQLi: SELECT FROM (raw+encoded)"),
    (r"(DROP.{0,20}TABLE)",                             "SQLi: DROP TABLE (raw+encoded)"),
    (r"(INSERT.{0,20}INTO)",                            "SQLi: INSERT INTO (raw+encoded)"),
    (r"(SLEEP\s*%28|SLEEP\s*\()",                       "SQLi: SLEEP() blind (raw+encoded)"),
    (r"(WAITFOR.{0,10}DELAY)",                          "SQLi: WAITFOR DELAY (MSSQL)"),
    (r"(BENCHMARK\s*%28|BENCHMARK\s*\()",               "SQLi: BENCHMARK() blind"),
    (r"(%27|')\s*(%20|\s)*(OR|AND)(%20|\s)",            "SQLi: quote + OR/AND (raw+encoded)"),
    (r"(OR%201=1|OR\s+1=1|AND%201=1|AND\s+1=1)",        "SQLi: numeric tautology"),
    (r"(--|%2D%2D|admin%27--|admin'--)",                 "SQLi: comment termination"),
    (r"(\?[^\"]{0,100}%27)",                            "SQLi: encoded quote in query"),
    (r"(%23|%2523)",                                    "SQLi: URL-encoded hash comment"),

    # ── Cross-Site Scripting (XSS) ─────────────────────────────────────────────
    (r"(<script[\s>\/])",                               "XSS: script tag"),
    (r"(<\/script>)",                                   "XSS: closing script tag"),
    (r"(<img[^>]{0,50}onerror\s*=)",                    "XSS: img onerror"),
    (r"(<svg[^>]{0,50}onload\s*=)",                     "XSS: svg onload"),
    (r"(<iframe[^>]{0,50}src\s*=)",                     "XSS: iframe src"),
    (r"(<body[^>]{0,50}onload\s*=)",                    "XSS: body onload"),
    (r"(javascript\s*:)",                               "XSS: javascript: protocol"),
    (r"(%3C\s*script|%3Cscript)",                       "XSS: URL-encoded script tag"),
    (r"(on\w+\s*=\s*[\"']?\s*(alert|document|window|eval))", "XSS: JS event handler"),

    # ── Path Traversal ─────────────────────────────────────────────────────────
    (r"(\.\./|\.\.\\)",                                 "Path traversal: ../"),
    (r"(\.\.%2f|%2e%2e%2f|%2e%2e/)",                   "Path traversal: URL-encoded ../"),
    (r"(\.\.%5c|%2e%2e%5c)",                            "Path traversal: URL-encoded ..\\\\"),
    (r"(%252e%252e|%252f)",                             "Path traversal: double URL-encoded"),
    (r"(/etc/passwd|/etc/shadow|/proc/self)",           "Path traversal: known Linux targets"),
    (r"(\.\..*etc.*(passwd|shadow))",                   "Path traversal: traversal to /etc"),

    # ── Command Injection ──────────────────────────────────────────────────────
    (r"(;\s*(cat|ls|id|whoami|pwd|uname|wget|curl|bash|sh|python|perl|nc|ncat)\b)",
                                                        "CMDi: semicolon + command"),
    (r"(\|\s*(cat|ls|id|whoami|pwd|uname|bash|sh)\b)", "CMDi: pipe + command"),
    (r"(`[^`]{0,50}(id|whoami|ls|cat)[^`]{0,50}`)",    "CMDi: backtick execution"),
    (r"(\$\([^)]{0,50}(id|whoami|ls|cat)[^)]{0,50}\))","CMDi: $() subshell"),
    (r"(%3B.{0,20}(cat|ls|id|whoami))",                "CMDi: URL-encoded semicolon + cmd"),
    (r"(%7C.{0,20}(cat|ls|id|whoami))",                "CMDi: URL-encoded pipe + cmd"),

    # ── NoSQL Injection ────────────────────────────────────────────────────────
    (r"(\[\$ne\]|\[\$gt\]|\[\$lt\]|\[\$gte\]|\[\$lte\]|%5[Bb]%24ne%5[Dd]|%5[Bb]%24gt%5[Dd])", 
                                                        "NoSQL: MongoDB comparison operator"),
    (r"(\[\$where\]|%5[Bb]%24where%5[Dd])",            "NoSQL: MongoDB $where operator"),
    (r"(\[\$regex\]|%5[Bb]%24regex%5[Dd])",            "NoSQL: MongoDB $regex operator"),
    (r"(\[\$in\]|\[\$nin\]|%5[Bb]%24in%5[Dd]|%5[Bb]%24nin%5[Dd])", 
                                                    "NoSQL: MongoDB $in/$nin operator"),
    # ── LDAP Injection ─────────────────────────────────────────────────────────
    # LDAP filter bypass patterns. The )( and *)(uid=*))(| sequences are
    # distinctive enough to be safe on the full line.
    (r"(\)\s*\(\s*\|)",                                 "LDAP: filter bypass )(|"),
    (r"(\*\)\s*\(\s*uid\s*=\s*\*\)\s*\)\s*\(\s*\|)",  "LDAP: uid wildcard injection"),
    (r"(\)\s*\(\s*objectclass\s*=\s*\*\))",            "LDAP: objectclass wildcard"),
    (r"(%00)",                                          "LDAP: null byte termination"),

    # ── LFI (PHP stream wrappers) ──────────────────────────────────────────────
    # Distinct from path traversal — these use PHP protocol wrappers,
    # not directory walking sequences.
    (r"(php://filter)",                                 "LFI: php://filter wrapper"),
    (r"(php://input)",                                  "LFI: php://input wrapper"),
    (r"(php://fd|php://memory|php://temp)",             "LFI: php:// misc wrappers"),
    (r"(data://text/plain)",                            "LFI: data:// wrapper"),
    (r"(expect://)",                                    "LFI: expect:// wrapper"),
    (r"(zip://|phar://)",                               "LFI: archive stream wrappers"),

    # ── RFI (Remote File Inclusion) ────────────────────────────────────────────
    # External URL inclusion — page= or file= params pointing to remote hosts.
    # The pattern anchors on common param names + http(s):// to avoid false
    # positives on Referer headers that legitimately contain URLs.
    (r"(=(https?|ftp)://[^/\s\"]{4,}/(shell|cmd|malicious|webshell|evil))",
                                                        "RFI: remote shell inclusion"),
    (r"(\?page=https?://|&page=https?://)",             "RFI: page param remote URL"),
    (r"(\?file=https?://|&file=https?://)",             "RFI: file param remote URL"),
    (r"(\?include=https?://|&include=https?://)",       "RFI: include param remote URL"),

    # ── PHP Code Injection ─────────────────────────────────────────────────────
    (r"(eval\s*%28|eval\s*\()",                         "PHP: eval() call"),
    (r"(base64_decode\s*%28|base64_decode\s*\()",       "PHP: base64_decode()"),
    (r"(system\s*%28|system\s*\()",                     "PHP: system()"),
    (r"(passthru\s*%28|passthru\s*\()",                 "PHP: passthru()"),
    (r"(shell_exec\s*%28|shell_exec\s*\()",             "PHP: shell_exec()"),
    (r"(gzdecode\s*%28|gzdecode\s*\()",                 "PHP: gzdecode()"),

    # ── Scanner / Reconnaissance ───────────────────────────────────────────────
    # Common scanner fingerprinting paths. Matching on path only —
    # these are distinctive enough that full-line matching is safe.
    (r'"(GET|POST|HEAD)\s+/\.env[\s?"]',                "Scanner: .env probe"),
    (r'"(GET|POST|HEAD)\s+/\.git/',                     "Scanner: .git probe"),
    (r'"(GET|POST|HEAD)\s+/wp-login\.php',              "Scanner: WordPress login probe"),
    (r'"(GET|POST|HEAD)\s+/wp-admin/',                  "Scanner: WordPress admin probe"),
    (r'"(GET|POST|HEAD)\s+/phpmyadmin',                 "Scanner: phpMyAdmin probe"),
    (r'"(GET|POST|HEAD)\s+/xmlrpc\.php',                "Scanner: xmlrpc probe"),
    (r'"(GET|POST|HEAD)\s+/\.htaccess',                 "Scanner: .htaccess probe"),
    (r'"(GET|POST|HEAD)\s+/backup\.',                   "Scanner: backup file probe"),
    (r'"(GET|POST|HEAD)\s+/config\.php',                "Scanner: config file probe"),
    (r'"(GET|POST|HEAD)\s+/actuator/',                  "Scanner: Spring actuator probe"),
    (r'"(GET|POST|HEAD)\s+/console/',                   "Scanner: console probe"),
    (r'"(GET|POST|HEAD)\s+/manager/html',               "Scanner: Tomcat manager probe"),
    (r'"(GET|POST|HEAD)\s+/server-status',              "Scanner: Apache server-status probe"),
    (r'"(GET|POST|HEAD)\s+/\.DS_Store',                 "Scanner: .DS_Store probe"),
]

# ── Patterns applied to REQUEST PORTION ONLY ──────────────────────────────────
# Shellshock: () { :;}; pattern is too generic for the full line because
# it appears in our UA rotation. Extract the request field first, then test.
REQUEST_ONLY_PATTERNS = [
    (r"(\(\s*\)\s*\{[^}]{0,50}:\s*;\s*\})", "CMDi: Shellshock in request"),
]

# ── Description → canonical attack_type mapping ───────────────────────────────
# Every description string above must appear here.
# is_malicious() uses this to return a validated ATTACK_TYPES member.
# If a description is missing from this map, it will fall through to "unknown"
# and log a warning — never silently produce an invalid type.
_DESCRIPTION_TO_TYPE: dict[str, str] = {
    # SQLi
    "SQLi: UNION SELECT (raw+encoded)":         "sqli",
    "SQLi: SELECT FROM (raw+encoded)":          "sqli",
    "SQLi: DROP TABLE (raw+encoded)":           "sqli",
    "SQLi: INSERT INTO (raw+encoded)":          "sqli",
    "SQLi: SLEEP() blind (raw+encoded)":        "sqli",
    "SQLi: WAITFOR DELAY (MSSQL)":              "sqli",
    "SQLi: BENCHMARK() blind":                  "sqli",
    "SQLi: quote + OR/AND (raw+encoded)":       "sqli",
    "SQLi: numeric tautology":                  "sqli",
    "SQLi: comment termination":                "sqli",
    "SQLi: encoded quote in query":             "sqli",
    "SQLi: URL-encoded hash comment":           "sqli",
    # XSS
    "XSS: script tag":                          "xss",
    "XSS: closing script tag":                  "xss",
    "XSS: img onerror":                         "xss",
    "XSS: svg onload":                          "xss",
    "XSS: iframe src":                          "xss",
    "XSS: body onload":                         "xss",
    "XSS: javascript: protocol":                "xss",
    "XSS: URL-encoded script tag":              "xss",
    "XSS: JS event handler":                    "xss",
    # Path traversal
    "Path traversal: ../":                      "path",
    "Path traversal: URL-encoded ../":          "path",
    "Path traversal: URL-encoded ..\\\\":       "path",
    "Path traversal: double URL-encoded":       "path",
    "Path traversal: known Linux targets":      "path",
    "Path traversal: traversal to /etc":        "path",
    # CMDi
    "CMDi: semicolon + command":                "cmdi",
    "CMDi: pipe + command":                     "cmdi",
    "CMDi: backtick execution":                 "cmdi",
    "CMDi: $() subshell":                       "cmdi",
    "CMDi: URL-encoded semicolon + cmd":        "cmdi",
    "CMDi: URL-encoded pipe + cmd":             "cmdi",
    "CMDi: Shellshock in request":              "cmdi",
    # NoSQL
    "NoSQL: MongoDB comparison operator":       "nosql",
    "NoSQL: MongoDB $where operator":           "nosql",
    "NoSQL: MongoDB $regex operator":           "nosql",
    "NoSQL: MongoDB $in/$nin operator":         "nosql",
    # LDAP
    "LDAP: filter bypass )(|":                  "ldap",
    "LDAP: uid wildcard injection":             "ldap",
    "LDAP: objectclass wildcard":               "ldap",
    "LDAP: null byte termination":              "ldap",
    # LFI
    "LFI: php://filter wrapper":                "lfi",
    "LFI: php://input wrapper":                 "lfi",
    "LFI: php:// misc wrappers":               "lfi",
    "LFI: data:// wrapper":                     "lfi",
    "LFI: expect:// wrapper":                   "lfi",
    "LFI: archive stream wrappers":             "lfi",
    # RFI
    "RFI: remote shell inclusion":              "rfi",
    "RFI: page param remote URL":               "rfi",
    "RFI: file param remote URL":               "rfi",
    "RFI: include param remote URL":            "rfi",
    # PHP
    "PHP: eval() call":                         "php",
    "PHP: base64_decode()":                     "php",
    "PHP: system()":                            "php",
    "PHP: passthru()":                          "php",
    "PHP: shell_exec()":                        "php",
    "PHP: gzdecode()":                          "php",
    # Scanner
    "Scanner: .env probe":                      "scanner",
    "Scanner: .git probe":                      "scanner",
    "Scanner: WordPress login probe":           "scanner",
    "Scanner: WordPress admin probe":           "scanner",
    "Scanner: phpMyAdmin probe":                "scanner",
    "Scanner: xmlrpc probe":                    "scanner",
    "Scanner: .htaccess probe":                 "scanner",
    "Scanner: backup file probe":               "scanner",
    "Scanner: config file probe":               "scanner",
    "Scanner: Spring actuator probe":           "scanner",
    "Scanner: console probe":                   "scanner",
    "Scanner: Tomcat manager probe":            "scanner",
    "Scanner: Apache server-status probe":      "scanner",
    "Scanner: .DS_Store probe":                 "scanner",
}

# Validate at import time — catches map drift before any data is processed.
# If a description exists in patterns but not in the map, fail immediately.
_ALL_DESCRIPTIONS = (
    {d for _, d in FULL_LINE_PATTERNS}
    | {d for _, d in REQUEST_ONLY_PATTERNS}
)
_MISSING = _ALL_DESCRIPTIONS - set(_DESCRIPTION_TO_TYPE.keys())
if _MISSING:
    raise RuntimeError(
        f"label_logs.py: {len(_MISSING)} pattern description(s) missing from "
        f"_DESCRIPTION_TO_TYPE map — fix before running:\n  "
        + "\n  ".join(sorted(_MISSING))
    )
_INVALID_TYPES = {t for t in _DESCRIPTION_TO_TYPE.values() if t not in ATTACK_TYPES}
if _INVALID_TYPES:
    raise RuntimeError(
        f"label_logs.py: _DESCRIPTION_TO_TYPE maps to invalid ATTACK_TYPES members: "
        f"{_INVALID_TYPES}"
    )

# Compile all patterns once at import time.
_COMPILED_FULL = [
    (re.compile(p, re.IGNORECASE), d) for p, d in FULL_LINE_PATTERNS
]
_COMPILED_REQUEST_ONLY = [
    (re.compile(p, re.IGNORECASE), d) for p, d in REQUEST_ONLY_PATTERNS
]


def is_malicious(line: str) -> tuple[bool, str | None, str | None]:
    """
    Returns (True, description, attack_type) or (False, None, None).

    attack_type is always a member of ATTACK_TYPES (imported from utils.py).

    Two-stage check:
    1. Run full-line patterns against the complete log line.
    2. Run request-only patterns against the extracted request field only,
       preventing UA/referer content from triggering those patterns.
    """
    # Stage 1: full line patterns
    for compiled, description in _COMPILED_FULL:
        if compiled.search(line):
            attack_type = _DESCRIPTION_TO_TYPE.get(description, "unknown")
            return True, description, attack_type

    # Stage 2: request-only patterns — extract request field first
    m = _REQUEST_EXTRACTOR.search(line)
    if m:
        request_portion = m.group(1)  # e.g. "GET /path?query HTTP/1.1"
        for compiled, description in _COMPILED_REQUEST_ONLY:
            if compiled.search(request_portion):
                attack_type = _DESCRIPTION_TO_TYPE.get(description, "unknown")
                return True, description, attack_type

    return False, None, None


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
    pattern_hit_counts: dict[str, int] = {}
    type_hit_counts: dict[str, int] = {}

    for line in lines:
        matched, description, attack_type = is_malicious(line)
        if matched:
            malicious_lines.append(line)
            pattern_hit_counts[description] = pattern_hit_counts.get(description, 0) + 1
            type_hit_counts[attack_type] = type_hit_counts.get(attack_type, 0) + 1
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

    if type_hit_counts:
        print(f"  By attack type:")
        for t, c in sorted(type_hit_counts.items(), key=lambda x: -x[1]):
            print(f"    {t:10}: {c}")

    if pattern_hit_counts:
        print(f"  By pattern:")
        for desc, count in sorted(pattern_hit_counts.items(), key=lambda x: -x[1]):
            print(f"    {count:>5}  {desc}")


def process_root():
    """
    Process the root-level access.log — scanner probes hit Nginx directly
    without an app prefix (/dvwa/, /juice/, /webgoat/) so they land here,
    not in per-app logs.
    """
    access_file = os.path.join(BASE_DIR, "access.log")
    benign_file  = os.path.join(BASE_DIR, "benign.log")
    malicious_file = os.path.join(BASE_DIR, "malicious.log")

    if not os.path.exists(access_file):
        print("[root] access.log not found, skipping.")
        return

    with open(access_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    benign_lines = []
    malicious_lines = []
    pattern_hit_counts: dict[str, int] = {}
    type_hit_counts: dict[str, int] = {}

    for line in lines:
        matched, description, attack_type = is_malicious(line)
        if matched:
            malicious_lines.append(line)
            pattern_hit_counts[description] = pattern_hit_counts.get(description, 0) + 1
            type_hit_counts[attack_type] = type_hit_counts.get(attack_type, 0) + 1
        else:
            benign_lines.append(line)

    with open(benign_file, "w", encoding="utf-8") as f:
        f.writelines(benign_lines)
    with open(malicious_file, "w", encoding="utf-8") as f:
        f.writelines(malicious_lines)

    print(f"\n[root]")
    print(f"  Total lines : {len(lines)}")
    print(f"  Benign      : {len(benign_lines)}")
    print(f"  Malicious   : {len(malicious_lines)}")
    if type_hit_counts:
        print(f"  By attack type:")
        for t, c in sorted(type_hit_counts.items(), key=lambda x: -x[1]):
            print(f"    {t:10}: {c}")
    if pattern_hit_counts:
        print(f"  By pattern:")
        for desc, count in sorted(pattern_hit_counts.items(), key=lambda x: -x[1]):
            print(f"    {count:>5}  {desc}")


if __name__ == "__main__":
    process_root()
    for app in ["dvwa", "juice_shop", "webgoat"]:
        process_app(app)
    print("\nDone. Check data/raw/<app>/benign.log and malicious.log.")