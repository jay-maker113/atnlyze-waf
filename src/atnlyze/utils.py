"""
src/atnlyze/utils.py

Shared utility functions used across both training pipeline and inference.
Single source of truth — import from here, never redefine elsewhere.
"""

import re
import os

from atnlyze.inference import normalize_input

# ── Attack type registry — single source of truth
# Import this everywhere attack type strings are used.
# Never hardcode attack type strings in label_logs.py, build_dataset.py,
# augment_attacks.py, build_hard_test_set.py, or frontend constants.
# To add a new attack type: add it here, then update all consumers.
ATTACK_TYPES = frozenset({
    "sqli",
    "xss",
    "cmdi",
    "lfi",
    "rfi",
    "php",
    "scanner",
    "path",
    "nosql",
    "ldap",
    "unknown",
})


_ATTACK_TYPE_PATTERNS: list[tuple[str, tuple[str, ...]]] = [
    ("nosql", (
        r"\[\$ne\]",
        r"\[\$gt\]",
        r"\[\$lt\]",
        r"\[\$where\]",
        r"\[\$regex\]",
        r"%5b%24ne%5d",
        r"%5b%24gt%5d",
        r"%5b%24lt%5d",
        r"%5b%24where%5d",
        r"%5b%24regex%5d",
    )),
    ("ldap", (r"\)\s*\(\s*uid\s*=\s*\*", r"\*\)\s*\(\s*uid\s*=", r"objectclass\s*=\s*\*")),
    ("lfi", (r"php://filter", r"php://input", r"data://text/plain", r"expect://", r"zip://", r"phar://")),
    ("rfi", (r"(=|\bpage=|\bfile=|\binclude=)(https?|ftp)://",)),
    ("php", (r"eval\s*(%28|\()", r"base64_decode\s*(%28|\()", r"system\s*(%28|\()", r"passthru\s*(%28|\()",
             r"shell_exec\s*(%28|\()", r"gzdecode\s*(%28|\()")),
    ("scanner", (r"/\.env(?:[\s?\"&]|$)", r"/\.git/", r"/wp-login\.php", r"/wp-admin/", r"/phpmyadmin",
                 r"/xmlrpc\.php", r"/\.htaccess", r"/backup\.", r"/config\.php", r"/actuator/",
                 r"/console/", r"/manager/html", r"/server-status", r"/\.ds_store")),
    ("sqli", (r"union.{0,40}select", r"select.{0,40}from", r"drop.{0,20}table", r"insert.{0,20}into",
              r"sleep\s*(%28|\()", r"waitfor.{0,10}delay", r"benchmark\s*(%28|\()", r"(%27|')\s*(%20|\s)*(or|and)(%20|\s)",
              r"or%201=1", r"or\s+1=1", r"and%201=1", r"and\s+1=1", r"(--|%2d%2d|admin%27--|admin'--)", r"%23", r"%2523")),
    ("xss", (r"<script[\s>/]", r"</script>", r"<img[^>]{0,50}onerror\s*=", r"<svg[^>]{0,50}onload\s*=",
             r"<iframe[^>]{0,50}src\s*=", r"<body[^>]{0,50}onload\s*=", r"javascript\s*:", r"%3c\s*script",
             r"on\w+\s*=\s*[\"']?\s*(alert|document|window|eval)")),
    ("cmdi", (
        r"[;&|`$]\s*(cat|ls|id|whoami|pwd|uname|wget|curl|bash|sh|python|perl|nc)\b",
        r"%3b.{0,20}(cat|ls|id|whoami)",
        r"%7c.{0,20}(cat|ls|id|whoami)",
        r"\(\s*\)\s*\{[^}]{0,50}:\s*;\s*\}",
    )),
    ("path", (r"\.\./", r"\.\.\\", r"\.\.%2f", r"%2e%2e%2f", r"\.\.%5c", r"%2e%2e%5c", r"%252e%252e", r"%252f",
              r"/etc/passwd", r"/etc/shadow", r"/proc/self")),
]

_COMPILED_ATTACK_TYPE_PATTERNS = [
    (attack_type, [re.compile(pattern, re.IGNORECASE) for pattern in patterns])
    for attack_type, patterns in _ATTACK_TYPE_PATTERNS
]


def build_structured_text(parsed: dict) -> str:
    """
    Converts a parsed Nginx log dict into the structured token format
    that DistilBERT was fine-tuned on.

    Expected input: output of parse_log_line()
    Output format: '[method] get [path] /login [query] user=admin [ua] mozilla/5.0
                    [referer] - [status] 200'

    CRITICAL: This must match exactly what build_transformer_dataset.py
    produced during training. Any format change here requires full retraining.
    normalize_input() lowercases — training data is all lowercase.
    """
    raw_structured = (
        f"[METHOD] {parsed.get('method', '')} "
        f"[PATH] {parsed.get('path', '')} "
        f"[QUERY] {parsed.get('query', '')} "
        f"[UA] {parsed.get('user_agent', '')} "
        f"[REFERER] {parsed.get('referer', '')} "
        f"[STATUS] {parsed.get('status', '')}"
    )
    return normalize_input(raw_structured)  # lowercase + url decode + html unescape


def detect_attack_type(text: str | None) -> str:
    """
    Best-effort attack-type detection for stats, dashboards, and shared tooling.

    This is intentionally coarser than the training labeler. Binary training still
    depends on dataset labels; this helper exists to avoid duplicating attack-type
    logic across scripts and runtime code.
    """
    if not text:
        return "unknown"

    normalized = normalize_input(text)
    if os.getenv("DEBUG_ATTACK_TYPE") == "1" and "/juice/rest/user/login" in normalized:
        print(f"[DEBUG detect_attack_type] {normalized}")
    for attack_type, compiled_patterns in _COMPILED_ATTACK_TYPE_PATTERNS:
        if any(pattern.search(normalized) for pattern in compiled_patterns):
            return attack_type

    return "unknown"
