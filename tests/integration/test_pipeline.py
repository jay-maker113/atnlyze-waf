"""
tests/integration/test_pipeline.py

Tests the full pipeline: raw log line → parse → normalize → structured text → inference.
These are integration tests — they test how the components work together,
not each component in isolation (that's what unit tests are for).
"""

from atnlyze.parser import parse_log_line
from atnlyze.inference import normalize_input
from atnlyze.utils import build_structured_text


# ── Fixtures ──────────────────────────────────────────────────────────────────

BENIGN_LOG = '127.0.0.1 - - [18/Jan/2026:10:12:45 +0530] "GET /home HTTP/1.1" 200 612 "-" "Mozilla/5.0"'

SQLI_LOG = '127.0.0.1 - - [18/Jan/2026:10:12:45 +0530] "GET /webgoat/SqlInjection/attack?username=admin\'-- HTTP/1.1" 404 683 "-" "python-requests/2.32.5"'

XSS_LOG = '127.0.0.1 - - [18/Jan/2026:10:12:45 +0530] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 980 "-" "Mozilla/5.0"'

PATH_TRAVERSAL_LOG = '127.0.0.1 - - [18/Jan/2026:10:12:45 +0530] "GET /download?file=../../../../etc/passwd HTTP/1.1" 403 64 "-" "curl/8.0"'

URL_ENCODED_SQLI_LOG = '127.0.0.1 - - [18/Jan/2026:10:12:45 +0530] "GET /login?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 100 "-" "Mozilla/5.0"'

DOUBLE_ENCODED_LOG = '127.0.0.1 - - [18/Jan/2026:10:12:45 +0530] "GET /login?id=1%2527%2520OR%25201%253D1 HTTP/1.1" 200 100 "-" "Mozilla/5.0"'


# ── Stage 1: parse_log_line ───────────────────────────────────────────────────

def test_parse_benign_log_extracts_all_fields():
    parsed = parse_log_line(BENIGN_LOG)
    assert parsed is not None
    assert parsed["ip"] == "127.0.0.1"
    assert parsed["method"] == "GET"
    assert parsed["path"] == "/home"
    assert parsed["query"] == ""
    assert parsed["status"] == 200
    assert parsed["user_agent"] == "Mozilla/5.0"
    assert parsed["timestamp"] is not None


def test_parse_sqli_log_extracts_query():
    parsed = parse_log_line(SQLI_LOG)
    assert parsed is not None
    assert parsed["method"] == "GET"
    assert parsed["path"] == "/webgoat/SqlInjection/attack"
    assert "admin" in parsed["query"]
    assert "--" in parsed["query"]


def test_parse_xss_log_extracts_query():
    parsed = parse_log_line(XSS_LOG)
    assert parsed is not None
    assert parsed["path"] == "/search"
    assert "script" in parsed["query"]


def test_parse_path_traversal_log_extracts_query():
    parsed = parse_log_line(PATH_TRAVERSAL_LOG)
    assert parsed is not None
    assert parsed["path"] == "/download"
    assert "passwd" in parsed["query"]


def test_parse_invalid_log_returns_none():
    assert parse_log_line("this is not a valid nginx log") is None
    assert parse_log_line("") is None
    assert parse_log_line("GET /login HTTP/1.1") is None  # missing nginx envelope


# ── Stage 2: normalize_input ──────────────────────────────────────────────────

def test_normalize_lowercases():
    result = normalize_input("GET /Login?User=ADMIN")
    assert result == "get /login?user=admin"


def test_normalize_decodes_url_encoding():
    result = normalize_input("/login?id=1%27%20OR%20%271%27%3D%271")
    assert "'" in result   # %27 decoded
    assert "or" in result  # %20OR%20 decoded and lowercased


def test_normalize_decodes_html_entities():
    result = normalize_input("/search?q=&lt;script&gt;alert(1)&lt;/script&gt;")
    assert "<script>" in result


def test_normalize_handles_empty_string():
    assert normalize_input("") == ""


# ── Stage 3: build_structured_text ───────────────────────────────────────────

def test_structured_text_format_benign():
    parsed = parse_log_line(BENIGN_LOG)
    structured = build_structured_text(parsed)

    assert "[method]" in structured      # lowercased by normalize_input
    assert "[path]" in structured
    assert "[query]" in structured
    assert "[ua]" in structured
    assert "[referer]" in structured
    assert "[status]" in structured
    assert "get" in structured
    assert "/home" in structured


def test_structured_text_contains_attack_payload():
    parsed = parse_log_line(SQLI_LOG)
    structured = build_structured_text(parsed)

    # Attack payload must survive into structured text
    assert "admin" in structured
    assert "--" in structured


def test_structured_text_xss_payload_preserved():
    parsed = parse_log_line(XSS_LOG)
    structured = build_structured_text(parsed)
    assert "script" in structured


# ── Stage 4: full pipeline (parse → normalize → structured text) ──────────────

def test_full_pipeline_benign_log():
    """Raw log → parse → structured text. No data lost."""
    parsed = parse_log_line(BENIGN_LOG)
    assert parsed is not None

    normalized_raw = normalize_input(parsed["raw"])
    assert "get" in normalized_raw
    assert "/home" in normalized_raw

    structured = build_structured_text(parsed)
    assert "[method] get" in structured
    assert "[path] /home" in structured
    assert "[status] 200" in structured


def test_full_pipeline_url_encoded_attack_decoded():
    """
    URL-encoded SQLi must be decoded by normalize_input before the model sees it.
    This is critical — if encoding is not stripped, the model misses the attack.
    """
    parsed = parse_log_line(URL_ENCODED_SQLI_LOG)
    assert parsed is not None

    structured = build_structured_text(parsed)

    # After normalize_input inside build_structured_text, %27 → ' and %20 → space
    assert "or" in structured   # decoded and lowercased
    assert "'" in structured    # decoded quote


def test_full_pipeline_parse_failure_is_explicit():
    """
    When parse fails, the pipeline must return None — not silently
    produce a partially-filled dict with missing fields.
    """
    result = parse_log_line("garbage input")
    assert result is None


def test_structured_text_is_consistent():
    """
    Same input must always produce same output.
    Non-determinism here would cause unpredictable inference.
    """
    parsed = parse_log_line(BENIGN_LOG)
    out1 = build_structured_text(parsed)
    out2 = build_structured_text(parsed)
    assert out1 == out2
