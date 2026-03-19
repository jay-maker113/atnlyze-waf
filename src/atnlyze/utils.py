"""
src/atnlyze/utils.py

Shared utility functions used across both training pipeline and inference.
Single source of truth — import from here, never redefine elsewhere.
"""

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