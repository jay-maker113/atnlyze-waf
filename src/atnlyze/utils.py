# Shared helpers
"""
src/atnlyze/utils.py

Shared utility functions used across both training pipeline and inference.
Single source of truth — import from here, never redefine elsewhere.
"""

from atnlyze.inference import normalize_input


def build_structured_text(parsed: dict) -> str:
    """
    Converts a parsed Nginx log dict into the structured token format
    that DistilBERT was fine-tuned on.

    Expected input: output of parse_log_line()
    Output format:  '[METHOD] get [PATH] /login [QUERY] user=admin [UA] mozilla/5.0 [REFERER] - [STATUS] 200'

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
