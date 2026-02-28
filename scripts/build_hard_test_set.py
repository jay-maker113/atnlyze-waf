"""
scripts/build_hard_test_set.py

Generates test_hard_bert.csv — an adversarial test set for honest model evaluation.

PURPOSE:
    The normal test.csv contains samples labeled by the same regex patterns used
    in label_logs.py. A model that memorizes those patterns scores perfectly.
    This hard test set applies evasion techniques that bypass naive pattern matching,
    giving a more realistic measure of whether the model learned attack semantics.

DESIGN RULES:
    1. One variant per malicious sample — keeps class ratio identical to test.csv.
    2. All benign samples are kept unchanged — they're already the harder class.
    3. Evasion functions are attack-type-aware — no-op mutations are excluded.
    4. Mutations stay semantically valid — they represent real attacker evasion,
       not gibberish that would never appear in production traffic.
    5. structured_text mutations use field-aware helpers to protect token markers.
    6. raw_text mutations apply to the query portion of the Nginx log line only.
"""

import pandas as pd
import random
import re
import urllib.parse

INPUT_PATH  = "data/processed/test_bert.csv"
OUTPUT_PATH = "data/processed/test_hard_bert.csv"

random.seed(42)


# ── Field helpers (same as augment_attacks.py) ────────────────────────────────

def extract_field(text: str, field: str) -> str:
    m = re.search(rf'\[{field}\]\s*(.*?)(?=\s*\[|$)', text, re.IGNORECASE)
    return m.group(1).strip() if m else ""

def replace_field(text: str, field: str, new_value: str) -> str:
    return re.sub(
        rf'(\[{field}\]\s*)([^\[]*)',
        lambda m: f"{m.group(1)}{new_value} ",
        text, flags=re.IGNORECASE
    )

# ── Attack type detection ─────────────────────────────────────────────────────

def detect_attack_type(text: str) -> str:
    t = text.lower()
    if any(x in t for x in ["union", "select", "drop table", "sleep(", "or 1=1",
                              "' or", "' and", "admin'--", "%27", "1=1"]):
        return "sqli"
    if any(x in t for x in ["script", "onerror", "onload", "alert(",
                              "javascript:", "iframe", "svg", "%3cscript"]):
        return "xss"
    if any(x in t for x in ["../", "%2e%2e", "....//", "passwd",
                              "/etc/", "%252f"]):
        return "path"
    if any(x in t for x in ["whoami", "cat /etc", ";id", "|id",
                              "$(", "`id`", "%3b", "%7c", "bash -c"]):
        return "cmdi"
    return "unknown"


# ── SQLi evasion ──────────────────────────────────────────────────────────────

def sqli_inline_comment(query: str) -> str:
    """INSERT SQL inline comments to break keyword scanning."""
    query = re.sub(r'\bUNION\b', 'UN/**/ION', query, flags=re.IGNORECASE)
    query = re.sub(r'\bSELECT\b', 'SEL/**/ECT', query, flags=re.IGNORECASE)
    query = re.sub(r'\bOR\b', 'O/**/R', query, flags=re.IGNORECASE)
    return query

def sqli_blind_variant(query: str) -> str:
    """Replace tautology with a blind timing variant."""
    query = re.sub(r"OR\s+1=1", "OR SLEEP(0)", query, flags=re.IGNORECASE)
    query = re.sub(r"' OR '1'='1", "' AND SLEEP(0)--", query, flags=re.IGNORECASE)
    return query

def sqli_hex_encode(query: str) -> str:
    """Hex-encode string literals in the query."""
    # Replace 'admin' with 0x61646d696e
    query = re.sub(r"'admin'", "0x61646d696e", query, flags=re.IGNORECASE)
    return query

SQLI_EVASIONS = [sqli_inline_comment, sqli_blind_variant, sqli_hex_encode]


# ── XSS evasion ───────────────────────────────────────────────────────────────

def xss_mixed_encoding(query: str) -> str:
    """Mix URL-encoding and raw characters in the payload."""
    query = query.replace("<script", "<%73cript")
    query = query.replace("alert", "al\x65rt")
    return query

def xss_event_obfuscation(query: str) -> str:
    """Replace onerror/onload with less common event handlers."""
    query = re.sub(r'onerror', 'onmouseover', query, flags=re.IGNORECASE)
    query = re.sub(r'onload', 'onfocus', query, flags=re.IGNORECASE)
    return query

def xss_tag_substitution(query: str) -> str:
    """Replace <script> with equivalent execution vectors."""
    query = re.sub(r'<script[^>]*>', '<img src=x onerror=', query, flags=re.IGNORECASE)
    query = re.sub(r'</script>', '>', query, flags=re.IGNORECASE)
    return query

XSS_EVASIONS = [xss_mixed_encoding, xss_event_obfuscation, xss_tag_substitution]


# ── Path traversal evasion ────────────────────────────────────────────────────

def path_double_encode(query: str) -> str:
    """Double URL-encode the traversal sequences."""
    query = query.replace("../", "..%252f")
    query = query.replace("..%2f", "..%252f")
    return query

def path_null_byte(query: str) -> str:
    """Insert null byte to confuse path parsers."""
    query = query.replace("/etc/passwd", "/etc/passwd%00.jpg")
    query = query.replace("/etc/shadow", "/etc/shadow%00.jpg")
    return query

def path_windows_separator(query: str) -> str:
    """Use Windows-style backslash separators."""
    query = query.replace("../", "..\\")
    return query

PATH_EVASIONS = [path_double_encode, path_null_byte, path_windows_separator]


# ── CMDi evasion ──────────────────────────────────────────────────────────────

def cmdi_ifs_substitution(query: str) -> str:
    """Use $IFS instead of spaces to bypass space filtering."""
    query = re.sub(r';(\s+)(cat|ls|id|whoami)', r';$IFS\2', query, flags=re.IGNORECASE)
    return query

def cmdi_base64_encoding(query: str) -> str:
    """Simulate base64-encoded command execution."""
    query = re.sub(r';id\b', ';$(echo aWQ= | base64 -d)', query, flags=re.IGNORECASE)
    query = re.sub(r';whoami\b', ';$(echo d2hvYW1p | base64 -d)', query, flags=re.IGNORECASE)
    return query

def cmdi_wildcard_injection(query: str) -> str:
    """Use wildcards to obfuscate command names."""
    query = re.sub(r'\bwhoami\b', 'wh?am?', query, flags=re.IGNORECASE)
    query = re.sub(r'\b;cat\b', ';c?t', query, flags=re.IGNORECASE)
    return query

CMDI_EVASIONS = [cmdi_ifs_substitution, cmdi_base64_encoding, cmdi_wildcard_injection]


EVASIONS_BY_TYPE = {
    "sqli": SQLI_EVASIONS,
    "xss":  XSS_EVASIONS,
    "path": PATH_EVASIONS,
    "cmdi": CMDI_EVASIONS,
}


# ── Apply evasion to a sample ─────────────────────────────────────────────────

def apply_evasion(row: dict) -> dict:
    """
    Apply one evasion technique to the query field of both
    structured_text and raw_text. Token markers are never touched.
    """
    structured = row["structured_text"]
    raw        = row["raw_text"]

    attack_type = detect_attack_type(structured)
    evasions    = EVASIONS_BY_TYPE.get(attack_type, None)

    if not evasions:
        return row  # unknown type — return unchanged, don't corrupt

    func  = random.choice(evasions)
    query = extract_field(structured, "query")

    if not query:
        return row

    mutated_query    = func(query)
    new_structured   = replace_field(structured, "query", mutated_query)

    # Apply same mutation to raw_text query portion
    try:
        new_raw = re.sub(
            r'(\?[^" ]*)',
            lambda m: "?" + m.group(0)[1:].replace(query, mutated_query, 1),
            raw, count=1
        )
    except Exception:
        new_raw = raw  # if raw_text mutation fails, keep original

    return {
        "raw_text":        new_raw,
        "structured_text": new_structured,
        "label":           row["label"]
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    df = pd.read_csv(INPUT_PATH)
    malicious = df[df["label"] == 1]
    benign    = df[df["label"] == 0]

    print(f"Input test set   : {len(df)} samples "
          f"(benign={len(benign)}, malicious={len(malicious)})")

    hard_rows = []
    type_counts  = {"sqli": 0, "xss": 0, "path": 0, "cmdi": 0, "unknown": 0}
    unknown_kept = 0

    # One evasion variant per malicious sample — preserves class ratio
    for _, row in malicious.iterrows():
        attack_type = detect_attack_type(row["structured_text"])
        type_counts[attack_type] += 1
        evaded = apply_evasion(row.to_dict())
        hard_rows.append(evaded)
        if attack_type == "unknown":
            unknown_kept += 1

    # All benign samples unchanged
    for _, row in benign.iterrows():
        hard_rows.append(row.to_dict())

    hard_df = pd.DataFrame(hard_rows)
    hard_df = hard_df.sample(frac=1, random_state=42).reset_index(drop=True)

    hard_benign    = (hard_df["label"] == 0).sum()
    hard_malicious = (hard_df["label"] == 1).sum()

    print(f"\nAttack type breakdown:")
    for t, c in type_counts.items():
        if c > 0:
            print(f"  {t:10}: {c}")

    print(f"\nHard test set    : {len(hard_df)} samples "
          f"(benign={hard_benign}, malicious={hard_malicious})")
    print(f"Attack rate      : {hard_malicious/len(hard_df)*100:.1f}%")
    print(f"Saved to {OUTPUT_PATH}")

    hard_df.to_csv(OUTPUT_PATH, index=False)


if __name__ == "__main__":
    main()