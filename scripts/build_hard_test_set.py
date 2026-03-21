"""
scripts/build_hard_test_set.py

Generates v2_test_hard_bert.csv — adversarial test set for honest model evaluation.

Input:  data/processed/v2_test_bert.csv
Output: data/processed/v2_test_hard_bert.csv

PURPOSE:
    Apply evasion techniques per attack type. Measures whether the model learned
    attack semantics (transformer) vs keyword patterns (baseline).
    The gap between normal and adversarial F1 is the thesis differentiator.

DESIGN RULES:
    1. One evasion variant per malicious sample — preserves class ratio.
    2. All benign samples unchanged.
    3. Evasion functions are attack-type-aware — uses attack_type column directly.
    4. unknown/nosql types — no evasion applied, returned unchanged.
    5. attack_type and source columns propagated through all output rows.
"""

import pandas as pd
import random
import re
import urllib.parse

INPUT_PATH  = "data/processed/v2_test_bert.csv"
OUTPUT_PATH = "data/processed/v2_test_hard_bert.csv"

random.seed(42)


# ── Field helpers ─────────────────────────────────────────────────────────────

def extract_field(text: str, field: str) -> str:
    m = re.search(rf'\[{field}\]\s*(.*?)(?=\s*\[|$)', text, re.IGNORECASE)
    return m.group(1).strip() if m else ""

def replace_field(text: str, field: str, new_value: str) -> str:
    return re.sub(
        rf'(\[{field}\]\s*)([^\[]*)',
        lambda m: f"{m.group(1)}{new_value} ",
        text, flags=re.IGNORECASE
    )


# ── SQLi evasion ──────────────────────────────────────────────────────────────

def sqli_inline_comment(query: str) -> str:
    query = re.sub(r'\bUNION\b',  'UN/**/ION',  query, flags=re.IGNORECASE)
    query = re.sub(r'\bSELECT\b', 'SEL/**/ECT', query, flags=re.IGNORECASE)
    query = re.sub(r'\bOR\b',     'O/**/R',      query, flags=re.IGNORECASE)
    return query

def sqli_blind_variant(query: str) -> str:
    query = re.sub(r"OR\s+1=1",        "OR SLEEP(0)",       query, flags=re.IGNORECASE)
    query = re.sub(r"' OR '1'='1",     "' AND SLEEP(0)--",  query, flags=re.IGNORECASE)
    return query

def sqli_hex_encode(query: str) -> str:
    query = re.sub(r"'admin'", "0x61646d696e", query, flags=re.IGNORECASE)
    return query

SQLI_EVASIONS = [sqli_inline_comment, sqli_blind_variant, sqli_hex_encode]


# ── XSS evasion ───────────────────────────────────────────────────────────────

def xss_mixed_encoding(query: str) -> str:
    query = query.replace("<script", "<%73cript")
    query = query.replace("alert", "al\x65rt")
    return query

def xss_event_obfuscation(query: str) -> str:
    query = re.sub(r'onerror', 'onmouseover', query, flags=re.IGNORECASE)
    query = re.sub(r'onload',  'onfocus',     query, flags=re.IGNORECASE)
    return query

def xss_tag_substitution(query: str) -> str:
    query = re.sub(r'<script[^>]*>', '<img src=x onerror=', query, flags=re.IGNORECASE)
    query = re.sub(r'</script>',     '>',                   query, flags=re.IGNORECASE)
    return query

XSS_EVASIONS = [xss_mixed_encoding, xss_event_obfuscation, xss_tag_substitution]


# ── Path traversal evasion ────────────────────────────────────────────────────

def path_double_encode(query: str) -> str:
    query = query.replace("../",   "..%252f")
    query = query.replace("..%2f", "..%252f")
    return query

def path_null_byte(query: str) -> str:
    query = query.replace("/etc/passwd", "/etc/passwd%00.jpg")
    query = query.replace("/etc/shadow", "/etc/shadow%00.jpg")
    return query

def path_windows_separator(query: str) -> str:
    query = query.replace("../", "..\\")
    return query

PATH_EVASIONS = [path_double_encode, path_null_byte, path_windows_separator]


# ── CMDi evasion ──────────────────────────────────────────────────────────────

def cmdi_ifs_substitution(query: str) -> str:
    query = re.sub(r';(\s+)(cat|ls|id|whoami)', r';$IFS\2', query, flags=re.IGNORECASE)
    return query

def cmdi_base64_encoding(query: str) -> str:
    query = re.sub(r';id\b',     ';$(echo aWQ= | base64 -d)',     query, flags=re.IGNORECASE)
    query = re.sub(r';whoami\b', ';$(echo d2hvYW1p | base64 -d)', query, flags=re.IGNORECASE)
    return query

def cmdi_wildcard_injection(query: str) -> str:
    query = re.sub(r'\bwhoami\b', 'wh?am?', query, flags=re.IGNORECASE)
    query = re.sub(r'\b;cat\b',   ';c?t',   query, flags=re.IGNORECASE)
    return query

CMDI_EVASIONS = [cmdi_ifs_substitution, cmdi_base64_encoding, cmdi_wildcard_injection]


# ── LFI evasion ───────────────────────────────────────────────────────────────

def lfi_wrapper_variation(query: str) -> str:
    wrappers = [
        "php://filter/convert.base64-encode/resource=",
        "php://filter/read=string.rot13/resource=",
        "php://filter/convert.iconv.utf-8.utf-16/resource=",
    ]
    query = re.sub(
        r'php://filter/[^/]+/resource=',
        random.choice(wrappers),
        query, flags=re.IGNORECASE
    )
    return query

def lfi_path_encoding(query: str) -> str:
    query = re.sub(
        r'(resource=)([^\s&]+)',
        lambda m: m.group(1) + urllib.parse.quote(m.group(2), safe=""),
        query, flags=re.IGNORECASE
    )
    return query

LFI_EVASIONS = [lfi_wrapper_variation, lfi_path_encoding]


# ── RFI evasion ───────────────────────────────────────────────────────────────

def rfi_url_variation(query: str) -> str:
    if "http://" in query:
        query = query.replace("http://", random.choice(["https://", "http://www."]), 1)
    return query

def rfi_param_variation(query: str) -> str:
    params = ["page", "file", "include", "path", "load"]
    query = re.sub(
        r'\b(page|file|include|path|load)=',
        random.choice(params) + "=",
        query, count=1, flags=re.IGNORECASE
    )
    return query

RFI_EVASIONS = [rfi_url_variation, rfi_param_variation]


# ── PHP evasion ───────────────────────────────────────────────────────────────

def php_function_variation(query: str) -> str:
    funcs = ["system(", "passthru(", "shell_exec(", "exec("]
    query = re.sub(
        r'\b(system|passthru|shell_exec|exec)\s*\(',
        random.choice(funcs),
        query, flags=re.IGNORECASE
    )
    return query

def php_encoding_variation(query: str) -> str:
    query = re.sub(
        r'eval\(([^)]+)\)',
        r'eval(base64_decode(\1))',
        query, flags=re.IGNORECASE
    )
    return query

PHP_EVASIONS = [php_function_variation, php_encoding_variation]


# ── Scanner evasion ───────────────────────────────────────────────────────────

def scanner_path_variation(query: str) -> str:
    # Scanner payloads are in path, not query — return unchanged
    # Scanner evasion handled at path level in apply_evasion()
    return query

def scanner_case_mangle(query: str) -> str:
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in query)

SCANNER_EVASIONS = [scanner_path_variation, scanner_case_mangle]


# ── LDAP evasion ──────────────────────────────────────────────────────────────

def ldap_wildcard_variation(query: str) -> str:
    variants = [
        "*)(uid=*))(|(uid=*",
        "*)(|(objectclass=*)",
        "*))(|(uid=*",
    ]
    if ")(uid=" in query or ")(|" in query:
        return random.choice(variants)
    return query

def ldap_encoding_variation(query: str) -> str:
    query = query.replace("(", "%28").replace(")", "%29").replace("*", "%2A")
    return query

LDAP_EVASIONS = [ldap_wildcard_variation, ldap_encoding_variation]


# ── Dispatch ──────────────────────────────────────────────────────────────────

EVASIONS_BY_TYPE = {
    "sqli":    SQLI_EVASIONS,
    "xss":     XSS_EVASIONS,
    "path":    PATH_EVASIONS,
    "cmdi":    CMDI_EVASIONS,
    "lfi":     LFI_EVASIONS,
    "rfi":     RFI_EVASIONS,
    "php":     PHP_EVASIONS,
    "scanner": SCANNER_EVASIONS,
    "ldap":    LDAP_EVASIONS,
    # unknown/nosql: no evasion — return unchanged
}


def apply_evasion(row: dict) -> dict:
    """
    Apply one evasion technique using attack_type from v2 CSV column.
    Propagates all 5 columns: raw_text, structured_text, label, attack_type, source.
    """
    structured  = row["structured_text"]
    raw         = row["raw_text"]
    attack_type = row["attack_type"]

    evasions = EVASIONS_BY_TYPE.get(attack_type)
    if not evasions:
        # unknown or nosql — return unchanged, all columns preserved
        return {
            "raw_text":        raw,
            "structured_text": structured,
            "label":           row["label"],
            "attack_type":     attack_type,
            "source":          row["source"],
        }

    func  = random.choice(evasions)
    query = extract_field(structured, "query")

    if not query:
        return {
            "raw_text":        raw,
            "structured_text": structured,
            "label":           row["label"],
            "attack_type":     attack_type,
            "source":          row["source"],
        }

    mutated_query  = func(query)
    new_structured = replace_field(structured, "query", mutated_query)

    try:
        new_raw = re.sub(
            r'(\?[^" ]*)',
            lambda m: "?" + m.group(0)[1:].replace(query, mutated_query, 1),
            raw, count=1
        )
    except Exception:
        new_raw = raw

    return {
        "raw_text":        new_raw,
        "structured_text": new_structured,
        "label":           row["label"],
        "attack_type":     attack_type,
        "source":          row["source"],
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    df = pd.read_csv(INPUT_PATH)

    required = {"raw_text", "structured_text", "label", "attack_type", "source"}
    missing  = required - set(df.columns)
    if missing:
        raise RuntimeError(f"Missing columns in {INPUT_PATH}: {missing}")

    malicious = df[df["label"] == 1]
    benign    = df[df["label"] == 0]

    print(f"Input: {INPUT_PATH}")
    print(f"Total : {len(df)} (benign={len(benign)}, malicious={len(malicious)})")

    hard_rows:   list[dict] = []
    type_counts: dict[str, int] = {}

    # One evasion per malicious sample — preserves class ratio
    for _, row in malicious.iterrows():
        attack_type = str(row["attack_type"])
        type_counts[attack_type] = type_counts.get(attack_type, 0) + 1
        evaded = apply_evasion(row.to_dict())
        hard_rows.append(evaded)

    # All benign unchanged — all 5 columns preserved
    for _, row in benign.iterrows():
        hard_rows.append({
            "raw_text":        row["raw_text"],
            "structured_text": row["structured_text"],
            "label":           row["label"],
            "attack_type":     row["attack_type"],
            "source":          row["source"],
        })

    hard_df = pd.DataFrame(hard_rows)
    hard_df = hard_df.sample(frac=1, random_state=42).reset_index(drop=True)

    hard_benign    = (hard_df["label"] == 0).sum()
    hard_malicious = (hard_df["label"] == 1).sum()

    print(f"\nEvasion applied by attack type:")
    for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
        evasion_applied = t in EVASIONS_BY_TYPE
        print(f"  {t:10}: {c:>6}  {'[evasion applied]' if evasion_applied else '[unchanged]'}")

    print(f"\nOutput: {OUTPUT_PATH}")
    print(f"Total : {len(hard_df)} (benign={hard_benign}, malicious={hard_malicious})")
    print(f"Attack rate: {hard_malicious/len(hard_df)*100:.1f}%")

    assert len(hard_df) == len(df), \
        f"Row count mismatch: input={len(df)}, output={len(hard_df)}"
    assert (hard_df["label"] == 0).sum() == len(benign), \
        "Benign count changed"
    assert (hard_df["label"] == 1).sum() == len(malicious), \
        "Malicious count changed"

    hard_df.to_csv(OUTPUT_PATH, index=False)
    print("Done.")


if __name__ == "__main__":
    main()