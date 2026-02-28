"""
scripts/augment_attacks.py

Generates adversarial augmentation variants of malicious training samples,
and applies UA neutralization to both benign and malicious samples.

DESIGN RULES:
1. Token markers ([method], [path], [query], etc.) are NEVER modified.
2. Augmentation targets QUERY and PATH fields only — where payloads live.
3. Attack-type-aware augmentation per attack category.
4. UA neutralization applied to BOTH benign and malicious equally.
   This prevents the model from learning UA as a proxy signal for maliciousness.
   If only malicious samples get UA augmentation, the model still learns
   UA distribution as a discriminating feature — just with more variance.
5. randomize_ua() is NOT in the malicious-only augmentation pool.
"""

import pandas as pd
import random
import re
import urllib.parse
import html

INPUT_PATH  = "data/processed/train_bert.csv"
OUTPUT_PATH = "data/processed/train_bert_augmented.csv"

random.seed(42)


# ── Field extraction helpers ──────────────────────────────────────────────────

def extract_field(structured_text: str, field: str) -> str:
    pattern = rf'\[{field}\]\s*(.*?)(?=\s*\[|$)'
    m = re.search(pattern, structured_text, re.IGNORECASE)
    return m.group(1).strip() if m else ""

def replace_field(structured_text: str, field: str, new_value: str) -> str:
    pattern = rf'(\[{field}\]\s*)([^\[]*)'
    return re.sub(
        pattern,
        lambda m: f"{m.group(1)}{new_value} ",
        structured_text,
        flags=re.IGNORECASE,
    )

# ── UA pool — shared across both classes ──────────────────────────────────────
# Applied to BOTH benign and malicious to make UA a non-signal.
# Every UA in this pool must appear in both classes after augmentation.
SHARED_UA_POOL = [
    "sqlmap/1.7",
    "mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36",
    "mozilla/5.0 (macintosh; intel mac os x 10_15_7) applewebkit/537.36",
    "mozilla/5.0 (x11; linux x86_64; rv:109.0) gecko/20100101 firefox/115.0",
    "mozilla/5.0 (iphone; cpu iphone os 17_0 like mac os x) applewebkit/605.1.15",
    "curl/8.0.1",
    "python-requests/2.31.0",
    "python-requests/2.32.5",
    "nikto/2.1.6",
    "go-http-client/1.1",
    "wpscan v3.8.22",
    "mozilla/5.0 (compatible; attacker/1.0)",
    "() { :;}; /bin/bash -c 'id'",
]

def randomize_ua(structured_text: str) -> str:
    return replace_field(structured_text, "ua", random.choice(SHARED_UA_POOL))


# ── Universal payload augmentations (malicious only) ─────────────────────────

def random_case_payload(structured_text: str) -> str:
    query = extract_field(structured_text, "query")
    if not query:
        return structured_text
    mangled = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in query)
    return replace_field(structured_text, "query", mangled)

def url_encode_payload(structured_text: str) -> str:
    query = extract_field(structured_text, "query")
    if not query:
        return structured_text
    return replace_field(structured_text, "query", urllib.parse.quote(query, safe="=&"))

def double_url_encode_payload(structured_text: str) -> str:
    query = extract_field(structured_text, "query")
    if not query:
        return structured_text
    encoded = urllib.parse.quote(urllib.parse.quote(query, safe="=&"), safe="=&")
    return replace_field(structured_text, "query", encoded)

def html_entity_encode_payload(structured_text: str) -> str:
    query = extract_field(structured_text, "query")
    if not query:
        return structured_text
    return replace_field(structured_text, "query", html.escape(query))


# ── SQLi-specific ─────────────────────────────────────────────────────────────

def sql_comment_injection(structured_text: str) -> str:
    query = extract_field(structured_text, "query")
    if not query:
        return structured_text
    query = re.sub(r'\bunion\b', 'un/**/ion', query, flags=re.IGNORECASE)
    query = re.sub(r'\bselect\b', 'sel/**/ect', query, flags=re.IGNORECASE)
    query = re.sub(r'\bwhere\b', 'wh/**/ere', query, flags=re.IGNORECASE)
    return replace_field(structured_text, "query", query)

def sql_alternate_comment(structured_text: str) -> str:
    query = extract_field(structured_text, "query")
    if not query:
        return structured_text
    return replace_field(structured_text, "query", query.replace("--", "#"))

def sql_whitespace_obfuscation(structured_text: str) -> str:
    query = extract_field(structured_text, "query")
    if not query:
        return structured_text
    for kw in ["union", "select", "from", "where", "and", "or"]:
        query = re.sub(rf'\b{kw}\b', kw[0] + "%09" + kw[1:], query, flags=re.IGNORECASE)
    return replace_field(structured_text, "query", query)


# ── XSS-specific ──────────────────────────────────────────────────────────────

def xss_tag_case_mangle(structured_text: str) -> str:
    query = extract_field(structured_text, "query")
    if not query:
        return structured_text
    def mangle_tag(m):
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in m.group(0))
    return replace_field(structured_text, "query", re.sub(r'<[^>]+>', mangle_tag, query))

def xss_encode_brackets(structured_text: str) -> str:
    query = extract_field(structured_text, "query")
    if not query:
        return structured_text
    return replace_field(structured_text, "query", query.replace("<", "%3C").replace(">", "%3E"))

def xss_event_handler_variation(structured_text: str) -> str:
    query = extract_field(structured_text, "query")
    if not query:
        return structured_text
    replacement = random.choice(["confirm(1)", "prompt(1)", "alert(document.cookie)"])
    return replace_field(structured_text, "query",
        re.sub(r'alert\([^)]*\)', replacement, query, flags=re.IGNORECASE))


# ── Path traversal-specific ───────────────────────────────────────────────────

def path_traversal_encoding_variation(structured_text: str) -> str:
    query = extract_field(structured_text, "query")
    if not query:
        return structured_text
    chosen = random.choice(["../", "..%2f", "%2e%2e%2f", "..%252f", "....//"])
    query = re.sub(r'(\.\./|\.\.%2f|%2e%2e%2f|\.\.%252f|\.\.\.\.//)', chosen, query, flags=re.IGNORECASE)
    return replace_field(structured_text, "query", query)

def path_traversal_target_variation(structured_text: str) -> str:
    query = extract_field(structured_text, "query")
    if not query:
        return structured_text
    targets = ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/proc/self/environ", "/proc/version"]
    for t in ["/etc/passwd", "/etc/shadow", "/proc/self"]:
        if t in query:
            query = query.replace(t, random.choice(targets))
            break
    return replace_field(structured_text, "query", query)


# ── CMDi-specific ─────────────────────────────────────────────────────────────

def cmdi_separator_variation(structured_text: str) -> str:
    query = extract_field(structured_text, "query")
    if not query:
        return structured_text
    chosen = random.choice([";", "%3B", "&&", "||", "|", "%7C"])
    query = re.sub(r'(;|%3b|&&|\|{1,2}|%7c)', chosen, query, flags=re.IGNORECASE, count=1)
    return replace_field(structured_text, "query", query)

def cmdi_command_variation(structured_text: str) -> str:
    query = extract_field(structured_text, "query")
    if not query:
        return structured_text
    swaps = {
        "whoami": random.choice(["id", "id -u", "id -un"]),
        "cat /etc/passwd": random.choice(["cat /etc/shadow", "more /etc/passwd"]),
        "ls -la": random.choice(["ls -lah", "ls -al"]),
    }
    for orig, replacement in swaps.items():
        if orig in query:
            query = query.replace(orig, replacement, 1)
    return replace_field(structured_text, "query", query)


# ── Attack type detection ─────────────────────────────────────────────────────

def detect_attack_type(structured_text: str) -> str:
    t = structured_text.lower()
    if any(x in t for x in ["union", "select", "drop table", "sleep(", "or 1=1", "' or", "' and", "--", "admin'", "%27"]):
        return "sqli"
    if any(x in t for x in ["script", "onerror", "onload", "alert(", "javascript:", "iframe", "svg"]):
        return "xss"
    if any(x in t for x in ["../", "%2e%2e", "....//", "passwd", "/etc/", "%252f"]):
        return "path"
    if any(x in t for x in ["whoami", ";cat", ";ls", ";id", "|cat", "|whoami", "$(", "`id`", "%3b", "%7c", "bash -c"]):
        return "cmdi"
    return "unknown"


# ── Augmentation dispatch (payload only — NO UA here) ────────────────────────

UNIVERSAL_PAYLOAD_FUNCS = [
    random_case_payload,
    url_encode_payload,
    double_url_encode_payload,
    html_entity_encode_payload,
]

ATTACK_SPECIFIC = {
    "sqli": [sql_comment_injection, sql_alternate_comment, sql_whitespace_obfuscation],
    "xss":  [xss_tag_case_mangle, xss_encode_brackets, xss_event_handler_variation],
    "path": [path_traversal_encoding_variation, path_traversal_target_variation],
    "cmdi": [cmdi_separator_variation, cmdi_command_variation],
}

def augment_payload(structured_text: str) -> str:
    """Augment payload fields only. UA is handled separately for both classes."""
    attack_type = detect_attack_type(structured_text)
    specific = ATTACK_SPECIFIC.get(attack_type, [])
    if specific and random.random() < 0.6:
        return random.choice(specific)(structured_text)
    return random.choice(UNIVERSAL_PAYLOAD_FUNCS)(structured_text)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    df = pd.read_csv(INPUT_PATH)
    benign    = df[df["label"] == 0]
    malicious = df[df["label"] == 1]

    print(f"Original training samples : {len(df)}")
    print(f"  Benign    : {len(benign)}")
    print(f"  Malicious : {len(malicious)}")

    augmented_rows = []
    type_counts = {"sqli": 0, "xss": 0, "path": 0, "cmdi": 0, "unknown": 0}

    # ── Step 1: Payload augmentation on malicious samples (3 variants each) ──
    print("\nGenerating payload augmentation variants for malicious samples...")
    for _, row in malicious.iterrows():
        attack_type = detect_attack_type(row["structured_text"])
        type_counts[attack_type] += 1
        for _ in range(1):
            new_structured = augment_payload(row["structured_text"])
            augmented_rows.append({
                "raw_text": row["raw_text"],
                "structured_text": new_structured,
                "label": 1
            })

    # ── Step 2: UA neutralization on ALL samples (both classes equally) ──────
    # Apply UA randomization to 50% of both benign and malicious samples.
    # Same pool, same probability — UA becomes non-discriminating.
    print("Applying UA neutralization to both benign and malicious samples...")
    ua_augmented = []

    for _, row in df.iterrows():
        if random.random() < 0.5:  # 50% of all samples get UA swapped
            new_structured = randomize_ua(row["structured_text"])
            ua_augmented.append({
                "raw_text": row["raw_text"],
                "structured_text": new_structured,
                "label": row["label"]
            })

    aug_df    = pd.DataFrame(augmented_rows)
    ua_df     = pd.DataFrame(ua_augmented)
    final_df  = pd.concat([df, aug_df, ua_df], ignore_index=True)
    final_df  = final_df.sample(frac=1, random_state=42).reset_index(drop=True)

    benign_final    = (final_df["label"] == 0).sum()
    malicious_final = (final_df["label"] == 1).sum()

    print(f"\nAttack type breakdown (original malicious):")
    for t, c in type_counts.items():
        if c > 0:
            print(f"  {t:10}: {c}")

    print(f"\nPayload augmented rows added : {len(aug_df)}")
    print(f"UA neutralization rows added : {len(ua_df)}")
    print(f"  (benign UA rows  : {(ua_df['label']==0).sum()})")
    print(f"  (malicious UA rows: {(ua_df['label']==1).sum()})")
    print(f"\nFinal training size : {len(final_df)}")
    print(f"  Benign    : {benign_final}")
    print(f"  Malicious : {malicious_final}")

    final_df.to_csv(OUTPUT_PATH, index=False)
    print(f"\nSaved to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()