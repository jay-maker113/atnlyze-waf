"""
scripts/convert_modsec.py

Converts MDPI ModSecurity audit logs (30 daily files) to Nginx combined log format.
All ModSec entries are malicious by definition — ModSecurity only logs rule violations.

Input:  data/external/modsec/  (folder tree, one subfolder per day)
        Each subfolder contains: modsec_audit.anon.log
        Format: ModSecurity audit log v2, multi-section transactions

Output: data/raw/modsec/malicious.log
        data/raw/modsec/modsec_labeled.csv  ← sidecar: text, label, attack_type, source

Transaction section structure:
    --txid-A--  metadata: timestamp + client IP
    --txid-B--  request: METHOD /path HTTP/1.1 + headers
    --txid-C--  request body (optional)
    --txid-F--  response: HTTP/1.1 STATUS + headers
    --txid-H--  ModSec audit: rule IDs, tags, messages
    --txid-Z--  end marker

Design decisions:
- Source of truth for attack_type: first [tag "attack-*"] in section H
- Skip rules: 444444, 920210, 920450, 920340, 920440 (protocol noise)
  Transactions where ALL fired rule IDs are in skip set → dropped
- attack-protocol tag → mapped to "scanner" (file extension/protocol violations)
- Stratified sampling cap: 30,000 total, proportional by attack_type
- random.seed(42) before sampling — reproducible
- IP from section A used directly (already anonymized in dataset)
- Synthesized Nginx log format for pipeline compatibility
"""

import os
import re
import sys
import random
import pandas as pd
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from atnlyze.utils import ATTACK_TYPES

INPUT_DIR     = "data/external/modsec"
OUTPUT_DIR    = "data/raw/modsec"
MALICIOUS_LOG = os.path.join(OUTPUT_DIR, "malicious.log")
SIDECAR_CSV   = os.path.join(OUTPUT_DIR, "modsec_labeled.csv")

SAMPLE_CAP    = 30_000
RANDOM_SEED   = 42

# Rule IDs to skip — protocol noise, not payload attacks
SKIP_RULE_IDS = {"444444", "920210", "920450", "920340", "920440"}

# ModSec attack tag → canonical ATTACK_TYPES member
TAG_TO_TYPE = {
    "attack-sqli":           "sqli",
    "attack-xss":            "xss",
    "attack-lfi":            "lfi",
    "attack-rfi":            "rfi",
    "attack-rce":            "cmdi",
    "attack-injection":      "cmdi",
    "attack-injection-php":  "php",
    "attack-protocol":       "scanner",   # file ext/protocol violations = scanner behavior
    "attack-reputation-scanner": "scanner",
}


# ── Transaction parser ────────────────────────────────────────────────────────

def parse_transactions(log_path: str) -> list[dict]:
    """
    Parses a single ModSec audit log file into a list of transaction dicts.
    Each dict contains the raw content of each section keyed by letter.
    Returns only transactions with a parseable section B request line.
    """
    with open(log_path, encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # Split on section boundaries — --txid-LETTER--
    # Each transaction starts with --txid-A--
    tx_pattern = re.compile(
        r'--([a-f0-9]+)-A--\n(.*?)(?=--[a-f0-9]+-A--|$)',
        re.DOTALL
    )
    section_pattern = re.compile(
        r'--[a-f0-9]+-([A-Z])--\n(.*?)(?=--[a-f0-9]+-[A-Z]--|$)',
        re.DOTALL
    )

    transactions = []
    for tx_match in tx_pattern.finditer(content):
        tx_id   = tx_match.group(1)
        tx_body = "--" + tx_id + "-A--\n" + tx_match.group(2)

        sections = {}
        for sec_match in section_pattern.finditer(tx_body):
            letter  = sec_match.group(1)
            content_sec = sec_match.group(2).strip()
            sections[letter] = content_sec

        if "B" not in sections:
            continue

        transactions.append({
            "id":       tx_id,
            "sections": sections,
        })

    return transactions


def extract_fields(tx: dict) -> dict | None:
    """
    Extracts usable fields from a parsed transaction.
    Returns None if the transaction should be dropped.
    """
    sections = tx["sections"]

    # ── Section A: timestamp + client IP
    a_lines = sections.get("A", "").splitlines()
    timestamp = None
    client_ip = "0.0.0.0"
    if a_lines:
        # Format: [11/Aug/2025:00:02:01 +0200] txid clientip port serverip port
        a_line = a_lines[0]
        ts_match = re.match(r'\[([^\]]+)\]', a_line)
        ip_match = re.search(r'\]\s+\S+\s+(\d+\.\d+\.\d+\.\d+)', a_line)
        if ts_match:
            timestamp = ts_match.group(1)
        if ip_match:
            client_ip = ip_match.group(1)

    # ── Section B: request line + headers
    b_lines = sections.get("B", "").splitlines()
    if not b_lines:
        return None

    # First line: METHOD /path HTTP/1.1
    request_line = b_lines[0].strip()
    req_parts = request_line.split()
    if len(req_parts) < 2:
        return None

    method = req_parts[0].upper()
    path   = req_parts[1]  # may include query string

    valid_methods = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}
    if method not in valid_methods:
        return None

    # Scan headers for User-Agent
    ua = "unknown"
    for line in b_lines[1:]:
        if line.lower().startswith("user-agent:"):
            ua = line.split(":", 1)[1].strip()
            break

    # ── Section F: response status
    f_lines = sections.get("F", "").splitlines()
    status = 403  # default for blocked requests
    if f_lines:
        st_match = re.match(r'HTTP/\d+\.\d+\s+(\d+)', f_lines[0])
        if st_match:
            status = int(st_match.group(1))

    # ── Section H: rule IDs and attack tags
    h_content = sections.get("H", "")

    # Extract all fired rule IDs
    rule_ids = set(re.findall(r'\[id "(\d+)"\]', h_content))

    # Drop if ALL rule IDs are in skip set (protocol noise only)
    if rule_ids and rule_ids.issubset(SKIP_RULE_IDS):
        return None

    # Extract first attack-* tag — this is the canonical attack type
    tags = re.findall(r'\[tag "([^"]+)"\]', h_content)
    attack_tag = next((t for t in tags if t.startswith("attack-")), None)

    if not attack_tag:
        # No attack tag at all — skip, not a payload attack
        return None

    attack_type = TAG_TO_TYPE.get(attack_tag, "unknown")

    return {
        "timestamp": timestamp,
        "client_ip": client_ip,
        "method":    method,
        "path":      path,
        "ua":        ua,
        "status":    status,
        "attack_type": attack_type,
        "attack_tag":  attack_tag,
    }


def build_nginx_log_line(fields: dict) -> str:
    """
    Reconstructs a Nginx combined log line from extracted ModSec fields.
    Uses original timestamp and client IP from section A.
    """
    ts = fields["timestamp"] or "01/Jan/2025:00:00:00 +0000"
    ip = fields["client_ip"]
    method = fields["method"]
    path   = fields["path"].replace('"', "%22")
    status = fields["status"]
    ua     = fields["ua"].replace('"', "'")

    return (
        f'{ip} - - [{ts}] '
        f'"{method} {path} HTTP/1.1" '
        f'{status} 0 "-" "{ua}"\n'
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print(f"Scanning {INPUT_DIR} for ModSec log files...")

    # Walk the folder tree — one modsec_audit.anon.log per dated subfolder
    log_files = []
    for root, dirs, files in os.walk(INPUT_DIR):
        for fname in files:
            if fname.endswith(".log"):
                log_files.append(os.path.join(root, fname))

    log_files.sort()
    print(f"Found {len(log_files)} log files.")

    if not log_files:
        raise RuntimeError(
            f"No .log files found in {INPUT_DIR}. "
            "Check that 30 dated subfolders are present."
        )

    # ── Parse all files
    all_records = []
    file_stats  = []
    total_transactions = 0
    total_skipped      = 0

    for log_path in log_files:
        folder = os.path.basename(os.path.dirname(log_path))
        transactions = parse_transactions(log_path)
        total_transactions += len(transactions)

        kept = 0
        skipped = 0
        for tx in transactions:
            fields = extract_fields(tx)
            if fields is None:
                skipped += 1
                total_skipped += 1
                continue
            all_records.append(fields)
            kept += 1

        file_stats.append((folder, len(transactions), kept, skipped))
        print(f"  [{folder}] {len(transactions)} transactions → {kept} kept, {skipped} skipped")

    print(f"\nTotal transactions parsed : {total_transactions}")
    print(f"Total kept               : {len(all_records)}")
    print(f"Total skipped            : {total_skipped}")

    if not all_records:
        raise RuntimeError("No usable records extracted. Check log format and skip rules.")

    # ── Attack type distribution before sampling
    type_counts_before: dict[str, int] = defaultdict(int)
    for r in all_records:
        type_counts_before[r["attack_type"]] += 1

    print(f"\nAttack type distribution before sampling:")
    for t, c in sorted(type_counts_before.items(), key=lambda x: -x[1]):
        pct = c / len(all_records) * 100
        bar = "█" * (c // 200)
        print(f"  {t:10}: {c:>6} ({pct:5.1f}%)  {bar}")

    # ── Stratified sampling — cap at SAMPLE_CAP, proportional by attack_type
    random.seed(RANDOM_SEED)

    if len(all_records) <= SAMPLE_CAP:
        sampled = all_records
        print(f"\nTotal records ({len(all_records)}) under cap ({SAMPLE_CAP}) — no sampling needed.")
    else:
        # Group by attack_type
        by_type: dict[str, list] = defaultdict(list)
        for r in all_records:
            by_type[r["attack_type"]].append(r)

        sampled = []
        for atype, records in by_type.items():
            # Proportional share of cap
            proportion = len(records) / len(all_records)
            n = max(1, round(SAMPLE_CAP * proportion))
            n = min(n, len(records))
            sampled.extend(random.sample(records, n))

        # If rounding left us short/over, trim or top-up from largest bucket
        if len(sampled) > SAMPLE_CAP:
            random.shuffle(sampled)
            sampled = sampled[:SAMPLE_CAP]

        print(f"\nStratified sampling: {len(all_records)} → {len(sampled)} records")

    # ── Build output
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    malicious_lines = []
    sidecar_rows    = []
    type_counts_after: dict[str, int] = defaultdict(int)

    for fields in sampled:
        log_line = build_nginx_log_line(fields)
        malicious_lines.append(log_line)
        type_counts_after[fields["attack_type"]] += 1

        sidecar_rows.append({
            "text":        log_line.rstrip("\n"),
            "label":       1,
            "attack_type": fields["attack_type"],
            "source":      "modsec",
        })

    with open(MALICIOUS_LOG, "w", encoding="utf-8") as f:
        f.writelines(malicious_lines)

    sidecar_df = pd.DataFrame(sidecar_rows)
    sidecar_df.to_csv(SIDECAR_CSV, index=False)

    # ── Summary
    print(f"\n{'='*55}")
    print(f"  ModSec conversion complete")
    print(f"{'='*55}")
    print(f"  Log files processed : {len(log_files)}")
    print(f"  Total transactions  : {total_transactions}")
    print(f"  Usable records      : {len(all_records)}")
    print(f"  After sampling      : {len(sampled)}")
    print(f"\n  Attack type distribution (after sampling):")
    for t, c in sorted(type_counts_after.items(), key=lambda x: -x[1]):
        bar = "█" * (c // 100)
        print(f"    {t:10}: {c:>6}  {bar}")

    invalid = set(type_counts_after.keys()) - ATTACK_TYPES
    if invalid:
        print(f"\n  ERROR: invalid attack types in output: {invalid}")
    else:
        print(f"\n  All attack types valid. ✓")

    print(f"\n  Output files:")
    print(f"    {MALICIOUS_LOG}  ({len(malicious_lines)} lines)")
    print(f"    {SIDECAR_CSV}  ({len(sidecar_rows)} rows)")


if __name__ == "__main__":
    main()