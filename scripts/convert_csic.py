"""
scripts/convert_csic.py

Converts CSIC 2010 HTTP dataset to Nginx combined log format.

Input:  data/external/csic_database.csv
        URL format: 'http://localhost:8080/path?query HTTP/1.1'  ← full absolute URL
        Method: GET / POST
        content: POST body (separate column, not in URL)
        classification: 0=benign, 1=malicious

Output: data/raw/csic/benign.log
        data/raw/csic/malicious.log
        data/raw/csic/csic_labeled.csv  ← sidecar: text, label, attack_type, source

Design decisions:
- URL cleanup: strip scheme+host+port and trailing ' HTTP/1.1' → path+query only
- POST body: appended to path as query string AFTER URL cleanup
- Labels come directly from classification column — label_logs.py NOT run on output
- attack_type derived here and persisted to sidecar CSV for build_dataset.py
- IP fixed to 127.0.0.2 to distinguish CSIC from Docker traffic in build_dataset.py
- Timestamps synthesized (sequential seconds from 2010-06-01)
"""

import os
import re
import sys
import pandas as pd
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from atnlyze.utils import ATTACK_TYPES

INPUT_PATH    = "data/external/csic_database.csv"
OUTPUT_DIR    = "data/raw/csic"
BENIGN_LOG    = os.path.join(OUTPUT_DIR, "benign.log")
MALICIOUS_LOG = os.path.join(OUTPUT_DIR, "malicious.log")
SIDECAR_CSV   = os.path.join(OUTPUT_DIR, "csic_labeled.csv")

BASE_TS = datetime(2010, 6, 1, 0, 0, 0, tzinfo=timezone(timedelta(hours=0)))

VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}


# ── URL normalization ─────────────────────────────────────────────────────────
def extract_path_query(raw_url: str) -> str:
    """
    Input:  'http://localhost:8080/tienda1/index.jsp HTTP/1.1'
    Output: '/tienda1/index.jsp'

    Input:  'http://localhost:8080/tienda1/page.jsp?id=1&q=x HTTP/1.1'
    Output: '/tienda1/page.jsp?id=1&q=x'
    """
    # Strip trailing ' HTTP/1.1' or ' HTTP/1.0' — always present in CSIC URLs
    url = re.sub(r'\s+HTTP/\d+\.\d+\s*$', '', raw_url.strip())
    # Parse and extract path + query only — drop scheme, host, port
    try:
        parsed = urlparse(url)
        path = parsed.path or "/"
        query = parsed.query
        return (path + "?" + query) if query else path
    except Exception:
        return "/"


# ── Attack type detection ─────────────────────────────────────────────────────
def detect_attack_type(path_query: str, content: str) -> str:
    """
    Detects attack type from path+query and POST body.
    Order matters — more specific checks first.
    Mirrors label_logs.py pattern intent, operates on decoded strings.
    """
    combined = (path_query + " " + (content or "")).lower()

    if any(x in combined for x in [
        "php://filter", "php://input", "data://text",
        "expect://", "phar://", "zip://"
    ]):
        return "lfi"

    if any(x in combined for x in [
        "=http://", "=https://", "=ftp://",
        "?page=http", "&page=http", "?file=http", "&file=http"
    ]):
        return "rfi"

    if any(x in combined for x in [
        "eval(", "base64_decode(", "system(", "passthru(",
        "shell_exec(", "gzdecode("
    ]):
        return "php"

    if any(x in combined for x in [
        "[$ne]", "[$gt]", "[$where]", "[$regex]",
        "%5b%24ne%5d", "%5b%24gt%5d"
    ]):
        return "nosql"

    if any(x in combined for x in [
        ")(uid=", ")(|", "objectclass=*", "%00"
    ]):
        return "ldap"

    if any(x in combined for x in [
        "union", "select", "drop table", "insert into",
        "sleep(", "waitfor", "benchmark(",
        "' or", "' and", "or 1=1", "and 1=1",
        "admin'--", "%27", "1=1--", "drop+table",
        "%3b+drop", "%3b+select"
    ]):
        return "sqli"

    if any(x in combined for x in [
        "<script", "</script>", "onerror=", "onload=",
        "javascript:", "<iframe", "<svg", "alert(",
        "%3cscript", "%3c/script"
    ]):
        return "xss"

    if any(x in combined for x in [
        "../", "..%2f", "%2e%2e", "....//",
        "/etc/passwd", "/etc/shadow", "%252f", "%252e"
    ]):
        return "path"

    if any(x in combined for x in [
        ";cat", ";ls", ";id", ";whoami",
        "|cat", "|whoami", "|id",
        "$(", "`id`", "%3b", "%7c",
        "bash -c", "wget ", "curl "
    ]):
        return "cmdi"

    if any(x in combined for x in [
        "/.env", "/.git/", "/wp-login", "/phpmyadmin",
        "/xmlrpc.php", "/.htaccess", "/backup.",
        "/actuator/", "/console/", "/manager/html",
        "/server-status", "/.ds_store"
    ]):
        return "scanner"

    return "unknown"


# ── Nginx combined log line builder ──────────────────────────────────────────
def build_log_line(method: str, path_query: str, ua: str,
                   status: int, ts: datetime, seq: int) -> str:
    """
    Builds a valid Nginx combined log line.
    path_query must be path+query only — NO scheme, host, or HTTP/1.1.
    """
    ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    ua_clean = (ua or "unknown").replace('"', "'")
    pq_clean = (path_query or "/").replace('"', "%22")
    return (
        f'127.0.0.2 - - [{ts_str}] '
        f'"{method} {pq_clean} HTTP/1.1" '
        f'{status} {seq} "-" "{ua_clean}"\n'
    )


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print(f"Loading {INPUT_PATH} ...")
    df = pd.read_csv(INPUT_PATH, low_memory=False)
    df.columns = df.columns.str.strip()
    print(f"Loaded {len(df)} rows. Columns: {list(df.columns)}")

    required = {"Method", "URL", "classification"}
    missing_cols = required - set(df.columns)
    if missing_cols:
        raise RuntimeError(f"Missing required columns: {missing_cols}")

    before = len(df)
    df = df.dropna(subset=["Method", "URL"])
    dropped_null = before - len(df)
    if dropped_null:
        print(f"Dropped {dropped_null} rows with null Method or URL")

    df["Method"]         = df["Method"].str.strip().str.upper()
    df["User-Agent"]     = df.get("User-Agent", pd.Series(["unknown"] * len(df))).fillna("unknown").astype(str)
    df["content"]        = df.get("content", pd.Series([""] * len(df))).fillna("").astype(str)
    df["classification"] = df["classification"].fillna(0).astype(int)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    benign_lines    = []
    malicious_lines = []
    sidecar_rows    = []
    attack_type_counts: dict[str, int] = {}
    drop_count = 0

    print("Converting rows...")

    for seq, (_, row) in enumerate(df.iterrows()):
        method = row["Method"]
        raw_url = str(row["URL"]).strip()
        ua      = str(row["User-Agent"])
        content = str(row["content"]).strip()
        label   = int(row["classification"])

        if method not in VALID_METHODS:
            drop_count += 1
            continue

        # Step 1: extract path+query from absolute URL, strip HTTP/1.1
        path_query = extract_path_query(raw_url)

        # Step 2: for POST requests, merge body into query string
        # Must happen AFTER URL cleanup — content is separate from URL in CSIC
        if method == "POST" and content and content != "nan":
            sep = "&" if "?" in path_query else "?"
            path_query = path_query + sep + content

        ts     = BASE_TS + timedelta(seconds=seq)
        status = 200 if label == 0 else 400

        log_line = build_log_line(method, path_query, ua, status, ts, seq)

        # Detect attack type for ALL rows (benign gets "unknown", that's fine)
        attack_type = detect_attack_type(path_query, content) if label == 1 else "unknown"

        if label == 0:
            benign_lines.append(log_line)
        else:
            attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1
            malicious_lines.append(log_line)

        # Sidecar row — persists text + label + attack_type + source
        sidecar_rows.append({
            "text":        log_line.rstrip("\n"),
            "label":       label,
            "attack_type": attack_type,
            "source":      "csic",
        })

    # Write logs
    with open(BENIGN_LOG, "w", encoding="utf-8") as f:
        f.writelines(benign_lines)
    with open(MALICIOUS_LOG, "w", encoding="utf-8") as f:
        f.writelines(malicious_lines)

    # Write sidecar CSV
    sidecar_df = pd.DataFrame(sidecar_rows)
    sidecar_df.to_csv(SIDECAR_CSV, index=False)

    total    = len(benign_lines) + len(malicious_lines)
    mal_rate = len(malicious_lines) / total * 100 if total else 0

    print(f"\n{'='*50}")
    print(f"  CSIC conversion complete")
    print(f"{'='*50}")
    print(f"  Total converted : {total}")
    print(f"  Benign          : {len(benign_lines)}")
    print(f"  Malicious       : {len(malicious_lines)}")
    print(f"  Attack rate     : {mal_rate:.1f}%")
    print(f"  Dropped         : {drop_count} (invalid method)")
    print(f"  Null dropped    : {dropped_null}")
    print(f"\n  Attack type breakdown (malicious):")
    for t, c in sorted(attack_type_counts.items(), key=lambda x: -x[1]):
        bar = "█" * (c // 50)
        print(f"    {t:10}: {c:>6}  {bar}")

    unknown_count = attack_type_counts.get("unknown", 0)
    unknown_pct   = unknown_count / len(malicious_lines) * 100 if malicious_lines else 0
    if unknown_pct > 30:
        print(f"\n  WARNING: {unknown_pct:.1f}% of malicious rows are 'unknown'")
        print(f"  Review detect_attack_type() — CSIC payloads may need more patterns")
    else:
        print(f"\n  unknown rate: {unknown_pct:.1f}% — acceptable")

    invalid_types = set(attack_type_counts.keys()) - ATTACK_TYPES
    if invalid_types:
        print(f"\n  ERROR: invalid attack types produced: {invalid_types}")

    print(f"\n  Output files:")
    print(f"    {BENIGN_LOG}  ({len(benign_lines)} lines)")
    print(f"    {MALICIOUS_LOG}  ({len(malicious_lines)} lines)")
    print(f"    {SIDECAR_CSV}  ({len(sidecar_rows)} rows)")


if __name__ == "__main__":
    main()