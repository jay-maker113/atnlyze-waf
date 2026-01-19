import re
from datetime import datetime
from typing import Optional, Dict


NGINX_COMBINED_REGEX = re.compile(
    r'(?P<ip>\S+) '                       # IP
    r'\S+ \S+ '                           # ident, authuser (ignored)
    r'\[(?P<time>[^\]]+)\] '              # time
    r'"(?P<request>[^"]*)" '              # request
    r'(?P<status>\d{3}) '                 # status
    r'(?P<bytes>\S+) '                    # bytes
    r'"(?P<referer>[^"]*)" '              # referer
    r'"(?P<user_agent>[^"]*)"'            # user agent
)


def _parse_time(time_str: str) -> Optional[str]:
    try:
        dt = datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")
        return dt.isoformat()
    except Exception:
        return None


def _parse_request(req: str):
    """
    Example: "GET /login?user=admin HTTP/1.1"
    """
    parts = req.split()
    if len(parts) != 3:
        return None, None, None, None

    method, full_path, http_version = parts
    if "?" in full_path:
        path, query = full_path.split("?", 1)
    else:
        path, query = full_path, ""

    return method, path, query, http_version.replace("HTTP/", "")


def parse_log_line(line: str) -> Optional[Dict]:
    """
    Parses a single Nginx combined log line into structured fields.
    Returns None if parsing fails.
    """
    match = NGINX_COMBINED_REGEX.match(line.strip())
    if not match:
        return None

    gd = match.groupdict()

    method, path, query, http_version = _parse_request(gd["request"])
    timestamp = _parse_time(gd["time"])

    try:
        status = int(gd["status"])
    except ValueError:
        status = None

    try:
        size = int(gd["bytes"]) if gd["bytes"].isdigit() else 0
    except ValueError:
        size = 0

    return {
        "ip": gd["ip"],
        "timestamp": timestamp,
        "method": method,
        "path": path,
        "query": query,
        "http_version": http_version,
        "status": status,
        "bytes": size,
        "referer": gd["referer"],
        "user_agent": gd["user_agent"],
        "raw": line.strip()
    }
