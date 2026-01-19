from atnlyze.parser import parse_log_line


def test_parse_valid_log():
    line = '127.0.0.1 - - [18/Jan/2026:10:12:45 +0530] "GET /login?user=admin HTTP/1.1" 200 612 "-" "Mozilla/5.0"'
    parsed = parse_log_line(line)

    assert parsed is not None
    assert parsed["ip"] == "127.0.0.1"
    assert parsed["method"] == "GET"
    assert parsed["path"] == "/login"
    assert parsed["query"] == "user=admin"
    assert parsed["status"] == 200
    assert parsed["bytes"] == 612
    assert parsed["user_agent"] == "Mozilla/5.0"
    assert parsed["timestamp"] is not None


def test_parse_invalid_log():
    line = "this is not a valid nginx log"
    parsed = parse_log_line(line)
    assert parsed is None
