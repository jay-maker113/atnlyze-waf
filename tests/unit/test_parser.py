#Tests small components: Parser, Tokenizer, Dataset
from atnlyze.parser import parse_log_line

def test_parse_log_line():
    line = "GET /index.html"
    parsed = parse_log_line(line)
    assert "raw" in parsed
