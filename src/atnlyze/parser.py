#Converts raw logs → structured objects
def parse_log_line(line: str) -> dict:
    """
    Basic placeholder parser.
    Later this will parse Apache/Nginx logs.
    """
    return {
        "raw": line.strip()
    }
