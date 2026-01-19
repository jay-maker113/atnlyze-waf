import re
import numpy as np
import hashlib

DEFAULT_DIM = 512


def _simple_hash(token: str, dim: int = DEFAULT_DIM) -> int:
    h = hashlib.md5(token.encode("utf-8")).hexdigest()
    return int(h, 16) % dim


def tokenize_path(path: str):
    if not path:
        return []
    return [p for p in path.strip("/").split("/") if p]


def tokenize_query(query: str):
    if not query:
        return []

    tokens = re.split(r"[=&]", query)
    final_tokens = []
    for t in tokens:
        final_tokens.extend(re.findall(r"[A-Za-z0-9]+|[^A-Za-z0-9\s]", t))
    return final_tokens


def tokenize_user_agent(ua: str):
    if not ua:
        return []
    return re.findall(r"[A-Za-z0-9]+", ua.lower())


def tokenize_request(parsed_log: dict) -> dict:
    """
    Returns structured tokens.
    """
    return {
        "method": [parsed_log.get("method", "")],
        "path": tokenize_path(parsed_log.get("path", "")),
        "query": tokenize_query(parsed_log.get("query", "")),
        "user_agent": tokenize_user_agent(parsed_log.get("user_agent", "")),
        "status": [str(parsed_log.get("status", ""))],
    }


def encode_tokens(token_dict: dict, dim: int = DEFAULT_DIM) -> np.ndarray:
    """
    Hash tokens into a fixed-size numeric vector.
    """
    vec = np.zeros(dim, dtype=np.float32)

    for field, tokens in token_dict.items():
        for tok in tokens:
            if not tok:
                continue
            idx = _simple_hash(f"{field}:{tok}", dim)
            vec[idx] += 1.0

    # Normalize
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec = vec / norm

    return vec
