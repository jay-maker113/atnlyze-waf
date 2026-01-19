import numpy as np
from atnlyze.tokenizer import tokenize_request, encode_tokens


def test_tokenize_and_encode():
    parsed = {
        "method": "GET",
        "path": "/login/admin",
        "query": "user=admin'--",
        "status": 500,
        "user_agent": "sqlmap/1.6"
    }

    tokens = tokenize_request(parsed)
    assert "path" in tokens
    assert "query" in tokens
    assert len(tokens["path"]) == 2

    vec = encode_tokens(tokens, dim=128)
    assert isinstance(vec, np.ndarray)
    assert vec.shape == (128,)
