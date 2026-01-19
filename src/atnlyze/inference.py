from atnlyze.parser import parse_log_line
from atnlyze.tokenizer import tokenize_request, encode_tokens
from atnlyze.model.baseline import BaselineWAFModel
import numpy as np


class WAFInferenceEngine:
    def __init__(self, model_path: str, dim: int = 512, threshold: float = 0.5):
        self.model = BaselineWAFModel()
        self.model.load(model_path)
        self.dim = dim
        self.threshold = threshold

    def analyze_log_line(self, line: str):
        parsed = parse_log_line(line)
        if parsed is None:
            return {
                "label": "unknown",
                "score": 0.0,
                "decision": "allow",
                "error": "Could not parse log line"
            }

        tokens = tokenize_request(parsed)
        vec = encode_tokens(tokens, dim=self.dim)
        vec = np.expand_dims(vec, axis=0)

        score = float(self.model.predict_proba(vec)[0])
        label = "malicious" if score >= self.threshold else "benign"
        decision = "block" if label == "malicious" else "allow"

        return {
            "label": label,
            "score": round(score, 4),
            "decision": decision
        }
