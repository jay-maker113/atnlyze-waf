import joblib
import urllib.parse
import html


def normalize_input(text: str) -> str:
    """
    Canonicalize input similar to real WAF preprocessing.
    Loop until idempotent — handles double/triple URL encoding
    that attackers use to bypass single-pass WAFs.
    """
    for _ in range(5):  # cap at 5 to prevent infinite loop on pathological input
        decoded = urllib.parse.unquote(text)
        decoded = html.unescape(decoded)
        if decoded == text:
            break
        text = decoded
    return text.lower()


class WAFInferenceEngine:
    def __init__(self, model_path: str, vectorizer_path: str, threshold: float = 0.5):
        self.model = joblib.load(model_path)
        self.vectorizer = joblib.load(vectorizer_path)
        self.threshold = threshold

    def analyze_log_line(self, line: str):
        # 🔹 Normalize before feature extraction
        line = normalize_input(line)

        X = self.vectorizer.transform([line])
        score = float(self.model.predict_proba(X)[0][1])  # probability of malicious

        label = "malicious" if score >= self.threshold else "benign"
        decision = "block" if label == "malicious" else "allow"

        return {
            "label": label,
            "score": round(score, 4),
            "decision": decision
        }
