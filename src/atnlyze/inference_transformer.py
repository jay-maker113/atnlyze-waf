import torch
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification


class TransformerWAFInferenceEngine:
    def __init__(self, model_dir: str, threshold: float = 0.5):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        self.tokenizer = DistilBertTokenizerFast.from_pretrained(model_dir)
        self.model = DistilBertForSequenceClassification.from_pretrained(model_dir)
        self.model.to(self.device)
        self.model.eval()

        self.threshold = threshold

    def analyze(self, structured_text: str):
        inputs = self.tokenizer(
            structured_text,
            truncation=True,
            padding=True,
            max_length=128,
            return_tensors="pt"
        )

        inputs = {k: v.to(self.device) for k, v in inputs.items()}

        with torch.no_grad():
            logits = self.model(**inputs).logits
            prob = torch.softmax(logits, dim=1)[0][1].item()

        label = "malicious" if prob >= self.threshold else "benign"
        decision = "block" if label == "malicious" else "allow"

        return {
            "label": label,
            "score": round(prob, 4),
            "decision": decision,
            "model": "transformer"
        }
