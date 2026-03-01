import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_recall_fscore_support


class BaselineWAFModel:
    def __init__(self):
        self.model = LogisticRegression(
            max_iter=1000,
            n_jobs=-1,
            class_weight="balanced"
        )

    def train(self, X_train, y_train):
        self.model.fit(X_train, y_train)

    def predict_proba(self, X):
        return self.model.predict_proba(X)[:, 1]

    def predict(self, X, threshold=0.5):
        probs = self.predict_proba(X)
        return (probs >= threshold).astype(int)

    def evaluate(self, X, y, threshold=0.5):
        preds = self.predict(X, threshold)
        acc = accuracy_score(y, preds)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y, preds, average="binary", zero_division=0
        )
        return {
            "accuracy": acc,
            "precision": precision,
            "recall": recall,
            "f1": f1
        }

    def save(self, path: str):
        joblib.dump(self.model, path)

    def load(self, path: str):
        self.model = joblib.load(path)
