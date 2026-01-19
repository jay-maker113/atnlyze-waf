import os
from atnlyze.model.baseline import BaselineWAFModel


class Trainer:
    def __init__(self, model=None, model_path="models/baseline.joblib"):
        self.model = model or BaselineWAFModel()
        self.model_path = model_path

        os.makedirs(os.path.dirname(model_path), exist_ok=True)

    def train(self, dataset):
        X_train, y_train = dataset.get_train()
        X_val, y_val = dataset.get_val()

        self.model.train(X_train, y_train)

        train_metrics = self.model.evaluate(X_train, y_train)
        val_metrics = self.model.evaluate(X_val, y_val)

        self.model.save(self.model_path)

        return {
            "train": train_metrics,
            "val": val_metrics
        }

    def load(self):
        self.model.load(self.model_path)

    def evaluate(self, dataset):
        X_test, y_test = dataset.get_test()
        return self.model.evaluate(X_test, y_test)

    def predict(self, X, threshold=0.5):
        return self.model.predict(X, threshold)

    def predict_proba(self, X):
        return self.model.predict_proba(X)
