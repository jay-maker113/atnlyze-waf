import random
from typing import Tuple
import numpy as np

from atnlyze.parser import parse_log_line
from atnlyze.tokenizer import tokenize_request, encode_tokens


class WAFDataset:
    def __init__(
        self,
        benign_path: str,
        malicious_path: str,
        dim: int = 512,
        test_ratio: float = 0.15,
        val_ratio: float = 0.15,
        seed: int = 42,
    ):
        self.benign_path = benign_path
        self.malicious_path = malicious_path
        self.dim = dim
        self.test_ratio = test_ratio
        self.val_ratio = val_ratio
        self.seed = seed

        self.X = []
        self.y = []

        self._load_data()
        self._shuffle()
        self._split()

    def _load_file(self, filepath: str, label: int):
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parsed = parse_log_line(line)
                if parsed is None:
                    continue

                tokens = tokenize_request(parsed)
                vec = encode_tokens(tokens, dim=self.dim)

                self.X.append(vec)
                self.y.append(label)

    def _load_data(self):
        self._load_file(self.benign_path, label=0)
        self._load_file(self.malicious_path, label=1)

        self.X = np.array(self.X)
        self.y = np.array(self.y)

    def _shuffle(self):
        random.seed(self.seed)
        idx = list(range(len(self.X)))
        random.shuffle(idx)

        self.X = self.X[idx]
        self.y = self.y[idx]

    def _split(self):
        n = len(self.X)
        test_size = int(n * self.test_ratio)
        val_size = int(n * self.val_ratio)

        self.X_test = self.X[:test_size]
        self.y_test = self.y[:test_size]

        self.X_val = self.X[test_size:test_size + val_size]
        self.y_val = self.y[test_size:test_size + val_size]

        self.X_train = self.X[test_size + val_size:]
        self.y_train = self.y[test_size + val_size:]

    def get_train(self) -> Tuple[np.ndarray, np.ndarray]:
        return self.X_train, self.y_train

    def get_val(self) -> Tuple[np.ndarray, np.ndarray]:
        return self.X_val, self.y_val

    def get_test(self) -> Tuple[np.ndarray, np.ndarray]:
        return self.X_test, self.y_test

    def batch_iter(self, split="train", batch_size=32, shuffle=True):
        if split == "train":
            X, y = self.X_train, self.y_train
        elif split == "val":
            X, y = self.X_val, self.y_val
        elif split == "test":
            X, y = self.X_test, self.y_test
        else:
            raise ValueError("split must be one of: train, val, test")

        indices = np.arange(len(X))
        if shuffle:
            np.random.shuffle(indices)

        for start in range(0, len(X), batch_size):
            end = start + batch_size
            batch_idx = indices[start:end]
            yield X[batch_idx], y[batch_idx]
