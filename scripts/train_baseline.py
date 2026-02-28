"""
scripts/train_baseline.py

Trains the TF-IDF + Logistic Regression baseline WAF model.
Reads from data/processed/train.csv and val.csv.
Saves model to models/baseline.joblib and models/vectorizer.joblib.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from atnlyze.model.trainer import main

if __name__ == "__main__":
    main()