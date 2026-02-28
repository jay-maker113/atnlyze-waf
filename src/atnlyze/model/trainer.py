import os
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report

DATA_DIR = "data/processed"
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "baseline.joblib")
VEC_PATH   = os.path.join(MODEL_DIR, "vectorizer.joblib")


def load_data(split):
    df = pd.read_csv(os.path.join(DATA_DIR, f"{split}.csv"))
    return df["text"].values, df["label"].values


def main():
    os.makedirs(MODEL_DIR, exist_ok=True)

    X_train, y_train = load_data("train")
    X_val,   y_val   = load_data("val")

    print(f"Train samples : {len(X_train)} "
          f"(benign={sum(y_train==0)}, malicious={sum(y_train==1)})")
    print(f"Val samples   : {len(X_val)} "
          f"(benign={sum(y_val==0)}, malicious={sum(y_val==1)})")

    print("\nVectorizing text...")
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=10000,   # increased from 5000 — dataset is 3x larger now
        stop_words=None       # do NOT use stop_words — 'or', 'and', 'select' are attack keywords
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_val_vec   = vectorizer.transform(X_val)

    print("Training Logistic Regression...")
    model = LogisticRegression(
        max_iter=1000,

        class_weight="balanced",  # safety net for any residual class imbalance
        C=1.0,                    # default regularization — tune if val F1 < 0.85
    )
    model.fit(X_train_vec, y_train)

    print("\nValidation Performance:")
    preds = model.predict(X_val_vec)
    print(classification_report(y_val, preds, target_names=["benign", "malicious"]))

    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VEC_PATH)
    print(f"Saved model      → {MODEL_PATH}")
    print(f"Saved vectorizer → {VEC_PATH}")


if __name__ == "__main__":
    main()