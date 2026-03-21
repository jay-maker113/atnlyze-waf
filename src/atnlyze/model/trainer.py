import os
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report

DATA_DIR   = "data/processed"
MODEL_DIR  = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "baseline.joblib")
VEC_PATH   = os.path.join(MODEL_DIR, "vectorizer.joblib")


def load_data(split):
    df = pd.read_csv(os.path.join(DATA_DIR, f"{split}.csv"))
    return df["text"].values, df["label"].values


def main():
    os.makedirs(MODEL_DIR, exist_ok=True)

    X_train, y_train = load_data("v2_train")
    X_val, y_val     = load_data("v2_val")

    print(f"Train samples : {len(X_train)} "
          f"(benign={sum(y_train==0)}, malicious={sum(y_train==1)})")
    print(f"Val samples   : {len(X_val)} "
          f"(benign={sum(y_val==0)}, malicious={sum(y_val==1)})")

    print("\nVectorizing text...")
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=50000,  # v2 dataset is 6x larger — 10K underfits
        stop_words=None,     # attack keywords like 'or', 'select' matter
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_val_vec   = vectorizer.transform(X_val)

    print("Training Logistic Regression...")
    model = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        C=1.0,
    )
    model.fit(X_train_vec, y_train)

    print("\nValidation Performance:")
    preds = model.predict(X_val_vec)
    print(classification_report(y_val, preds, target_names=["benign", "malicious"]))

    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VEC_PATH)
    print(f"Saved model -> {MODEL_PATH}")
    print(f"Saved vectorizer -> {VEC_PATH}")


if __name__ == "__main__":
    main()