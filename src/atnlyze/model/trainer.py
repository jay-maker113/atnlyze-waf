import os
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report

DATA_DIR = "data/processed"
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "baseline.joblib")
VEC_PATH = os.path.join(MODEL_DIR, "vectorizer.joblib")

def load_data(split):
    df = pd.read_csv(os.path.join(DATA_DIR, f"{split}.csv"))
    return df["text"].values, df["label"].values

def main():
    os.makedirs(MODEL_DIR, exist_ok=True)

    X_train, y_train = load_data("train")
    X_val, y_val = load_data("val")

    print("Vectorizing text...")
    vectorizer = TfidfVectorizer(
        ngram_range=(1,2),
        max_features=5000,
        stop_words=None
    )

    X_train_vec = vectorizer.fit_transform(X_train)
    X_val_vec = vectorizer.transform(X_val)

    print("Training Logistic Regression...")
    model = LogisticRegression(max_iter=1000, n_jobs=-1)
    model.fit(X_train_vec, y_train)

    print("Validation Performance:")
    preds = model.predict(X_val_vec)
    print(classification_report(y_val, preds))

    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VEC_PATH)

    print("Model and vectorizer saved.")

if __name__ == "__main__":
    main()
