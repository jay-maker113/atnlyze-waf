import os
import pandas as pd
from sklearn.model_selection import train_test_split

RAW_DIR = "data/raw"
OUT_DIR = "data/processed"

APPS = ["dvwa", "juice_shop", "webgoat"]

def load_logs(app, label):
    path = os.path.join(RAW_DIR, app, f"{label}.log")
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [(line.strip(), 1 if label == "malicious" else 0) for line in f.readlines()]

def main():
    data = []

    for app in APPS:
        data += load_logs(app, "benign")
        data += load_logs(app, "malicious")

    df = pd.DataFrame(data, columns=["text", "label"])

    print("Total samples:", len(df))
    print(df["label"].value_counts())

    train, temp = train_test_split(df, test_size=0.3, stratify=df["label"], random_state=42)
    val, test = train_test_split(temp, test_size=0.5, stratify=temp["label"], random_state=42)

    os.makedirs(OUT_DIR, exist_ok=True)

    train.to_csv(os.path.join(OUT_DIR, "train.csv"), index=False)
    val.to_csv(os.path.join(OUT_DIR, "val.csv"), index=False)
    test.to_csv(os.path.join(OUT_DIR, "test.csv"), index=False)

    print("Saved train/val/test datasets to data/processed/")

if __name__ == "__main__":
    main()
