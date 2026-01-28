import pandas as pd
from atnlyze.parser import parse_log_line
from atnlyze.inference import normalize_input

INPUT_DIR = "data/processed"
OUTPUT_DIR = "data/processed"

def build_structured_text(parsed):
    return (
        f"[METHOD] {parsed.get('method','')} "
        f"[PATH] {parsed.get('path','')} "
        f"[QUERY] {parsed.get('query','')} "
        f"[UA] {parsed.get('user_agent','')} "
        f"[REFERER] {parsed.get('referer','')} "
        f"[STATUS] {parsed.get('status','')}"
    )

def process_split(split):
    df = pd.read_csv(f"{INPUT_DIR}/{split}.csv")

    raw_texts = []
    structured_texts = []
    labels = []

    for _, row in df.iterrows():
        raw = normalize_input(row["text"])
        parsed = parse_log_line(raw)
        if not parsed:
            continue

        raw_texts.append(raw)
        structured_texts.append(build_structured_text(parsed))
        labels.append(row["label"])

    out_df = pd.DataFrame({
        "raw_text": raw_texts,
        "structured_text": structured_texts,
        "label": labels
    })

    out_df.to_csv(f"{OUTPUT_DIR}/{split}_bert.csv", index=False)
    print(f"{split}: {len(out_df)} samples saved")

if __name__ == "__main__":
    for split in ["train", "val", "test"]:
        process_split(split)
