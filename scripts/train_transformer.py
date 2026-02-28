from atnlyze.model.transformer import TransformerWAF

if __name__ == "__main__":
    model = TransformerWAF()

    model.train(
        train_path="data/processed/train_bert_augmented.csv",
        val_path="data/processed/val_bert.csv"
    )
