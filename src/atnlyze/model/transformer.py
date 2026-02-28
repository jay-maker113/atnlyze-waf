import numpy as np
import pandas as pd
import torch
from datasets import Dataset
from transformers import (
    DistilBertTokenizerFast,
    DistilBertForSequenceClassification,
    Trainer,
    TrainingArguments
)
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score

MODEL_NAME = "distilbert-base-uncased"


class TransformerWAF:
    def __init__(self, model_dir="models/bert_waf"):
        self.model_dir = model_dir
        self.tokenizer = DistilBertTokenizerFast.from_pretrained(MODEL_NAME)
        self.model = DistilBertForSequenceClassification.from_pretrained(
            MODEL_NAME,
            num_labels=2,
            # output_attentions removed — was causing tuple output in compute_metrics
            # requiring a workaround hack. Not used anywhere in training or inference.
            # Re-enable only if you need attention visualization.
        )

    def _load_split(self, path):
        df = pd.read_csv(path)
        return Dataset.from_dict({
            "text": df["structured_text"].tolist(),
            "label": df["label"].tolist()
        })

    def _tokenize(self, batch):
        return self.tokenizer(
            batch["text"],
            padding="max_length",
            truncation=True,
            max_length=128
        )

    def train(self, train_path, val_path):
        train_ds = self._load_split(train_path)
        val_ds   = self._load_split(val_path)

        train_ds = train_ds.map(self._tokenize, batched=True)
        val_ds   = val_ds.map(self._tokenize, batched=True)

        train_ds.set_format("torch", columns=["input_ids", "attention_mask", "label"])
        val_ds.set_format("torch", columns=["input_ids", "attention_mask", "label"])

        args = TrainingArguments(
            output_dir=self.model_dir,

            num_train_epochs=3,
            eval_strategy="epoch",
            save_strategy="epoch",

            per_device_train_batch_size=16,
            per_device_eval_batch_size=16,
            learning_rate=2e-5,
            weight_decay=0.01,

            load_best_model_at_end=True,
            metric_for_best_model="f1",

            save_total_limit=2,
            logging_dir="runs/bert_waf",
            logging_strategy="steps",
            logging_steps=20,
            report_to="tensorboard",
        )

        trainer = Trainer(
            model=self.model,
            args=args,
            train_dataset=train_ds,
            eval_dataset=val_ds,
            compute_metrics=self.compute_metrics,
        )

        trainer.train()
        trainer.save_model(self.model_dir)
        self.tokenizer.save_pretrained(self.model_dir)

    def compute_metrics(self, pred):
        labels = pred.label_ids

        # Clean: output_attentions=True removed so predictions is always a plain ndarray.
        # No tuple handling needed.
        logits = pred.predictions

        probs = torch.softmax(torch.tensor(logits), dim=1)[:, 1].numpy()
        preds = (probs >= 0.5).astype(int)

        precision, recall, f1, _ = precision_recall_fscore_support(
            labels, preds, average="binary"
        )
        acc = accuracy_score(labels, preds)
        roc = roc_auc_score(labels, probs)

        return {
            "accuracy": acc,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "roc_auc": roc
        }