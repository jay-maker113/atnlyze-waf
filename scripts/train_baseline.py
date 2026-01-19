from atnlyze.dataset import WAFDataset
from atnlyze.model.trainer import Trainer

dataset = WAFDataset(
    benign_path="data/samples/benign.log",
    malicious_path="data/samples/malicious.log",
    dim=512
)

trainer = Trainer(model_path="models/baseline.joblib")
metrics = trainer.train(dataset)

print("Training complete.")
print(metrics)

test_metrics = trainer.evaluate(dataset)
print("Test metrics:", test_metrics)
