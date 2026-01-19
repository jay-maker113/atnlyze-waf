from atnlyze.dataset import WAFDataset
from atnlyze.model.trainer import Trainer


def test_training_pipeline():
    dataset = WAFDataset(
        benign_path="data/samples/benign.log",
        malicious_path="data/samples/malicious.log",
        dim=64
    )

    trainer = Trainer(model_path="models/test_model.joblib")
    metrics = trainer.train(dataset)

    assert "train" in metrics
    assert "val" in metrics

    test_metrics = trainer.evaluate(dataset)
    assert "accuracy" in test_metrics
