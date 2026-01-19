from atnlyze.dataset import WAFDataset
import os


def test_dataset_loading():
    dataset = WAFDataset(
        benign_path="data/samples/benign.log",
        malicious_path="data/samples/malicious.log",
        dim=64
    )

    X_train, y_train = dataset.get_train()
    X_val, y_val = dataset.get_val()
    X_test, y_test = dataset.get_test()

    assert len(X_train) > 0
    assert len(X_val) >= 0
    assert len(X_test) >= 0

    assert X_train.shape[1] == 64
