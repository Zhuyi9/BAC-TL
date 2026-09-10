#!/usr/bin/env python3
"""Measure classifier inference using precomputed behavior vectors.

This adapter keeps CSV/PCAP parsing and behavior-vector extraction out of the
detection phase. Those operations are already measured during dataset preparation.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import numpy as np
import torch


class BehaviorMLP(torch.nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int = 128, dropout: float = 0.2):
        super().__init__()
        self.net = torch.nn.Sequential(
            torch.nn.Linear(input_dim, hidden_dim),
            torch.nn.ReLU(),
            torch.nn.Dropout(dropout),
            torch.nn.Linear(hidden_dim, hidden_dim // 2),
            torch.nn.ReLU(),
            torch.nn.Dropout(dropout),
            torch.nn.Linear(hidden_dim // 2, 1),
        )

    def forward(self, features: torch.Tensor) -> torch.Tensor:
        return self.net(features).squeeze(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run behavior classifier inference on precomputed .npy vectors."
    )
    parser.add_argument("--model_path", required=True)
    parser.add_argument("--features", required=True)
    parser.add_argument("--labels", required=True)
    parser.add_argument("--metadata", required=True)
    parser.add_argument("--output_dir", required=True)
    parser.add_argument("--threshold", type=float)
    return parser.parse_args()


def binary_metrics(labels: np.ndarray, predictions: np.ndarray) -> dict[str, object]:
    labels = labels.astype(np.int64)
    predictions = predictions.astype(np.int64)
    tp = int(np.sum((labels == 1) & (predictions == 1)))
    tn = int(np.sum((labels == 0) & (predictions == 0)))
    fp = int(np.sum((labels == 0) & (predictions == 1)))
    fn = int(np.sum((labels == 1) & (predictions == 0)))
    accuracy = (tp + tn) / max(len(labels), 1)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2.0 * precision * recall / max(precision + recall, 1e-12)
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "confusion_matrix": [[tn, fp], [fn, tp]],
    }


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    features = np.load(args.features).astype(np.float32)
    labels = np.load(args.labels).astype(np.int64)
    if len(features) != len(labels):
        raise ValueError(f"Feature/label count mismatch: {len(features)} != {len(labels)}")

    checkpoint = torch.load(args.model_path, map_location="cpu", weights_only=False)
    features = (features - checkpoint["x_mean"]) / checkpoint["x_std"]
    components = checkpoint.get("pca_components")
    if components is not None:
        features = ((features - checkpoint["pca_mean"]) @ components.T).astype(np.float32)

    model = BehaviorMLP(
        input_dim=int(checkpoint["input_dim"]),
        hidden_dim=int(checkpoint["hidden_dim"]),
    )
    model.load_state_dict(checkpoint["model_state"])
    model.eval()
    with torch.no_grad():
        logits = model(torch.from_numpy(features).float()).numpy()
    probabilities = 1.0 / (1.0 + np.exp(-logits))
    threshold = float(args.threshold if args.threshold is not None else checkpoint["threshold"])
    predictions = (probabilities >= threshold).astype(np.int64)

    metrics = {
        "threshold": threshold,
        "sample_count": int(len(labels)),
        "positive_count": int(labels.sum()),
        "negative_count": int((labels == 0).sum()),
        **binary_metrics(labels, predictions),
    }
    with (output_dir / "metrics.json").open("w", encoding="utf-8") as handle:
        json.dump(metrics, handle, ensure_ascii=False, indent=2)

    with Path(args.metadata).open("r", encoding="utf-8", newline="") as source, (
        output_dir / "predictions.csv"
    ).open("w", encoding="utf-8", newline="") as target:
        reader = csv.DictReader(source)
        fieldnames = list(reader.fieldnames or []) + ["y_true", "y_pred", "score"]
        writer = csv.DictWriter(target, fieldnames=fieldnames)
        writer.writeheader()
        row_count = 0
        for row_count, (row, label, prediction, score) in enumerate(
            zip(reader, labels, predictions, probabilities), start=1
        ):
            row.update(
                {
                    "y_true": int(label),
                    "y_pred": int(prediction),
                    "score": float(score),
                }
            )
            writer.writerow(row)
    if row_count != len(labels):
        raise ValueError(f"Metadata row count mismatch: {row_count} != {len(labels)}")

    print(json.dumps(metrics, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
