"""
ML model training and evaluation script.

Trains a Random Forest classifier on the generated CAN dataset,
evaluates with real metrics, and saves results.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from can_security.detection.ml_detector import RandomForestDetector, IsolationForestDetector

logger = logging.getLogger(__name__)


def train_and_evaluate(
    dataset_dir: str = "ml/datasets",
    output_dir: str = "ml/models",
    results_dir: str = "results",
    n_estimators: int = 100,
    max_depth: int = 20,
    seed: int = 42,
) -> dict:
    """
    Train a Random Forest model, evaluate it, and save all results.

    Returns a dict containing all measured metrics.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    Path(results_dir).mkdir(parents=True, exist_ok=True)

    # Load data
    train_path = Path(dataset_dir) / "train.csv"
    test_path = Path(dataset_dir) / "test.csv"

    if not train_path.exists() or not test_path.exists():
        raise FileNotFoundError(
            f"Dataset not found at {dataset_dir}. "
            "Run 'python -m can_security generate-dataset' first."
        )

    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)

    feature_cols = [c for c in train_df.columns if c not in ("label", "split")]

    X_train = train_df[feature_cols].values.astype(np.float32)
    y_train = train_df["label"].values
    X_test = test_df[feature_cols].values.astype(np.float32)
    y_test = test_df["label"].values

    # Handle NaN/inf
    X_train = np.nan_to_num(X_train, nan=0.0, posinf=0.0, neginf=0.0)
    X_test = np.nan_to_num(X_test, nan=0.0, posinf=0.0, neginf=0.0)

    print(f"\n{'='*60}")
    print(f"  Training Data: {len(X_train)} samples, {X_train.shape[1]} features")
    print(f"  Test Data:     {len(X_test)} samples")
    print(f"  Classes:       {sorted(set(y_train))}")
    print(f"{'='*60}\n")

    # --- Train Random Forest ---
    print("Training Random Forest...")
    rf = RandomForestDetector(
        n_estimators=n_estimators,
        max_depth=max_depth,
        random_seed=seed,
    )
    train_metrics = rf.train(X_train, y_train, feature_names=feature_cols)
    print(f"  Training time: {train_metrics['train_time_seconds']}s")

    # --- Evaluate ---
    print("\nEvaluating on test set...")
    start = time.perf_counter()
    predictions = rf.predict_batch(X_test)
    batch_latency = (time.perf_counter() - start) * 1000

    y_pred = [p.attack_type.value if p.attack_type != "NONE" else "NORMAL" for p in predictions]
    # Map NONE to NORMAL
    y_pred_fixed = []
    for p in predictions:
        if p.attack_type.value == "NONE":
            y_pred_fixed.append("NORMAL")
        else:
            y_pred_fixed.append(p.attack_type.value)
    y_pred = y_pred_fixed

    # Metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    recall = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    per_sample_latency = batch_latency / len(X_test)

    report = classification_report(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    print(f"\n{'='*60}")
    print(f"  MODEL EVALUATION RESULTS")
    print(f"{'='*60}")
    print(f"  Accuracy:   {accuracy:.4f}")
    print(f"  Precision:  {precision:.4f}")
    print(f"  Recall:     {recall:.4f}")
    print(f"  F1 Score:   {f1:.4f}")
    print(f"  Inference:  {per_sample_latency:.3f} ms/sample")
    print(f"\n  Classification Report:\n{report}")
    print(f"  Confusion Matrix:\n{cm}")

    # Save model
    model_path = str(Path(output_dir) / "random_forest.joblib")
    rf.save(model_path)
    model_size_mb = os.path.getsize(model_path) / (1024 * 1024)
    print(f"\n  Model saved: {model_path} ({model_size_mb:.2f} MB)")

    # Save results
    results = {
        "model": "RandomForest",
        "n_estimators": n_estimators,
        "max_depth": max_depth,
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "features": X_train.shape[1],
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "inference_latency_ms": round(per_sample_latency, 4),
        "batch_latency_ms": round(batch_latency, 2),
        "model_size_mb": round(model_size_mb, 3),
        "train_time_seconds": train_metrics["train_time_seconds"],
        "confusion_matrix": cm.tolist(),
        "classification_report": report,
        "feature_importance_top10": dict(
            sorted(
                train_metrics.get("feature_importance", {}).items(),
                key=lambda x: x[1],
                reverse=True,
            )[:10]
        ),
    }

    results_path = Path(results_dir) / "detection_metrics.json"
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  Results saved: {results_path}")

    # Generate confusion matrix plot
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import seaborn as sns

        labels = sorted(set(y_test) | set(y_pred))
        fig, ax = plt.subplots(figsize=(10, 8))
        sns.heatmap(
            confusion_matrix(y_test, y_pred, labels=labels),
            annot=True, fmt="d", cmap="Blues",
            xticklabels=labels, yticklabels=labels,
            ax=ax,
        )
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")
        ax.set_title("CAN IDS - Confusion Matrix")
        plt.tight_layout()
        cm_path = Path(results_dir) / "confusion_matrix.png"
        fig.savefig(cm_path, dpi=150)
        plt.close(fig)
        print(f"  Confusion matrix plot: {cm_path}")
    except Exception as e:
        print(f"  Warning: Could not generate plot: {e}")

    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    train_and_evaluate()
