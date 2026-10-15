"""
ML-based intrusion detection — pluggable detector interface + implementations.

Supports: Random Forest, Isolation Forest (pluggable).
Uses scikit-learn for all models. Measures inference latency and model size.
"""

from __future__ import annotations

import logging
import os
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from can_security.core.enums import AttackType, DetectorType
from can_security.core.models import MLPrediction

logger = logging.getLogger(__name__)


# =============================================================================
# Detector Interface
# =============================================================================

class BaseDetector(ABC):
    """Abstract interface for ML-based detectors."""

    def __init__(self, name: str, detector_type: DetectorType):
        self.name = name
        self.detector_type = detector_type
        self._model: Any = None
        self._is_trained = False
        self._feature_names: list[str] = []
        self._label_map: dict[int, str] = {}
        self._reverse_label_map: dict[str, int] = {}

    @abstractmethod
    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        feature_names: list[str] | None = None,
    ) -> dict[str, Any]:
        """Train the detector. Returns training metrics."""
        ...

    @abstractmethod
    def predict(self, features: np.ndarray) -> MLPrediction:
        """Run inference on a single feature vector."""
        ...

    @abstractmethod
    def predict_batch(self, features: np.ndarray) -> list[MLPrediction]:
        """Run inference on a batch of feature vectors."""
        ...

    def save(self, path: str) -> None:
        """Save the trained model to disk."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self._model,
                "feature_names": self._feature_names,
                "label_map": self._label_map,
                "reverse_label_map": self._reverse_label_map,
                "name": self.name,
                "detector_type": self.detector_type.value,
            },
            path,
        )
        size_mb = os.path.getsize(path) / (1024 * 1024)
        logger.info(f"Model saved: {path} ({size_mb:.2f} MB)")

    def load(self, path: str) -> None:
        """Load a trained model from disk."""
        data = joblib.load(path)
        self._model = data["model"]
        self._feature_names = data.get("feature_names", [])
        self._label_map = data.get("label_map", {})
        self._reverse_label_map = data.get("reverse_label_map", {})
        self._is_trained = True
        logger.info(f"Model loaded: {path}")

    @property
    def is_trained(self) -> bool:
        return self._is_trained

    def _map_label(self, label_idx: int) -> AttackType:
        """Map integer label back to AttackType."""
        label_str = self._label_map.get(label_idx, "NONE")
        try:
            return AttackType(label_str)
        except ValueError:
            if label_str == "NORMAL":
                return AttackType.NONE
            return AttackType.NONE


# =============================================================================
# Random Forest Detector
# =============================================================================

class RandomForestDetector(BaseDetector):
    """
    Random Forest classifier for CAN intrusion detection.

    Strong baseline: fast training, interpretable, good for tabular data.
    """

    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: int = 20,
        random_seed: int = 42,
    ):
        super().__init__("RandomForest", DetectorType.RANDOM_FOREST)
        self._n_estimators = n_estimators
        self._max_depth = max_depth
        self._seed = random_seed

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        feature_names: list[str] | None = None,
    ) -> dict[str, Any]:
        from sklearn.ensemble import RandomForestClassifier

        self._feature_names = feature_names or []

        # Build label maps
        unique_labels = sorted(set(y_train))
        self._label_map = {i: label for i, label in enumerate(unique_labels)}
        self._reverse_label_map = {label: i for i, label in enumerate(unique_labels)}

        # Encode string labels to integers
        y_encoded = np.array([self._reverse_label_map[label] for label in y_train])

        start = time.perf_counter()
        self._model = RandomForestClassifier(
            n_estimators=self._n_estimators,
            max_depth=self._max_depth,
            random_state=self._seed,
            n_jobs=-1,
            class_weight="balanced",
        )
        self._model.fit(X_train, y_encoded)
        train_time = time.perf_counter() - start

        self._is_trained = True

        # Feature importance
        importances = {}
        if feature_names:
            for name, imp in zip(feature_names, self._model.feature_importances_):
                importances[name] = float(imp)

        logger.info(
            f"RandomForest trained: {self._n_estimators} trees, "
            f"{train_time:.2f}s, {len(X_train)} samples"
        )

        return {
            "train_time_seconds": round(train_time, 3),
            "n_samples": len(X_train),
            "n_features": X_train.shape[1],
            "n_classes": len(unique_labels),
            "feature_importance": importances,
        }

    def predict(self, features: np.ndarray) -> MLPrediction:
        if not self._is_trained or self._model is None:
            raise RuntimeError("Model not trained")

        start = time.perf_counter()
        x = features.reshape(1, -1)
        pred_class = self._model.predict(x)[0]
        probas = self._model.predict_proba(x)[0]
        latency_ms = (time.perf_counter() - start) * 1000

        attack_type = self._map_label(pred_class)
        confidence = float(probas[pred_class])

        # Anomaly score: 1 - probability of NORMAL class
        normal_idx = self._reverse_label_map.get("NORMAL", 0)
        if normal_idx < len(probas):
            anomaly_score = 1.0 - float(probas[normal_idx])
        else:
            anomaly_score = confidence if attack_type != AttackType.NONE else 0.0

        return MLPrediction(
            attack_type=attack_type,
            confidence=confidence,
            anomaly_score=anomaly_score,
            detector_name=self.name,
            inference_latency_ms=latency_ms,
        )

    def predict_batch(self, features: np.ndarray) -> list[MLPrediction]:
        if not self._is_trained or self._model is None:
            raise RuntimeError("Model not trained")

        start = time.perf_counter()
        pred_classes = self._model.predict(features)
        probas = self._model.predict_proba(features)
        total_ms = (time.perf_counter() - start) * 1000
        per_sample_ms = total_ms / len(features)

        normal_idx = self._reverse_label_map.get("NORMAL", 0)
        results = []
        for i, (pred, proba) in enumerate(zip(pred_classes, probas)):
            attack_type = self._map_label(pred)
            confidence = float(proba[pred])
            anomaly_score = 1.0 - float(proba[normal_idx]) if normal_idx < len(proba) else confidence
            results.append(
                MLPrediction(
                    attack_type=attack_type,
                    confidence=confidence,
                    anomaly_score=anomaly_score,
                    detector_name=self.name,
                    inference_latency_ms=per_sample_ms,
                )
            )
        return results


# =============================================================================
# Isolation Forest Detector
# =============================================================================

class IsolationForestDetector(BaseDetector):
    """
    Isolation Forest for unsupervised anomaly detection.

    Complements the Random Forest by detecting novel/unseen attacks
    without requiring labeled training data.
    """

    def __init__(self, n_estimators: int = 100, contamination: float = 0.1, random_seed: int = 42):
        super().__init__("IsolationForest", DetectorType.ISOLATION_FOREST)
        self._n_estimators = n_estimators
        self._contamination = contamination
        self._seed = random_seed

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray | None = None,
        feature_names: list[str] | None = None,
    ) -> dict[str, Any]:
        from sklearn.ensemble import IsolationForest

        self._feature_names = feature_names or []

        # Build label maps for compatibility
        if y_train is not None:
            unique_labels = sorted(set(y_train))
            self._label_map = {i: label for i, label in enumerate(unique_labels)}
            self._reverse_label_map = {label: i for i, label in enumerate(unique_labels)}

        start = time.perf_counter()
        self._model = IsolationForest(
            n_estimators=self._n_estimators,
            contamination=self._contamination,
            random_state=self._seed,
            n_jobs=-1,
        )
        # Train only on NORMAL data for anomaly detection
        if y_train is not None:
            normal_mask = np.array([y == "NORMAL" for y in y_train])
            X_normal = X_train[normal_mask]
            if len(X_normal) == 0:
                X_normal = X_train
        else:
            X_normal = X_train

        self._model.fit(X_normal)
        train_time = time.perf_counter() - start
        self._is_trained = True

        logger.info(f"IsolationForest trained: {train_time:.2f}s, {len(X_normal)} normal samples")
        return {
            "train_time_seconds": round(train_time, 3),
            "n_samples": len(X_normal),
            "n_features": X_train.shape[1],
        }

    def predict(self, features: np.ndarray) -> MLPrediction:
        if not self._is_trained or self._model is None:
            raise RuntimeError("Model not trained")

        start = time.perf_counter()
        x = features.reshape(1, -1)
        raw_score = self._model.decision_function(x)[0]
        prediction = self._model.predict(x)[0]
        latency_ms = (time.perf_counter() - start) * 1000

        # Convert: negative score = anomaly, positive = normal
        # Normalize to [0, 1] where 1 = strong anomaly
        anomaly_score = max(0.0, min(1.0, 0.5 - raw_score))
        is_anomaly = prediction == -1

        return MLPrediction(
            attack_type=AttackType.INJECTION if is_anomaly else AttackType.NONE,
            confidence=anomaly_score if is_anomaly else 1.0 - anomaly_score,
            anomaly_score=anomaly_score,
            detector_name=self.name,
            inference_latency_ms=latency_ms,
        )

    def predict_batch(self, features: np.ndarray) -> list[MLPrediction]:
        if not self._is_trained or self._model is None:
            raise RuntimeError("Model not trained")

        start = time.perf_counter()
        raw_scores = self._model.decision_function(features)
        predictions = self._model.predict(features)
        total_ms = (time.perf_counter() - start) * 1000
        per_sample_ms = total_ms / len(features)

        results = []
        for raw, pred in zip(raw_scores, predictions):
            anomaly_score = max(0.0, min(1.0, 0.5 - raw))
            is_anomaly = pred == -1
            results.append(
                MLPrediction(
                    attack_type=AttackType.INJECTION if is_anomaly else AttackType.NONE,
                    confidence=anomaly_score if is_anomaly else 1.0 - anomaly_score,
                    anomaly_score=anomaly_score,
                    detector_name=self.name,
                    inference_latency_ms=per_sample_ms,
                )
            )
        return results
