"""
Feature extraction pipeline for CAN traffic analysis.

Extracts temporal, frequency, and payload features from sliding
windows of CAN messages. All features are deterministic and testable.
"""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict
from typing import Any

from can_security.core.enums import AttackType
from can_security.core.models import CANMessage, FeatureVector

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """
    Main feature extraction pipeline.

    Processes a sliding window of CAN messages and produces a
    FeatureVector containing temporal, frequency, and payload features.
    """

    def __init__(self, window_size: int = 100, window_overlap: int = 50):
        self.window_size = window_size
        self.window_overlap = window_overlap
        self._buffer: list[CANMessage] = []
        self._extraction_count = 0

    def add_message(self, message: CANMessage) -> FeatureVector | None:
        """
        Add a message to the buffer. Returns a FeatureVector when
        a complete window is available.
        """
        self._buffer.append(message)

        if len(self._buffer) >= self.window_size:
            window = list(self._buffer[:self.window_size])
            # Slide the window
            self._buffer = self._buffer[self.window_size - self.window_overlap:]
            return self.extract(window)

        return None

    def extract(
        self,
        messages: list[CANMessage],
        label: AttackType = AttackType.NONE,
    ) -> FeatureVector:
        """
        Extract all features from a window of CAN messages.

        Returns a FeatureVector with deterministic feature ordering.
        """
        if not messages:
            raise ValueError("Cannot extract features from empty message list")

        start_time = time.perf_counter()

        features: dict[str, float] = {}

        # 1. Temporal features
        features.update(self._extract_temporal(messages))

        # 2. Frequency features
        features.update(self._extract_frequency(messages))

        # 3. Payload features
        features.update(self._extract_payload(messages))

        # 4. CAN ID distribution features
        features.update(self._extract_id_distribution(messages))

        latency_ms = (time.perf_counter() - start_time) * 1000
        self._extraction_count += 1

        if self._extraction_count % 100 == 0:
            logger.debug(
                "Feature extraction",
                extra={
                    "count": self._extraction_count,
                    "latency_ms": round(latency_ms, 3),
                },
            )

        # Use the most common CAN ID in the window as the primary ID
        id_counts = defaultdict(int)
        for msg in messages:
            id_counts[msg.can_id] += 1
        primary_id = max(id_counts, key=id_counts.get)

        return FeatureVector(
            can_id=primary_id,
            features=features,
            window_start=messages[0].timestamp,
            window_end=messages[-1].timestamp,
            window_size=len(messages),
            label=label,
        )

    def _extract_temporal(self, messages: list[CANMessage]) -> dict[str, float]:
        """Extract timing-based features."""
        features: dict[str, float] = {}

        timestamps = [m.timestamp for m in messages]
        window_duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0.0

        features["window_duration"] = window_duration
        features["message_count"] = float(len(messages))

        # Inter-arrival times
        if len(timestamps) > 1:
            intervals = [
                timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))
            ]
            features["iat_mean"] = sum(intervals) / len(intervals)
            features["iat_std"] = _std(intervals)
            features["iat_min"] = min(intervals)
            features["iat_max"] = max(intervals)
            features["iat_range"] = features["iat_max"] - features["iat_min"]

            # Coefficient of variation (normalized std)
            if features["iat_mean"] > 0:
                features["iat_cv"] = features["iat_std"] / features["iat_mean"]
            else:
                features["iat_cv"] = 0.0
        else:
            features["iat_mean"] = 0.0
            features["iat_std"] = 0.0
            features["iat_min"] = 0.0
            features["iat_max"] = 0.0
            features["iat_range"] = 0.0
            features["iat_cv"] = 0.0

        # Burst detection: count rapid-fire messages (interval < 0.001s)
        if len(timestamps) > 1:
            burst_count = sum(
                1 for i in range(1, len(timestamps))
                if timestamps[i] - timestamps[i - 1] < 0.001
            )
            features["burst_ratio"] = burst_count / (len(timestamps) - 1)
        else:
            features["burst_ratio"] = 0.0

        return features

    def _extract_frequency(self, messages: list[CANMessage]) -> dict[str, float]:
        """Extract frequency-based features."""
        features: dict[str, float] = {}

        window_duration = (
            messages[-1].timestamp - messages[0].timestamp
            if len(messages) > 1
            else 1.0
        )
        if window_duration == 0:
            window_duration = 1.0

        # Overall message rate
        features["msg_rate"] = len(messages) / window_duration

        # Per-CAN-ID frequencies
        id_counts: dict[int, int] = defaultdict(int)
        for msg in messages:
            id_counts[msg.can_id] += 1

        # Number of unique CAN IDs
        features["unique_ids"] = float(len(id_counts))

        # Frequency of most common and least common IDs
        if id_counts:
            max_count = max(id_counts.values())
            min_count = min(id_counts.values())
            features["max_id_frequency"] = max_count / window_duration
            features["min_id_frequency"] = min_count / window_duration
            features["id_freq_ratio"] = (
                max_count / min_count if min_count > 0 else float(max_count)
            )

            # Entropy of CAN ID distribution
            total = sum(id_counts.values())
            probs = [c / total for c in id_counts.values()]
            features["id_entropy"] = -sum(
                p * math.log2(p) for p in probs if p > 0
            )
        else:
            features["max_id_frequency"] = 0.0
            features["min_id_frequency"] = 0.0
            features["id_freq_ratio"] = 0.0
            features["id_entropy"] = 0.0

        return features

    def _extract_payload(self, messages: list[CANMessage]) -> dict[str, float]:
        """Extract payload-based features."""
        features: dict[str, float] = {}

        # DLC statistics
        dlcs = [float(m.dlc) for m in messages]
        features["dlc_mean"] = sum(dlcs) / len(dlcs)
        features["dlc_std"] = _std(dlcs)
        features["dlc_min"] = min(dlcs)
        features["dlc_max"] = max(dlcs)

        # Byte-level statistics across all payloads
        all_bytes: list[int] = []
        for msg in messages:
            all_bytes.extend(msg.data)

        if all_bytes:
            features["payload_mean"] = sum(all_bytes) / len(all_bytes)
            features["payload_std"] = _std([float(b) for b in all_bytes])
            features["payload_min"] = float(min(all_bytes))
            features["payload_max"] = float(max(all_bytes))

            # Payload entropy (byte-level Shannon entropy)
            byte_counts: dict[int, int] = defaultdict(int)
            for b in all_bytes:
                byte_counts[b] += 1
            total = len(all_bytes)
            probs = [c / total for c in byte_counts.values()]
            features["payload_entropy"] = -sum(
                p * math.log2(p) for p in probs if p > 0
            )

            # Ratio of zero bytes
            features["zero_byte_ratio"] = sum(
                1 for b in all_bytes if b == 0
            ) / len(all_bytes)
        else:
            features["payload_mean"] = 0.0
            features["payload_std"] = 0.0
            features["payload_min"] = 0.0
            features["payload_max"] = 0.0
            features["payload_entropy"] = 0.0
            features["zero_byte_ratio"] = 0.0

        return features

    def _extract_id_distribution(
        self, messages: list[CANMessage]
    ) -> dict[str, float]:
        """Extract CAN ID distribution features as normalized counts."""
        # Fixed set of known CAN IDs for consistent feature vector length
        known_ids = [
            0x100, 0x101, 0x102, 0x103, 0x104,
            0x105, 0x106, 0x107, 0x200, 0x201,
        ]

        id_counts: dict[int, int] = defaultdict(int)
        for msg in messages:
            id_counts[msg.can_id] += 1

        total = len(messages)
        features: dict[str, float] = {}
        for cid in known_ids:
            features[f"id_ratio_0x{cid:03X}"] = (
                id_counts.get(cid, 0) / total if total > 0 else 0.0
            )

        # Count of unknown IDs (not in known set)
        unknown_count = sum(
            count for cid, count in id_counts.items() if cid not in known_ids
        )
        features["unknown_id_ratio"] = unknown_count / total if total > 0 else 0.0

        return features

    def reset(self) -> None:
        """Clear the internal buffer."""
        self._buffer.clear()

    @property
    def buffer_size(self) -> int:
        return len(self._buffer)

    @staticmethod
    def feature_names() -> list[str]:
        """Return the canonical ordered list of feature names."""
        # Build by running extraction on a dummy window
        extractor = FeatureExtractor(window_size=2)
        dummy = CANMessage(
            timestamp=0.0, can_id=0x100, dlc=8, data=b"\x00" * 8
        )
        dummy2 = CANMessage(
            timestamp=0.01, can_id=0x100, dlc=8, data=b"\x00" * 8
        )
        fv = extractor.extract([dummy, dummy2])
        return fv.feature_names()


def _std(values: list[float]) -> float:
    """Calculate population standard deviation."""
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)
