"""
Core domain models for the CAN Security Framework.

Provides strongly-typed, validated data structures for CAN messages,
security events, alerts, authentication metadata, and feature vectors.
Uses dataclasses for performance and Pydantic models for API boundaries.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from can_security.core.enums import (
    AttackType,
    AuthStatus,
    ECUType,
    FreshnessStatus,
    MessageStatus,
    ResponseAction,
    RuleName,
    Severity,
)


# =============================================================================
# CAN Message — Core Data Structure
# =============================================================================

@dataclass(slots=True)
class CANMessage:
    """
    Strongly-typed CAN message representation.

    Validates CAN ID range (0x000–0x7FF for standard CAN),
    DLC (0–8), and data length consistency.
    """
    timestamp: float
    can_id: int
    dlc: int
    data: bytes
    source_ecu: ECUType = ECUType.UNKNOWN
    sequence_counter: int | None = None
    is_authenticated: bool = False
    auth_tag: bytes | None = None
    message_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def __post_init__(self) -> None:
        """Validate CAN frame constraints."""
        if not (0x000 <= self.can_id <= 0x7FF):
            raise ValueError(
                f"CAN ID 0x{self.can_id:03X} out of standard range [0x000, 0x7FF]"
            )
        if not (0 <= self.dlc <= 8):
            raise ValueError(f"DLC {self.dlc} out of range [0, 8]")
        if len(self.data) != self.dlc:
            raise ValueError(
                f"Data length {len(self.data)} does not match DLC {self.dlc}"
            )
        if self.timestamp < 0:
            raise ValueError(f"Timestamp {self.timestamp} must be non-negative")

    @property
    def can_id_hex(self) -> str:
        """Return CAN ID as hex string for display/logging."""
        return f"0x{self.can_id:03X}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON/database storage."""
        return {
            "message_id": self.message_id,
            "timestamp": self.timestamp,
            "can_id": self.can_id,
            "can_id_hex": self.can_id_hex,
            "dlc": self.dlc,
            "data": self.data.hex(),
            "source_ecu": self.source_ecu.value,
            "sequence_counter": self.sequence_counter,
            "is_authenticated": self.is_authenticated,
        }


# =============================================================================
# Authentication Metadata
# =============================================================================

@dataclass(slots=True)
class AuthenticationResult:
    """Result of authenticating a CAN message."""
    status: AuthStatus
    can_id: int
    key_id: str | None = None
    key_version: int | None = None
    error_message: str | None = None
    timestamp: float = field(default_factory=time.time)


@dataclass(slots=True)
class FreshnessResult:
    """Result of a freshness/replay check on a CAN message."""
    status: FreshnessStatus
    can_id: int
    received_counter: int | None = None
    expected_counter: int | None = None
    error_message: str | None = None
    timestamp: float = field(default_factory=time.time)


# =============================================================================
# Rule Evidence
# =============================================================================

@dataclass(slots=True)
class RuleEvidence:
    """Structured evidence produced by a detection rule."""
    rule: RuleName
    can_id: int
    severity: Severity
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule.value,
            "can_id": f"0x{self.can_id:03X}",
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }


# =============================================================================
# ML Prediction
# =============================================================================

@dataclass(slots=True)
class MLPrediction:
    """Result from an ML-based detector."""
    attack_type: AttackType
    confidence: float  # 0.0–1.0
    anomaly_score: float  # 0.0–1.0
    detector_name: str
    inference_latency_ms: float
    feature_importance: dict[str, float] | None = None
    timestamp: float = field(default_factory=time.time)


# =============================================================================
# Security Event — Fused Decision
# =============================================================================

@dataclass(slots=True)
class SecurityEvent:
    """
    Complete security assessment for a CAN message or message window.

    Combines evidence from rules, ML, authentication, and freshness
    into a single explainable security decision.
    """
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    timestamp: float = field(default_factory=time.time)
    can_id: int = 0
    message_id: str | None = None
    attack_type: AttackType = AttackType.NONE
    severity: Severity = Severity.NORMAL
    risk_score: float = 0.0
    status: MessageStatus = MessageStatus.NORMAL

    # Evidence sources
    rule_evidence: list[RuleEvidence] = field(default_factory=list)
    ml_prediction: MLPrediction | None = None
    auth_result: AuthenticationResult | None = None
    freshness_result: FreshnessResult | None = None

    # Response
    actions_taken: list[ResponseAction] = field(default_factory=list)
    recommended_response: str = ""

    # Context
    source_ecu: ECUType = ECUType.UNKNOWN
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "can_id": f"0x{self.can_id:03X}",
            "message_id": self.message_id,
            "attack_type": self.attack_type.value,
            "severity": self.severity.value,
            "risk_score": round(self.risk_score, 4),
            "status": self.status.value,
            "rule_evidence": [r.to_dict() for r in self.rule_evidence],
            "ml_prediction": {
                "attack_type": self.ml_prediction.attack_type.value,
                "confidence": round(self.ml_prediction.confidence, 4),
                "anomaly_score": round(self.ml_prediction.anomaly_score, 4),
                "detector": self.ml_prediction.detector_name,
            } if self.ml_prediction else None,
            "auth_status": self.auth_result.status.value if self.auth_result else None,
            "freshness_status": (
                self.freshness_result.status.value if self.freshness_result else None
            ),
            "actions_taken": [a.value for a in self.actions_taken],
            "source_ecu": self.source_ecu.value,
            "description": self.description,
        }


# =============================================================================
# Alert — User-Facing Notification
# =============================================================================

@dataclass(slots=True)
class Alert:
    """
    Explainable security alert with full context.

    Every alert must explain WHY it was raised — not just "attack detected".
    """
    alert_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    timestamp: float = field(default_factory=time.time)
    can_id: int = 0
    attack_type: AttackType = AttackType.NONE
    severity: Severity = Severity.NORMAL
    confidence: float = 0.0
    risk_score: float = 0.0

    # Explanation — the key differentiator
    title: str = ""
    description: str = ""
    ml_score: float | None = None
    rule_evidence: list[dict[str, Any]] = field(default_factory=list)
    auth_status: AuthStatus = AuthStatus.NOT_REQUIRED
    freshness_status: FreshnessStatus = FreshnessStatus.NOT_REQUIRED
    recommended_response: str = ""

    source_ecu: ECUType = ECUType.UNKNOWN
    event_id: str | None = None
    acknowledged: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "can_id": f"0x{self.can_id:03X}",
            "attack_type": self.attack_type.value,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 4),
            "risk_score": round(self.risk_score, 4),
            "title": self.title,
            "description": self.description,
            "ml_score": round(self.ml_score, 4) if self.ml_score is not None else None,
            "rule_evidence": self.rule_evidence,
            "auth_status": self.auth_status.value,
            "freshness_status": self.freshness_status.value,
            "recommended_response": self.recommended_response,
            "source_ecu": self.source_ecu.value,
            "acknowledged": self.acknowledged,
        }


# =============================================================================
# Feature Vector
# =============================================================================

@dataclass(slots=True)
class FeatureVector:
    """
    Extracted feature vector from a CAN message window.

    Used as input to ML detectors. All features are numeric for
    direct consumption by sklearn/PyTorch models.
    """
    can_id: int
    features: dict[str, float]
    window_start: float  # timestamp of first message in window
    window_end: float  # timestamp of last message in window
    window_size: int  # number of messages in window
    label: AttackType = AttackType.NONE  # ground truth for training

    def to_array(self) -> list[float]:
        """Convert to ordered float array for model input."""
        return list(self.features.values())

    def feature_names(self) -> list[str]:
        """Return ordered feature names matching to_array() order."""
        return list(self.features.keys())


# =============================================================================
# System Metrics
# =============================================================================

@dataclass(slots=True)
class SystemMetrics:
    """Runtime system performance metrics."""
    timestamp: float = field(default_factory=time.time)
    messages_per_second: float = 0.0
    processing_latency_ms: float = 0.0
    feature_extraction_latency_ms: float = 0.0
    ml_inference_latency_ms: float = 0.0
    auth_latency_ms: float = 0.0
    db_write_latency_ms: float = 0.0
    end_to_end_latency_ms: float = 0.0
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    total_messages: int = 0
    total_alerts: int = 0
    total_attacks_detected: int = 0
