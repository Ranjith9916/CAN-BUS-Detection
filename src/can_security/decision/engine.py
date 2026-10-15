"""
Security decision engine.

Fuses evidence from rules, ML, authentication, and freshness
into a single explainable risk score and severity classification.
"""

from __future__ import annotations

import logging
from typing import Any

from can_security.core.enums import (
    AttackType,
    AuthStatus,
    FreshnessStatus,
    MessageStatus,
    ResponseAction,
    Severity,
)
from can_security.core.models import (
    Alert,
    AuthenticationResult,
    CANMessage,
    FreshnessResult,
    MLPrediction,
    RuleEvidence,
    SecurityEvent,
)

logger = logging.getLogger(__name__)


class SecurityDecisionEngine:
    """
    Combines multiple security signals into an explainable decision.

    Scoring model:
    - Rule evidence contributes based on rule severity
    - ML anomaly score contributes based on confidence
    - Authentication failures add significant risk
    - Freshness violations add significant risk
    - Scores are combined and classified into severity levels
    """

    # Severity → base risk contribution
    SEVERITY_WEIGHTS = {
        Severity.NORMAL: 0.0,
        Severity.LOW: 0.15,
        Severity.MEDIUM: 0.35,
        Severity.HIGH: 0.6,
        Severity.CRITICAL: 0.9,
    }

    def __init__(
        self,
        risk_thresholds: dict[str, float] | None = None,
        response_policy: dict[str, list[str]] | None = None,
    ):
        self._thresholds = risk_thresholds or {
            "normal": 0.29,
            "low": 0.59,
            "medium": 0.79,
            "high": 0.94,
            "critical": 1.0,
        }
        self._response_policy = response_policy or {}

    def evaluate(
        self,
        message: CANMessage,
        rule_evidence: list[RuleEvidence] | None = None,
        ml_prediction: MLPrediction | None = None,
        auth_result: AuthenticationResult | None = None,
        freshness_result: FreshnessResult | None = None,
    ) -> SecurityEvent:
        """
        Produce a security decision by fusing all available evidence.

        The risk score is computed as a weighted combination of:
        - Max rule severity (0.3 weight)
        - ML anomaly score (0.3 weight)
        - Auth failure (0.2 weight)
        - Freshness failure (0.2 weight)
        """
        rule_evidence = rule_evidence or []

        # Calculate component scores
        rule_score = self._score_rules(rule_evidence)
        ml_score = self._score_ml(ml_prediction)
        auth_score = self._score_auth(auth_result)
        freshness_score = self._score_freshness(freshness_result)

        # Weighted fusion
        risk_score = (
            0.3 * rule_score
            + 0.3 * ml_score
            + 0.2 * auth_score
            + 0.2 * freshness_score
        )

        # Any CRITICAL evidence should push score to at least 0.8
        if any(e.severity == Severity.CRITICAL for e in rule_evidence):
            risk_score = max(risk_score, 0.8)
        if auth_result and auth_result.status == AuthStatus.INVALID:
            risk_score = max(risk_score, 0.85)
        if freshness_result and freshness_result.status == FreshnessStatus.REPLAY:
            risk_score = max(risk_score, 0.85)

        # Clamp to [0, 1]
        risk_score = max(0.0, min(1.0, risk_score))

        # Classify severity
        severity = self._classify_severity(risk_score)
        status = self._classify_status(severity)
        attack_type = self._determine_attack_type(
            rule_evidence, ml_prediction, auth_result, freshness_result
        )

        # Determine response actions
        actions = self._determine_actions(severity)
        recommended = self._build_recommendation(severity, attack_type)

        # Build description
        description = self._build_description(
            message, rule_evidence, ml_prediction, auth_result, freshness_result,
            risk_score, severity
        )

        event = SecurityEvent(
            can_id=message.can_id,
            message_id=message.message_id,
            attack_type=attack_type,
            severity=severity,
            risk_score=risk_score,
            status=status,
            rule_evidence=rule_evidence,
            ml_prediction=ml_prediction,
            auth_result=auth_result,
            freshness_result=freshness_result,
            actions_taken=actions,
            recommended_response=recommended,
            source_ecu=message.source_ecu,
            description=description,
        )

        return event

    def create_alert(self, event: SecurityEvent) -> Alert | None:
        """
        Create an alert from a security event if severity warrants it.

        Only creates alerts for MEDIUM, HIGH, or CRITICAL severity.
        """
        if event.severity in (Severity.NORMAL, Severity.LOW):
            return None

        return Alert(
            can_id=event.can_id,
            attack_type=event.attack_type,
            severity=event.severity,
            confidence=event.ml_prediction.confidence if event.ml_prediction else 0.0,
            risk_score=event.risk_score,
            title=self._alert_title(event),
            description=event.description,
            ml_score=(
                event.ml_prediction.anomaly_score if event.ml_prediction else None
            ),
            rule_evidence=[e.to_dict() for e in event.rule_evidence],
            auth_status=(
                event.auth_result.status if event.auth_result else AuthStatus.NOT_REQUIRED
            ),
            freshness_status=(
                event.freshness_result.status
                if event.freshness_result
                else FreshnessStatus.NOT_REQUIRED
            ),
            recommended_response=event.recommended_response,
            source_ecu=event.source_ecu,
            event_id=event.event_id,
        )

    # --- Scoring Helpers ---

    def _score_rules(self, evidence: list[RuleEvidence]) -> float:
        if not evidence:
            return 0.0
        # Use the maximum severity weight among triggered rules
        max_weight = max(
            self.SEVERITY_WEIGHTS.get(e.severity, 0.0) for e in evidence
        )
        # Add a small bonus for multiple triggered rules
        multi_bonus = min(0.1, len(evidence) * 0.02)
        return min(1.0, max_weight + multi_bonus)

    def _score_ml(self, prediction: MLPrediction | None) -> float:
        if prediction is None:
            return 0.0
        return prediction.anomaly_score

    def _score_auth(self, result: AuthenticationResult | None) -> float:
        if result is None or result.status == AuthStatus.NOT_REQUIRED:
            return 0.0
        if result.status == AuthStatus.VALID:
            return 0.0
        if result.status == AuthStatus.INVALID:
            return 1.0
        if result.status == AuthStatus.MISSING_KEY:
            return 0.5
        return 0.3  # ERROR

    def _score_freshness(self, result: FreshnessResult | None) -> float:
        if result is None or result.status == FreshnessStatus.NOT_REQUIRED:
            return 0.0
        if result.status == FreshnessStatus.FRESH:
            return 0.0
        if result.status == FreshnessStatus.REPLAY:
            return 1.0
        if result.status == FreshnessStatus.STALE:
            return 0.9
        if result.status == FreshnessStatus.COUNTER_JUMP:
            return 0.4
        return 0.3

    def _classify_severity(self, risk_score: float) -> Severity:
        if risk_score <= self._thresholds["normal"]:
            return Severity.NORMAL
        if risk_score <= self._thresholds["low"]:
            return Severity.LOW
        if risk_score <= self._thresholds["medium"]:
            return Severity.MEDIUM
        if risk_score <= self._thresholds["high"]:
            return Severity.HIGH
        return Severity.CRITICAL

    def _classify_status(self, severity: Severity) -> MessageStatus:
        if severity == Severity.NORMAL:
            return MessageStatus.NORMAL
        if severity in (Severity.LOW, Severity.MEDIUM):
            return MessageStatus.SUSPICIOUS
        return MessageStatus.ATTACK

    def _determine_attack_type(
        self,
        rules: list[RuleEvidence],
        ml: MLPrediction | None,
        auth: AuthenticationResult | None,
        freshness: FreshnessResult | None,
    ) -> AttackType:
        """Determine the most likely attack type from all evidence."""
        # 1. Cryptographic failures (Deterministic & High Severity)
        if auth and auth.status == AuthStatus.INVALID:
            return AttackType.SPOOFING

        if freshness and freshness.status in (
            FreshnessStatus.REPLAY, FreshnessStatus.STALE
        ):
            return AttackType.REPLAY

        # 2. Deterministic Rule Evidence (Prioritized by specificity)
        rule_names = {e.rule for e in rules}
        from can_security.core.enums import RuleName
        
        if RuleName.UNKNOWN_CAN_ID in rule_names:
            return AttackType.INJECTION
            
        if RuleName.EXCESSIVE_BURST in rule_names:
            return AttackType.FLOODING
            
        if RuleName.UNEXPECTED_SOURCE in rule_names:
            return AttackType.SPOOFING
            
        if RuleName.ABNORMAL_FREQUENCY in rule_names:
            return AttackType.ABNORMAL_FREQUENCY

        # 3. Probabilistic ML Prediction (Fallback)
        if ml and ml.attack_type != AttackType.NONE:
            return ml.attack_type

        return AttackType.NONE

    def _determine_actions(self, severity: Severity) -> list[ResponseAction]:
        actions = [ResponseAction.LOG]
        if severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL):
            actions.append(ResponseAction.ALERT)
        if severity in (Severity.HIGH, Severity.CRITICAL):
            actions.append(ResponseAction.QUARANTINE_SIMULATION_MESSAGE)
        if severity == Severity.CRITICAL:
            actions.append(ResponseAction.REJECT_SIMULATED_MESSAGE)
        return actions

    def _build_recommendation(
        self, severity: Severity, attack_type: AttackType
    ) -> str:
        if severity == Severity.CRITICAL:
            return (
                f"CRITICAL: Immediate investigation required. "
                f"Suspected {attack_type.value} attack. "
                f"Message rejected in simulation."
            )
        if severity == Severity.HIGH:
            return (
                f"HIGH: Review CAN traffic for {attack_type.value} patterns. "
                f"Message quarantined in simulation."
            )
        if severity == Severity.MEDIUM:
            return f"MEDIUM: Monitor {attack_type.value} activity closely."
        if severity == Severity.LOW:
            return "LOW: Minor anomaly detected. Continue monitoring."
        return "NORMAL: No action required."

    def _build_description(
        self,
        msg: CANMessage,
        rules: list[RuleEvidence],
        ml: MLPrediction | None,
        auth: AuthenticationResult | None,
        freshness: FreshnessResult | None,
        risk_score: float,
        severity: Severity,
    ) -> str:
        parts = [f"CAN ID 0x{msg.can_id:03X} | Risk: {risk_score:.2f} | {severity.value}"]

        if rules:
            rule_names = ", ".join(e.rule.value for e in rules)
            parts.append(f"Rules triggered: {rule_names}")

        if ml and ml.anomaly_score > 0:
            parts.append(f"ML anomaly score: {ml.anomaly_score:.2f}")

        if auth:
            parts.append(f"Auth: {auth.status.value}")

        if freshness:
            parts.append(f"Freshness: {freshness.status.value}")

        return " | ".join(parts)

    def _alert_title(self, event: SecurityEvent) -> str:
        if event.attack_type != AttackType.NONE:
            return (
                f"{event.severity.value} - Potential {event.attack_type.value} "
                f"attack on CAN ID 0x{event.can_id:03X}"
            )
        return f"{event.severity.value} - Anomaly detected on CAN ID 0x{event.can_id:03X}"
