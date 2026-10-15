"""
Rule-based intrusion detection engine.

Implements 9 fast, lightweight detection rules that produce
structured evidence. Each rule is independently configurable
and can be enabled/disabled via detection_rules.yaml.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Any

from can_security.core.enums import RuleName, Severity
from can_security.core.models import CANMessage, RuleEvidence

logger = logging.getLogger(__name__)


class RuleEngine:
    """
    Fast rule-based detection engine.

    Maintains per-CAN-ID state for frequency and counter tracking.
    Each rule produces structured RuleEvidence on trigger.
    """

    def __init__(
        self,
        can_id_definitions: dict[int, dict[str, Any]],
        rule_config: dict[str, dict[str, Any]],
    ):
        self._can_defs = can_id_definitions
        self._rules = rule_config
        self._known_ids = set(can_id_definitions.keys())

        # Per-ID state tracking
        self._id_timestamps: dict[int, list[float]] = defaultdict(list)
        self._id_counters: dict[int, int | None] = {}
        self._last_check_time: float = 0.0

        # Maximum history length per ID (for frequency calculations)
        self._max_history = 200

    def evaluate(self, message: CANMessage) -> list[RuleEvidence]:
        """
        Evaluate all enabled rules against a CAN message.

        Returns a list of triggered rule evidence (may be empty).
        """
        evidence: list[RuleEvidence] = []

        # Track timestamp history
        ts_list = self._id_timestamps[message.can_id]
        ts_list.append(message.timestamp)
        if len(ts_list) > self._max_history:
            ts_list.pop(0)

        # Rule 1: Unknown CAN ID
        if self._is_enabled("unknown_can_id"):
            result = self._check_unknown_id(message)
            if result:
                evidence.append(result)

        # Rule 2: Invalid DLC
        if self._is_enabled("invalid_dlc"):
            result = self._check_invalid_dlc(message)
            if result:
                evidence.append(result)

        # Rule 3: Abnormal frequency
        if self._is_enabled("abnormal_frequency"):
            result = self._check_abnormal_frequency(message)
            if result:
                evidence.append(result)

        # Rule 4: Excessive burst
        if self._is_enabled("excessive_burst"):
            result = self._check_excessive_burst(message)
            if result:
                evidence.append(result)

        # Rule 5: Invalid payload range
        if self._is_enabled("invalid_payload_range"):
            result = self._check_invalid_payload(message)
            if result:
                evidence.append(result)

        # Rule 6: Unexpected source
        if self._is_enabled("unexpected_source"):
            result = self._check_unexpected_source(message)
            if result:
                evidence.append(result)

        # Rule 7: Counter anomaly
        if self._is_enabled("counter_anomaly"):
            result = self._check_counter_anomaly(message)
            if result:
                evidence.append(result)

        return evidence

    def _is_enabled(self, rule_name: str) -> bool:
        return self._rules.get(rule_name, {}).get("enabled", False)

    def _get_severity(self, rule_name: str) -> Severity:
        sev_str = self._rules.get(rule_name, {}).get("severity", "MEDIUM")
        try:
            return Severity(sev_str)
        except ValueError:
            return Severity.MEDIUM

    # --- Rule Implementations ---

    def _check_unknown_id(self, msg: CANMessage) -> RuleEvidence | None:
        if msg.can_id not in self._known_ids:
            return RuleEvidence(
                rule=RuleName.UNKNOWN_CAN_ID,
                can_id=msg.can_id,
                severity=self._get_severity("unknown_can_id"),
                description=f"Unknown CAN ID 0x{msg.can_id:03X} not in configured ID map",
                evidence={
                    "can_id_hex": f"0x{msg.can_id:03X}",
                    "known_ids": len(self._known_ids),
                },
            )
        return None

    def _check_invalid_dlc(self, msg: CANMessage) -> RuleEvidence | None:
        id_def = self._can_defs.get(msg.can_id)
        if id_def is None:
            return None

        expected_dlc = id_def.get("dlc")
        if expected_dlc is not None and msg.dlc != expected_dlc:
            return RuleEvidence(
                rule=RuleName.INVALID_DLC,
                can_id=msg.can_id,
                severity=self._get_severity("invalid_dlc"),
                description=(
                    f"CAN ID 0x{msg.can_id:03X} DLC {msg.dlc} "
                    f"does not match expected DLC {expected_dlc}"
                ),
                evidence={
                    "observed_dlc": msg.dlc,
                    "expected_dlc": expected_dlc,
                },
            )
        return None

    def _check_abnormal_frequency(self, msg: CANMessage) -> RuleEvidence | None:
        id_def = self._can_defs.get(msg.can_id)
        if id_def is None:
            return None

        expected_period_ms = id_def.get("period_ms", 0)
        if expected_period_ms <= 0:
            return None  # Event-driven, no expected frequency

        expected_rate = 1000.0 / expected_period_ms  # msg/s

        rule_cfg = self._rules.get("abnormal_frequency", {})
        high_mult = rule_cfg.get("high_threshold_multiplier", 3.0)
        low_mult = rule_cfg.get("low_threshold_multiplier", 0.1)
        window_s = rule_cfg.get("measurement_window_seconds", 1.0)

        # Calculate observed rate in the measurement window
        ts_list = self._id_timestamps[msg.can_id]
        cutoff = msg.timestamp - window_s
        recent = [t for t in ts_list if t > cutoff]
        observed_rate = len(recent) / window_s if window_s > 0 else 0

        if observed_rate > expected_rate * high_mult:
            return RuleEvidence(
                rule=RuleName.ABNORMAL_FREQUENCY,
                can_id=msg.can_id,
                severity=self._get_severity("abnormal_frequency"),
                description=(
                    f"CAN ID 0x{msg.can_id:03X} frequency {observed_rate:.1f} msg/s "
                    f"exceeds {high_mult}x expected rate {expected_rate:.1f} msg/s"
                ),
                evidence={
                    "observed_rate": round(observed_rate, 2),
                    "expected_rate": round(expected_rate, 2),
                    "threshold_multiplier": high_mult,
                    "window_seconds": window_s,
                },
            )
        elif observed_rate < expected_rate * low_mult and len(recent) > 3:
            return RuleEvidence(
                rule=RuleName.ABNORMAL_FREQUENCY,
                can_id=msg.can_id,
                severity=Severity.LOW,
                description=(
                    f"CAN ID 0x{msg.can_id:03X} frequency {observed_rate:.1f} msg/s "
                    f"below {low_mult}x expected rate {expected_rate:.1f} msg/s"
                ),
                evidence={
                    "observed_rate": round(observed_rate, 2),
                    "expected_rate": round(expected_rate, 2),
                    "threshold_multiplier": low_mult,
                    "direction": "low",
                },
            )
        return None

    def _check_excessive_burst(self, msg: CANMessage) -> RuleEvidence | None:
        rule_cfg = self._rules.get("excessive_burst", {})
        threshold = rule_cfg.get("burst_threshold", 50)
        window_s = rule_cfg.get("burst_window_seconds", 0.1)

        ts_list = self._id_timestamps[msg.can_id]
        cutoff = msg.timestamp - window_s
        burst_count = sum(1 for t in ts_list if t > cutoff)

        if burst_count > threshold:
            return RuleEvidence(
                rule=RuleName.EXCESSIVE_BURST,
                can_id=msg.can_id,
                severity=self._get_severity("excessive_burst"),
                description=(
                    f"CAN ID 0x{msg.can_id:03X} burst of {burst_count} messages "
                    f"in {window_s}s exceeds threshold of {threshold}"
                ),
                evidence={
                    "burst_count": burst_count,
                    "burst_window_seconds": window_s,
                    "threshold": threshold,
                },
            )
        return None

    def _check_invalid_payload(self, msg: CANMessage) -> RuleEvidence | None:
        """Check signal values against configured ranges."""
        id_def = self._can_defs.get(msg.can_id)
        if id_def is None:
            return None

        from can_security.can.message import CANMessageFactory

        signal_defs = id_def.get("signals", [])
        if not signal_defs:
            return None

        violations = CANMessageFactory.validate_payload_range(msg, signal_defs)
        if violations:
            return RuleEvidence(
                rule=RuleName.INVALID_PAYLOAD_RANGE,
                can_id=msg.can_id,
                severity=self._get_severity("invalid_payload_range"),
                description=(
                    f"CAN ID 0x{msg.can_id:03X} payload out of range: "
                    + "; ".join(violations)
                ),
                evidence={
                    "violations": violations,
                    "violation_count": len(violations),
                },
            )
        return None

    def _check_unexpected_source(self, msg: CANMessage) -> RuleEvidence | None:
        id_def = self._can_defs.get(msg.can_id)
        if id_def is None:
            return None

        expected_source = id_def.get("source_ecu")
        if expected_source is None:
            return None

        if (
            msg.source_ecu.value != "unknown"
            and msg.source_ecu.value != expected_source
        ):
            return RuleEvidence(
                rule=RuleName.UNEXPECTED_SOURCE,
                can_id=msg.can_id,
                severity=self._get_severity("unexpected_source"),
                description=(
                    f"CAN ID 0x{msg.can_id:03X} received from "
                    f"{msg.source_ecu.value}, expected {expected_source}"
                ),
                evidence={
                    "observed_source": msg.source_ecu.value,
                    "expected_source": expected_source,
                },
            )
        return None

    def _check_counter_anomaly(self, msg: CANMessage) -> RuleEvidence | None:
        if msg.sequence_counter is None:
            return None

        rule_cfg = self._rules.get("counter_anomaly", {})
        max_gap = rule_cfg.get("max_acceptable_gap", 5)

        last_counter = self._id_counters.get(msg.can_id)
        self._id_counters[msg.can_id] = msg.sequence_counter

        if last_counter is None:
            return None  # First message, no comparison

        expected_next = last_counter + 1
        gap = msg.sequence_counter - expected_next

        if gap < 0:
            # Counter went backwards — possible replay
            return RuleEvidence(
                rule=RuleName.COUNTER_ANOMALY,
                can_id=msg.can_id,
                severity=Severity.HIGH,
                description=(
                    f"CAN ID 0x{msg.can_id:03X} counter went backwards: "
                    f"{last_counter} -> {msg.sequence_counter}"
                ),
                evidence={
                    "last_counter": last_counter,
                    "received_counter": msg.sequence_counter,
                    "gap": gap,
                    "direction": "backwards",
                },
            )
        elif gap > max_gap:
            # Counter jumped too far — possible missed messages or tampering
            return RuleEvidence(
                rule=RuleName.COUNTER_ANOMALY,
                can_id=msg.can_id,
                severity=Severity.MEDIUM,
                description=(
                    f"CAN ID 0x{msg.can_id:03X} counter jump of {gap} "
                    f"exceeds max acceptable gap of {max_gap}"
                ),
                evidence={
                    "last_counter": last_counter,
                    "received_counter": msg.sequence_counter,
                    "gap": gap,
                    "max_gap": max_gap,
                    "direction": "forward",
                },
            )
        return None

    def reset(self) -> None:
        """Clear all tracked state."""
        self._id_timestamps.clear()
        self._id_counters.clear()
