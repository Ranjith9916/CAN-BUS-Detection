"""
Unit tests for feature extraction, rule engine, authentication,
freshness, decision engine, and attack simulation.
"""

import math
import secrets

import pytest

from can_security.core.config import load_config
from can_security.core.enums import (
    AttackType, AuthStatus, ECUType, FreshnessStatus,
    RuleName, Severity, MessageStatus,
)
from can_security.core.models import (
    CANMessage, MLPrediction, AuthenticationResult, FreshnessResult,
)
from can_security.features.extractor import FeatureExtractor
from can_security.detection.rules import RuleEngine
from can_security.authentication.hmac_auth import HMACAuthenticator
from can_security.authentication.key_manager import KeyManager
from can_security.authentication.freshness import FreshnessManager
from can_security.decision.engine import SecurityDecisionEngine
from can_security.attacks.simulator import AttackSimulator


# =============================================================================
# Feature Extraction Tests
# =============================================================================

class TestFeatureExtractor:
    def _make_messages(self, n=100, can_id=0x100, start_time=0.0, interval=0.01):
        return [
            CANMessage(
                timestamp=start_time + i * interval,
                can_id=can_id,
                dlc=8,
                data=bytes([i % 256] * 8),
                source_ecu=ECUType.ENGINE,
            )
            for i in range(n)
        ]

    def test_extract_basic(self):
        msgs = self._make_messages(50)
        extractor = FeatureExtractor(window_size=50)
        fv = extractor.extract(msgs)
        assert fv.window_size == 50
        assert len(fv.features) > 10
        assert fv.can_id == 0x100

    def test_deterministic(self):
        msgs = self._make_messages(50)
        ext = FeatureExtractor(window_size=50)
        fv1 = ext.extract(msgs)
        fv2 = ext.extract(msgs)
        assert fv1.features == fv2.features

    def test_iat_features(self):
        msgs = self._make_messages(50, interval=0.01)
        fv = FeatureExtractor(window_size=50).extract(msgs)
        # Inter-arrival time mean should be ~0.01
        assert abs(fv.features["iat_mean"] - 0.01) < 0.001

    def test_feature_names_consistent(self):
        names = FeatureExtractor.feature_names()
        assert len(names) > 10
        assert "iat_mean" in names
        assert "msg_rate" in names
        assert "payload_entropy" in names

    def test_sliding_window(self):
        extractor = FeatureExtractor(window_size=10, window_overlap=5)
        results = []
        for i in range(20):
            msg = CANMessage(
                timestamp=i * 0.01,
                can_id=0x100,
                dlc=8,
                data=b"\x00" * 8,
            )
            fv = extractor.add_message(msg)
            if fv is not None:
                results.append(fv)
        # Should produce at least 1 feature vector from 20 messages with window=10
        assert len(results) >= 1


# =============================================================================
# Rule Engine Tests
# =============================================================================

class TestRuleEngine:
    @pytest.fixture
    def config(self):
        return load_config()

    @pytest.fixture
    def engine(self, config):
        return RuleEngine(config.can_id_definitions, config.detection_rules)

    def test_unknown_id_triggers(self, engine):
        msg = CANMessage(
            timestamp=1.0, can_id=0x7FF, dlc=8, data=b"\x00" * 8
        )
        evidence = engine.evaluate(msg)
        rules = [e.rule for e in evidence]
        assert RuleName.UNKNOWN_CAN_ID in rules

    def test_known_id_no_trigger(self, engine):
        msg = CANMessage(
            timestamp=1.0, can_id=0x100, dlc=8, data=b"\x00" * 8,
            source_ecu=ECUType.ENGINE,
        )
        evidence = engine.evaluate(msg)
        rules = [e.rule for e in evidence]
        assert RuleName.UNKNOWN_CAN_ID not in rules

    def test_invalid_dlc_triggers(self, engine):
        msg = CANMessage(
            timestamp=1.0, can_id=0x100, dlc=4, data=b"\x00" * 4,
            source_ecu=ECUType.ENGINE,
        )
        evidence = engine.evaluate(msg)
        rules = [e.rule for e in evidence]
        assert RuleName.INVALID_DLC in rules

    def test_unexpected_source_triggers(self, engine):
        # 0x100 should come from ENGINE, not INFOTAINMENT
        msg = CANMessage(
            timestamp=1.0, can_id=0x100, dlc=8, data=b"\x00" * 8,
            source_ecu=ECUType.INFOTAINMENT,
        )
        evidence = engine.evaluate(msg)
        rules = [e.rule for e in evidence]
        assert RuleName.UNEXPECTED_SOURCE in rules

    def test_counter_backwards_triggers(self, engine):
        # First message with counter 10
        msg1 = CANMessage(
            timestamp=1.0, can_id=0x100, dlc=8, data=b"\x00" * 8,
            source_ecu=ECUType.ENGINE, sequence_counter=10,
        )
        engine.evaluate(msg1)

        # Second message with counter 5 (backwards)
        msg2 = CANMessage(
            timestamp=2.0, can_id=0x100, dlc=8, data=b"\x00" * 8,
            source_ecu=ECUType.ENGINE, sequence_counter=5,
        )
        evidence = engine.evaluate(msg2)
        rules = [e.rule for e in evidence]
        assert RuleName.COUNTER_ANOMALY in rules

    def test_evidence_has_structure(self, engine):
        msg = CANMessage(
            timestamp=1.0, can_id=0x7FF, dlc=8, data=b"\x00" * 8
        )
        evidence = engine.evaluate(msg)
        assert len(evidence) > 0
        e = evidence[0]
        d = e.to_dict()
        assert "rule" in d
        assert "severity" in d
        assert "evidence" in d


# =============================================================================
# Authentication Tests
# =============================================================================

class TestHMACAuth:
    @pytest.fixture
    def key(self):
        return secrets.token_bytes(32)

    @pytest.fixture
    def auth(self, key):
        return HMACAuthenticator(key, key_id="test", key_version=1)

    def test_sign_produces_tag(self, auth):
        msg = CANMessage(timestamp=0.0, can_id=0x100, dlc=8, data=b"\x00" * 8)
        tag = auth.sign(msg, counter=1)
        assert len(tag) == 16
        assert isinstance(tag, bytes)

    def test_verify_valid(self, auth):
        msg = CANMessage(timestamp=0.0, can_id=0x100, dlc=8, data=b"\x01" * 8)
        tag = auth.sign(msg, counter=42)
        result = auth.verify(msg, tag, counter=42)
        assert result.status == AuthStatus.VALID

    def test_verify_tampered_payload(self, auth):
        msg = CANMessage(timestamp=0.0, can_id=0x100, dlc=8, data=b"\x01" * 8)
        tag = auth.sign(msg, counter=1)

        # Tamper the payload
        tampered = CANMessage(timestamp=0.0, can_id=0x100, dlc=8, data=b"\x02" * 8)
        result = auth.verify(tampered, tag, counter=1)
        assert result.status == AuthStatus.INVALID

    def test_verify_wrong_counter(self, auth):
        msg = CANMessage(timestamp=0.0, can_id=0x100, dlc=8, data=b"\x00" * 8)
        tag = auth.sign(msg, counter=1)
        result = auth.verify(msg, tag, counter=2)  # Wrong counter
        assert result.status == AuthStatus.INVALID

    def test_verify_wrong_key(self, key):
        auth1 = HMACAuthenticator(key, key_id="k1")
        auth2 = HMACAuthenticator(secrets.token_bytes(32), key_id="k2")

        msg = CANMessage(timestamp=0.0, can_id=0x100, dlc=8, data=b"\x00" * 8)
        tag = auth1.sign(msg, counter=1)
        result = auth2.verify(msg, tag, counter=1)
        assert result.status == AuthStatus.INVALID

    def test_short_key_rejected(self):
        with pytest.raises(ValueError, match="at least 16 bytes"):
            HMACAuthenticator(b"\x00" * 8)

    def test_deterministic_tags(self, auth):
        msg = CANMessage(timestamp=0.0, can_id=0x100, dlc=8, data=b"\x00" * 8)
        tag1 = auth.sign(msg, counter=1)
        tag2 = auth.sign(msg, counter=1)
        assert tag1 == tag2


# =============================================================================
# Key Management Tests
# =============================================================================

class TestKeyManager:
    def test_generate_key(self):
        km = KeyManager()
        info = km.generate_key("test_key")
        assert info.key_id == "test_key"
        assert km.has_key("test_key")

    def test_get_key(self):
        km = KeyManager(key_length=32)
        km.generate_key("k1")
        key = km.get_key("k1")
        assert len(key) == 32

    def test_missing_key_raises(self):
        km = KeyManager()
        from can_security.core.exceptions import KeyManagementError
        with pytest.raises(KeyManagementError):
            km.get_key("nonexistent")

    def test_rotate_key(self):
        km = KeyManager()
        info1 = km.generate_key("k1", version=1)
        info2 = km.rotate_key("k1")
        assert info2.version == 2

    def test_list_keys(self):
        km = KeyManager()
        km.generate_key("a")
        km.generate_key("b")
        keys = km.list_keys()
        assert len(keys) == 2


# =============================================================================
# Freshness Tests
# =============================================================================

class TestFreshnessManager:
    def test_first_message_fresh(self):
        fm = FreshnessManager(max_counter_jump=100)
        result = fm.check(0x100, counter=1)
        assert result.status == FreshnessStatus.FRESH

    def test_increment_fresh(self):
        fm = FreshnessManager()
        fm.check(0x100, counter=1)
        result = fm.check(0x100, counter=2)
        assert result.status == FreshnessStatus.FRESH

    def test_duplicate_is_replay(self):
        fm = FreshnessManager()
        fm.check(0x100, counter=5)
        result = fm.check(0x100, counter=5)
        assert result.status == FreshnessStatus.REPLAY

    def test_backwards_is_stale(self):
        fm = FreshnessManager()
        fm.check(0x100, counter=10)
        result = fm.check(0x100, counter=5)
        assert result.status == FreshnessStatus.STALE

    def test_large_jump_flagged(self):
        fm = FreshnessManager(max_counter_jump=10)
        fm.check(0x100, counter=1)
        result = fm.check(0x100, counter=100)
        assert result.status == FreshnessStatus.COUNTER_JUMP

    def test_per_id_isolation(self):
        fm = FreshnessManager()
        fm.check(0x100, counter=5)
        # Different CAN ID should have independent state
        result = fm.check(0x102, counter=1)
        assert result.status == FreshnessStatus.FRESH

    def test_reset(self):
        fm = FreshnessManager()
        fm.check(0x100, counter=5)
        fm.reset(0x100)
        # After reset, same counter should be fresh (first message)
        result = fm.check(0x100, counter=5)
        assert result.status == FreshnessStatus.FRESH


# =============================================================================
# Decision Engine Tests
# =============================================================================

class TestDecisionEngine:
    @pytest.fixture
    def engine(self):
        return SecurityDecisionEngine()

    def test_normal_message(self, engine):
        msg = CANMessage(timestamp=0.0, can_id=0x100, dlc=8, data=b"\x00" * 8)
        event = engine.evaluate(msg)
        assert event.severity == Severity.NORMAL
        assert event.status == MessageStatus.NORMAL

    def test_rule_evidence_raises_score(self, engine):
        msg = CANMessage(timestamp=0.0, can_id=0x100, dlc=8, data=b"\x00" * 8)
        from can_security.core.models import RuleEvidence
        evidence = [
            RuleEvidence(
                rule=RuleName.UNKNOWN_CAN_ID,
                can_id=0x100,
                severity=Severity.HIGH,
                description="test",
            )
        ]
        event = engine.evaluate(msg, rule_evidence=evidence)
        assert event.risk_score > 0.1, "Rule evidence should raise risk score"
        # A single rule at 30% weight may not change severity, but score should be nonzero

    def test_combined_evidence_raises_severity(self, engine):
        """Multiple evidence sources should push severity higher."""
        msg = CANMessage(timestamp=0.0, can_id=0x100, dlc=8, data=b"\x00" * 8)
        from can_security.core.models import RuleEvidence
        evidence = [
            RuleEvidence(
                rule=RuleName.UNKNOWN_CAN_ID,
                can_id=0x100, severity=Severity.HIGH, description="test",
            )
        ]
        ml = MLPrediction(
            attack_type=AttackType.INJECTION, confidence=0.9,
            anomaly_score=0.85, detector_name="test", inference_latency_ms=1.0,
        )
        event = engine.evaluate(msg, rule_evidence=evidence, ml_prediction=ml)
        assert event.severity != Severity.NORMAL
        assert event.risk_score > 0.4

    def test_auth_failure_critical(self, engine):
        msg = CANMessage(timestamp=0.0, can_id=0x100, dlc=8, data=b"\x00" * 8)
        auth = AuthenticationResult(
            status=AuthStatus.INVALID, can_id=0x100
        )
        event = engine.evaluate(msg, auth_result=auth)
        assert event.risk_score >= 0.85
        assert event.severity in (Severity.HIGH, Severity.CRITICAL)

    def test_replay_critical(self, engine):
        msg = CANMessage(timestamp=0.0, can_id=0x100, dlc=8, data=b"\x00" * 8)
        fresh = FreshnessResult(
            status=FreshnessStatus.REPLAY, can_id=0x100
        )
        event = engine.evaluate(msg, freshness_result=fresh)
        assert event.risk_score >= 0.85

    def test_alert_generation(self, engine):
        msg = CANMessage(timestamp=0.0, can_id=0x100, dlc=8, data=b"\x00" * 8)
        auth = AuthenticationResult(status=AuthStatus.INVALID, can_id=0x100)
        event = engine.evaluate(msg, auth_result=auth)
        alert = engine.create_alert(event)
        assert alert is not None
        assert alert.severity in (Severity.HIGH, Severity.CRITICAL)
        assert len(alert.description) > 0

    def test_no_alert_for_normal(self, engine):
        msg = CANMessage(timestamp=0.0, can_id=0x100, dlc=8, data=b"\x00" * 8)
        event = engine.evaluate(msg)
        alert = engine.create_alert(event)
        assert alert is None

    def test_description_is_explainable(self, engine):
        msg = CANMessage(timestamp=0.0, can_id=0x100, dlc=8, data=b"\x00" * 8)
        auth = AuthenticationResult(status=AuthStatus.INVALID, can_id=0x100)
        event = engine.evaluate(msg, auth_result=auth)
        assert "Auth: INVALID" in event.description
        assert "0x100" in event.description


# =============================================================================
# Attack Simulator Tests
# =============================================================================

class TestAttackSimulator:
    def test_flooding(self):
        sim = AttackSimulator(seed=42)
        sim.start_attack(AttackType.FLOODING, target_id=0x102, rate=10)
        msgs = sim.generate_attack_messages(1.0)
        assert len(msgs) == 10
        assert all(m.can_id == 0x102 for m in msgs)
        sim.stop_attack()

    def test_injection(self):
        sim = AttackSimulator(seed=42)
        sim.start_attack(AttackType.INJECTION, injected_id=0x7FF)
        msgs = sim.generate_attack_messages(1.0)
        assert len(msgs) == 1
        assert msgs[0].can_id == 0x7FF
        sim.stop_attack()

    def test_replay(self):
        sim = AttackSimulator(seed=42)
        sim.start_attack(AttackType.REPLAY, target_id=0x100, stale_counter=1)
        msgs = sim.generate_attack_messages(1.0)
        assert len(msgs) == 1
        assert msgs[0].sequence_counter == 1
        sim.stop_attack()

    def test_spoofing(self):
        sim = AttackSimulator(seed=42)
        sim.start_attack(AttackType.SPOOFING, target_id=0x102)
        msgs = sim.generate_attack_messages(1.0)
        assert len(msgs) == 1
        assert msgs[0].source_ecu == ECUType.INFOTAINMENT
        sim.stop_attack()

    def test_stop_returns_summary(self):
        sim = AttackSimulator(seed=42)
        sim.start_attack(AttackType.FLOODING, rate=5)
        sim.generate_attack_messages(1.0)
        summary = sim.stop_attack()
        assert summary["attack_type"] == "FLOODING"
        assert summary["messages_generated"] == 5
        assert summary["mode"] == "SIMULATION"

    def test_no_messages_when_stopped(self):
        sim = AttackSimulator(seed=42)
        msgs = sim.generate_attack_messages(1.0)
        assert msgs == []
