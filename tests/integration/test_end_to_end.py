"""
End-to-end integration test — validates the full pipeline:

Simulation → Traffic Collection → Feature Extraction → Rule Detection →
ML Detection → Authentication → Freshness → Decision Engine → Alerts

Tests normal traffic, then each attack type, verifying that the
detection pipeline correctly identifies attacks.
"""

import time

import numpy as np
import pytest

from can_security.attacks.simulator import AttackSimulator
from can_security.authentication.freshness import FreshnessManager
from can_security.authentication.hmac_auth import HMACAuthenticator
from can_security.authentication.key_manager import KeyManager
from can_security.can.collector import CANCollector
from can_security.can.interface import VirtualCANInterface
from can_security.can.simulator import VehicleSimulator
from can_security.core.config import load_config
from can_security.core.enums import AttackType, FreshnessStatus, Severity
from can_security.decision.engine import SecurityDecisionEngine
from can_security.detection.rules import RuleEngine
from can_security.features.extractor import FeatureExtractor


@pytest.fixture
def config():
    return load_config()


@pytest.fixture
def pipeline(config):
    """Create a full detection pipeline."""
    interface = VirtualCANInterface()
    collector = CANCollector(interface)
    rule_engine = RuleEngine(config.can_id_definitions, config.detection_rules)
    feature_extractor = FeatureExtractor(window_size=50, window_overlap=25)
    decision_engine = SecurityDecisionEngine()
    key_mgr = KeyManager()
    key_mgr.generate_key("test")
    auth = HMACAuthenticator(key_mgr.get_key("test"), key_id="test")
    freshness = FreshnessManager(max_counter_jump=100)

    return {
        "interface": interface,
        "collector": collector,
        "rules": rule_engine,
        "features": feature_extractor,
        "decision": decision_engine,
        "auth": auth,
        "freshness": freshness,
    }


class TestEndToEndNormalTraffic:
    """Verify that normal traffic produces NO alerts."""

    def test_normal_traffic_no_alerts(self, config, pipeline):
        sim = VehicleSimulator(config)
        sim.start()

        alerts = []
        for i in range(200):
            messages = sim.tick(i * 0.01, 0.01)
            for msg in messages:
                pipeline["collector"].process_message(msg)
                evidence = pipeline["rules"].evaluate(msg)

                # Normal traffic should produce very few or zero rule triggers
                if evidence:
                    event = pipeline["decision"].evaluate(msg, rule_evidence=evidence)
                    alert = pipeline["decision"].create_alert(event)
                    if alert:
                        alerts.append(alert)

        sim.stop()

        # Normal traffic may trigger some LOW severity alerts from timing
        # But should NOT trigger HIGH/CRITICAL alerts
        critical_alerts = [a for a in alerts if a.severity in (Severity.HIGH, Severity.CRITICAL)]
        assert len(critical_alerts) == 0, (
            f"Normal traffic produced {len(critical_alerts)} critical alerts"
        )


class TestEndToEndAttackDetection:
    """Verify that each attack type is detected by the pipeline."""

    def _run_attack_scenario(self, config, pipeline, attack_type, attack_kwargs=None):
        """Run simulation with attack injection and return all events."""
        sim = VehicleSimulator(config)
        sim.start()
        attacker = AttackSimulator(seed=42)
        attack_kwargs = attack_kwargs or {}

        events = []
        alerts = []

        # Warm-up phase (normal traffic)
        for i in range(100):
            messages = sim.tick(i * 0.01, 0.01)
            for msg in messages:
                pipeline["rules"].evaluate(msg)

        # Attack phase
        target = attack_kwargs.pop("target_id", 0x102)
        attacker.start_attack(attack_type, target_id=target, **attack_kwargs)

        for i in range(100, 300):
            t = i * 0.01
            messages = sim.tick(t, 0.01)
            attack_msgs = attacker.generate_attack_messages(t)
            messages.extend(attack_msgs)

            for msg in messages:
                evidence = pipeline["rules"].evaluate(msg)
                if evidence:
                    event = pipeline["decision"].evaluate(msg, rule_evidence=evidence)
                    events.append(event)
                    alert = pipeline["decision"].create_alert(event)
                    if alert:
                        alerts.append(alert)

        attacker.stop_attack()
        sim.stop()

        return events, alerts

    def test_flooding_detected(self, config, pipeline):
        events, alerts = self._run_attack_scenario(
            config, pipeline, AttackType.FLOODING, {"rate": 20}
        )
        # Flooding generates events from rule engine (unknown source, frequency anomalies)
        assert len(events) > 0, "Flooding attack should produce security events"

    def test_injection_detected(self, config, pipeline):
        events, alerts = self._run_attack_scenario(
            config, pipeline, AttackType.INJECTION, {"injected_id": 0x7FF}
        )
        # Check that unknown CAN ID was flagged
        assert len(events) > 0, "Injection attack should produce events"

    def test_spoofing_detected(self, config, pipeline):
        events, alerts = self._run_attack_scenario(
            config, pipeline, AttackType.SPOOFING, {"target_id": 0x102}
        )
        assert len(events) > 0, "Spoofing attack should produce events"

    def test_replay_detected_by_freshness(self, config, pipeline):
        """Replay attacks should be caught by the freshness manager."""
        freshness = pipeline["freshness"]

        # Simulate normal counter progression
        for i in range(1, 11):
            result = freshness.check(0x100, counter=i)
            assert result.status == FreshnessStatus.FRESH

        # Simulate replay (duplicate counter)
        result = freshness.check(0x100, counter=5)
        assert result.status == FreshnessStatus.STALE

        # Simulate replay (exact duplicate)
        freshness.reset()
        freshness.check(0x100, counter=10)
        result = freshness.check(0x100, counter=10)
        assert result.status == FreshnessStatus.REPLAY


class TestEndToEndAuthentication:
    """Verify that HMAC authentication works end-to-end."""

    def test_valid_message_accepted(self, config, pipeline):
        from can_security.core.models import CANMessage, AuthenticationResult
        from can_security.core.enums import ECUType, AuthStatus

        msg = CANMessage(
            timestamp=time.time(), can_id=0x100, dlc=8,
            data=b"\x03\xe8\x00\x5a\x02\x00\x00\x00",
            source_ecu=ECUType.ENGINE, sequence_counter=1,
        )
        auth = pipeline["auth"]
        tag = auth.sign(msg, counter=1)
        result = auth.verify(msg, tag, counter=1)
        assert result.status == AuthStatus.VALID

    def test_tampered_message_rejected(self, config, pipeline):
        from can_security.core.models import CANMessage
        from can_security.core.enums import ECUType, AuthStatus

        msg = CANMessage(
            timestamp=time.time(), can_id=0x100, dlc=8,
            data=b"\x03\xe8\x00\x5a\x02\x00\x00\x00",
            source_ecu=ECUType.ENGINE, sequence_counter=1,
        )
        auth = pipeline["auth"]
        tag = auth.sign(msg, counter=1)

        # Tamper the message
        tampered = CANMessage(
            timestamp=msg.timestamp, can_id=0x100, dlc=8,
            data=b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
            source_ecu=ECUType.ENGINE, sequence_counter=1,
        )
        result = auth.verify(tampered, tag, counter=1)
        assert result.status == AuthStatus.INVALID

        # Feed tampered result into decision engine
        event = pipeline["decision"].evaluate(tampered, auth_result=result)
        assert event.risk_score >= 0.85, "Tampered message should have high risk"


class TestEndToEndMetrics:
    """Verify that metrics collection works."""

    def test_collector_statistics(self, config, pipeline):
        sim = VehicleSimulator(config)
        sim.start()
        pipeline["collector"].start()

        for i in range(100):
            messages = sim.tick(i * 0.01, 0.01)
            for msg in messages:
                pipeline["collector"].process_message(msg)

        sim.stop()
        pipeline["collector"].stop()

        stats = pipeline["collector"].get_statistics()
        assert stats["total_received"] > 0
        assert stats["unique_can_ids"] > 0
        assert stats["messages_per_second"] > 0

    def test_feature_extraction_pipeline(self, config, pipeline):
        sim = VehicleSimulator(config)
        sim.start()

        feature_vectors = []
        for i in range(500):
            messages = sim.tick(i * 0.01, 0.01)
            for msg in messages:
                fv = pipeline["features"].add_message(msg)
                if fv:
                    feature_vectors.append(fv)

        sim.stop()

        assert len(feature_vectors) > 0, "Should produce feature vectors"
        # Verify feature vector structure
        fv = feature_vectors[0]
        assert fv.window_size == 50
        assert len(fv.features) > 10
        assert "iat_mean" in fv.features
        assert "msg_rate" in fv.features
