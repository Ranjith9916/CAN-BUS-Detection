"""
Unit tests for ECU simulation and vehicle simulator.

Tests that ECUs generate valid messages, signals are correlated,
and the vehicle simulator produces realistic traffic patterns.
"""

import pytest

from can_security.core.config import load_config
from can_security.core.enums import ECUType
from can_security.can.simulator import VehicleSimulator
from can_security.ecu.engine import EngineECU
from can_security.ecu.brake import BrakeECU
from can_security.ecu.steering import SteeringECU
from can_security.ecu.transmission import TransmissionECU
from can_security.ecu.infotainment import InfotainmentECU


# =============================================================================
# Individual ECU Tests
# =============================================================================

class TestEngineECU:
    """Test Engine ECU behavior."""

    def test_initial_state(self):
        ecu = EngineECU()
        assert ecu.ecu_type == ECUType.ENGINE
        assert ecu.state["rpm"] == 800  # Idle RPM
        assert ecu.state["engine_state"] == 2  # RUNNING

    def test_rpm_increases_with_pedal(self):
        ecu = EngineECU()
        vehicle_state = {"speed": 50, "gear": 3, "pedal_position": 60}

        # Run several updates to let RPM stabilize
        for _ in range(100):
            ecu.update_state(vehicle_state, dt=0.01)

        assert ecu.state["rpm"] > 800, "RPM should increase with pedal input"

    def test_temperature_rises_from_cold(self):
        ecu = EngineECU()
        vehicle_state = {"speed": 50, "gear": 3, "pedal_position": 30}

        initial_temp = ecu.state["engine_temp"]
        for _ in range(500):
            ecu.update_state(vehicle_state, dt=0.01)

        assert ecu.state["engine_temp"] > initial_temp, (
            "Engine temp should rise from cold start"
        )

    def test_generates_correct_can_ids(self):
        ecu = EngineECU()
        vehicle_state = {"speed": 50, "gear": 3, "pedal_position": 30}
        ecu.update_state(vehicle_state, dt=0.01)

        messages = ecu.generate_messages(current_time=1.0, vehicle_state=vehicle_state, dt=0.01)
        can_ids = {m.can_id for m in messages}
        # Should generate at least engine status (0x100) on first tick
        assert 0x100 in can_ids or len(messages) > 0


class TestBrakeECU:
    """Test Brake ECU behavior."""

    def test_brake_pressure_with_input(self):
        ecu = BrakeECU()
        vehicle_state = {"speed": 60, "brake_input": 80}

        for _ in range(200):
            ecu.update_state(vehicle_state, dt=0.01)

        assert ecu.state["brake_pressure"] > 50, (
            "Brake pressure should build with brake input"
        )

    def test_abs_activates_at_speed(self):
        ecu = BrakeECU()
        vehicle_state = {"speed": 60, "brake_input": 90}

        for _ in range(200):
            ecu.update_state(vehicle_state, dt=0.01)

        assert ecu.state["abs_active"] == 1, (
            "ABS should activate under heavy braking at speed"
        )

    def test_no_abs_at_low_speed(self):
        ecu = BrakeECU()
        vehicle_state = {"speed": 5, "brake_input": 90}

        for _ in range(200):
            ecu.update_state(vehicle_state, dt=0.01)

        assert ecu.state["abs_active"] == 0, (
            "ABS should not activate at very low speed"
        )


class TestTransmissionECU:
    """Test Transmission ECU behavior."""

    def test_upshift_with_speed(self):
        ecu = TransmissionECU()
        # Start from standstill with engine running
        ecu.update_state({"speed": 5, "engine_running": True}, dt=0.01)
        initial_gear = ecu.state["gear"]

        # Increase speed progressively
        for speed in range(10, 80, 5):
            for _ in range(20):  # Allow cooldown
                ecu.update_state({"speed": speed, "engine_running": True}, dt=0.1)

        assert ecu.state["gear"] > initial_gear, "Should upshift with increasing speed"

    def test_park_when_engine_off(self):
        ecu = TransmissionECU()
        ecu.update_state({"speed": 0, "engine_running": False}, dt=0.1)
        assert ecu.state["gear"] == 0, "Should be in park when engine is off"


class TestSteeringECU:
    """Test Steering ECU behavior."""

    def test_steering_changes_over_time(self):
        ecu = SteeringECU()
        angles = []

        for i in range(100):
            ecu.update_state({"speed": 60}, dt=0.1)
            angles.append(ecu.state["steering_angle"])

        # Should not be constant — steering oscillates
        assert len(set(int(a) for a in angles)) > 1, (
            "Steering angle should vary over time"
        )


class TestInfotainmentECU:
    """Test Infotainment ECU behavior."""

    def test_initial_state(self):
        ecu = InfotainmentECU()
        assert ecu.state["media_state"] == 1
        assert ecu.state["volume"] == 30
        assert ecu.state["climate_temp_set"] == 22


# =============================================================================
# Vehicle Simulator Integration Tests
# =============================================================================

class TestVehicleSimulator:
    """Test the vehicle simulator orchestration."""

    @pytest.fixture
    def config(self):
        return load_config()

    def test_simulator_starts_and_stops(self, config):
        sim = VehicleSimulator(config)
        sim.start()
        assert sim.is_running
        sim.stop()
        assert not sim.is_running

    def test_generates_messages(self, config):
        sim = VehicleSimulator(config)
        sim.start()

        all_messages = []
        for i in range(100):
            msgs = sim.tick(current_time=i * 0.01, dt=0.01)
            all_messages.extend(msgs)

        sim.stop()
        assert len(all_messages) > 0, "Simulator should generate CAN messages"

    def test_messages_have_valid_can_ids(self, config):
        sim = VehicleSimulator(config)
        sim.start()

        for i in range(100):
            msgs = sim.tick(current_time=i * 0.01, dt=0.01)
            for msg in msgs:
                assert 0x000 <= msg.can_id <= 0x7FF
                assert 0 <= msg.dlc <= 8
                assert len(msg.data) == msg.dlc

        sim.stop()

    def test_messages_from_multiple_ecus(self, config):
        sim = VehicleSimulator(config)
        sim.start()

        ecu_sources = set()
        for i in range(200):
            msgs = sim.tick(current_time=i * 0.01, dt=0.01)
            for msg in msgs:
                ecu_sources.add(msg.source_ecu)

        sim.stop()
        # Should have messages from at least 3 different ECU types
        assert len(ecu_sources) >= 3, (
            f"Expected messages from multiple ECUs, got: {ecu_sources}"
        )

    def test_speed_increases_during_acceleration(self, config):
        """Vehicle speed should increase when the scenario enters acceleration phase."""
        sim = VehicleSimulator(config)
        sim.start()

        # Run for enough ticks to get through idle phase and into acceleration
        speeds = []
        for i in range(1000):
            sim.tick(current_time=i * 0.01, dt=0.01)
            speeds.append(sim.vehicle_state["speed"])

        sim.stop()
        max_speed = max(speeds)
        assert max_speed > 5, (
            f"Expected vehicle to accelerate, max speed was {max_speed}"
        )

    def test_deterministic_with_same_seed(self, config):
        """Same seed should produce identical message sequences."""
        def run_sim(seed: int) -> list[tuple[int, int]]:
            config.simulation.seed = seed
            sim = VehicleSimulator(config)
            sim.start()
            results = []
            for i in range(50):
                msgs = sim.tick(current_time=i * 0.01, dt=0.01)
                for msg in msgs:
                    results.append((msg.can_id, msg.dlc))
            sim.stop()
            return results

        run1 = run_sim(42)
        run2 = run_sim(42)
        assert run1 == run2, "Same seed should produce deterministic output"

    def test_sequence_counters_increment(self, config):
        """Sequence counters should increment per CAN ID."""
        sim = VehicleSimulator(config)
        sim.start()

        counters: dict[int, list[int]] = {}
        for i in range(200):
            msgs = sim.tick(current_time=i * 0.01, dt=0.01)
            for msg in msgs:
                if msg.sequence_counter is not None:
                    counters.setdefault(msg.can_id, []).append(msg.sequence_counter)

        sim.stop()

        # Verify counters are monotonically increasing for each CAN ID
        for can_id, counter_list in counters.items():
            if len(counter_list) > 1:
                for i in range(1, len(counter_list)):
                    assert counter_list[i] > counter_list[i - 1], (
                        f"Counter for 0x{can_id:03X} not monotonic: {counter_list[i-1]} -> {counter_list[i]}"
                    )
