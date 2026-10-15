"""
Vehicle CAN bus simulator.

Orchestrates all virtual ECUs with a shared vehicle state model,
creating realistic correlated CAN traffic. Supports configurable
driving scenarios (idle, city, highway, etc.).
"""

from __future__ import annotations

import logging
import math
import random
import time
from typing import Any

from can_security.can.message import CANMessageFactory
from can_security.core.config import AppConfig
from can_security.core.enums import ECUType
from can_security.core.models import CANMessage
from can_security.ecu.base import BaseECU
from can_security.ecu.brake import BrakeECU
from can_security.ecu.engine import EngineECU
from can_security.ecu.infotainment import InfotainmentECU
from can_security.ecu.steering import SteeringECU
from can_security.ecu.transmission import TransmissionECU

logger = logging.getLogger(__name__)


class InstrumentClusterECU(BaseECU):
    """
    Instrument cluster ECU — reads vehicle speed and status from shared state.

    CAN IDs: 0x101 (VEHICLE_SPEED), 0x107 (VEHICLE_STATUS)
    """

    def __init__(self, can_id_definitions: dict[int, dict[str, Any]] | None = None):
        super().__init__(
            ecu_type=ECUType.INSTRUMENT_CLUSTER,
            can_ids=[0x101, 0x107],
            period_ms=100,
            can_id_definitions=can_id_definitions,
        )
        self._state = {
            "speed": 0,
            "odometer": 0,
            "warning_flags": 0,
            "fuel_level": 75,
        }

    def update_state(self, vehicle_state: dict[str, Any], dt: float) -> None:
        self._state["speed"] = vehicle_state.get("speed", 0)
        # Accumulate odometer
        self._state["odometer"] += self._state["speed"] / 3600 * dt  # km
        # Slowly decrease fuel
        self._state["fuel_level"] = max(
            0, self._state["fuel_level"] - 0.001 * dt
        )

    def _build_signals(self, can_id: int) -> dict[str, int | float]:
        if can_id == 0x101:
            return {
                "speed": int(self._state["speed"]),
                "odometer": int(self._state["odometer"]),
            }
        elif can_id == 0x107:
            return {
                "warning_flags": self._state["warning_flags"],
                "fuel_level": int(self._state["fuel_level"]),
            }
        return {}


class VehicleSimulator:
    """
    Orchestrates all virtual ECUs with a shared physics model.

    The shared vehicle state ensures signal correlation:
    - Speed depends on throttle and braking
    - RPM correlates with speed and gear
    - Gear shifts based on speed
    - Brake affects deceleration
    """

    def __init__(self, config: AppConfig):
        self.config = config
        self._rng = random.Random(config.simulation.seed)
        self._running = False

        # Shared vehicle state — the single source of truth
        self._vehicle_state: dict[str, Any] = {
            "speed": 0.0,  # km/h
            "pedal_position": 0.0,  # 0–100%
            "brake_input": 0.0,  # 0–100%
            "gear": 0,
            "engine_running": True,
            "time": 0.0,
        }

        # Driving scenario state machine
        self._scenario_phase = "idle"
        self._phase_timer = 0.0
        self._phase_duration = 0.0

        # Initialize all ECUs
        can_defs = config.can_id_definitions
        self._ecus: list[BaseECU] = [
            EngineECU(can_defs),
            BrakeECU(can_defs),
            SteeringECU(can_defs),
            TransmissionECU(can_defs),
            InstrumentClusterECU(can_defs),
            InfotainmentECU(can_defs),
        ]

        self._total_messages = 0

    def start(self) -> None:
        """Start the vehicle simulation."""
        self._running = True
        self._vehicle_state["engine_running"] = True
        self._vehicle_state["time"] = 0.0
        self._set_phase("idle", duration=2.0)
        logger.info(
            "Vehicle simulator started",
            extra={"scenario": self.config.simulation.scenario},
        )

    def stop(self) -> None:
        """Stop the vehicle simulation."""
        self._running = False
        logger.info(
            "Vehicle simulator stopped",
            extra={"total_messages": self._total_messages},
        )

    def tick(self, current_time: float, dt: float) -> list[CANMessage]:
        """
        Advance the simulation by one time step.

        Updates driving scenario, vehicle physics, and all ECUs.
        Returns all CAN messages generated in this tick.
        """
        if not self._running:
            return []

        self._vehicle_state["time"] = current_time

        # Update driving scenario (controls pedal/brake inputs)
        self._update_driving_scenario(dt)

        # Update vehicle physics (speed based on pedal/brake)
        self._update_physics(dt)

        # Collect messages from all ECUs
        messages: list[CANMessage] = []
        for ecu in self._ecus:
            ecu_msgs = ecu.generate_messages(
                current_time, self._vehicle_state, dt
            )
            messages.extend(ecu_msgs)

        self._total_messages += len(messages)
        return messages

    def _update_driving_scenario(self, dt: float) -> None:
        """
        State machine for driving scenarios.

        Cycles through phases: idle → accelerate → cruise → brake → idle
        creating realistic pedal/brake input patterns.
        """
        self._phase_timer += dt

        if self._phase_timer >= self._phase_duration:
            # Transition to next phase
            transitions = {
                "idle": ("accelerate", self._rng.uniform(3, 8)),
                "accelerate": ("cruise", self._rng.uniform(5, 15)),
                "cruise": ("decelerate", self._rng.uniform(2, 5)),
                "decelerate": ("idle", self._rng.uniform(1, 4)),
            }
            next_phase, duration = transitions.get(
                self._scenario_phase, ("idle", 2.0)
            )
            self._set_phase(next_phase, duration)

        # Apply inputs based on current phase
        if self._scenario_phase == "idle":
            self._vehicle_state["pedal_position"] = 0
            self._vehicle_state["brake_input"] = 0
        elif self._scenario_phase == "accelerate":
            # Gradually increase throttle
            progress = self._phase_timer / self._phase_duration
            self._vehicle_state["pedal_position"] = min(
                80, 20 + progress * 60
            )
            self._vehicle_state["brake_input"] = 0
        elif self._scenario_phase == "cruise":
            # Maintain speed with gentle throttle
            speed = self._vehicle_state["speed"]
            target = self._rng.uniform(60, 100)
            if speed < target:
                self._vehicle_state["pedal_position"] = 25
            else:
                self._vehicle_state["pedal_position"] = 10
            self._vehicle_state["brake_input"] = 0
        elif self._scenario_phase == "decelerate":
            self._vehicle_state["pedal_position"] = 0
            progress = self._phase_timer / self._phase_duration
            self._vehicle_state["brake_input"] = min(70, 20 + progress * 50)

    def _set_phase(self, phase: str, duration: float) -> None:
        """Transition to a new driving phase."""
        self._scenario_phase = phase
        self._phase_timer = 0.0
        self._phase_duration = duration
        logger.debug(
            "Driving phase transition",
            extra={"phase": phase, "duration_s": round(duration, 2)},
        )

    def _update_physics(self, dt: float) -> None:
        """
        Simplified vehicle physics model.

        Converts pedal position to acceleration and brake input to deceleration,
        then updates vehicle speed.
        """
        speed = self._vehicle_state["speed"]
        pedal = self._vehicle_state["pedal_position"]
        brake = self._vehicle_state["brake_input"]

        # Acceleration from throttle (simplified: pedal% → m/s²)
        acceleration = pedal * 0.05  # Max ~4 m/s² at full throttle

        # Deceleration from braking
        deceleration = brake * 0.08  # Max ~8 m/s² at full brake

        # Air resistance (simplified quadratic drag)
        drag = speed * speed * 0.0001

        # Net acceleration in km/h per second
        net_accel = (acceleration - deceleration - drag) * 3.6  # m/s² to km/h/s

        speed += net_accel * dt
        speed = max(0, min(200, speed))

        self._vehicle_state["speed"] = speed

        # Update gear in shared state for other ECUs
        for ecu in self._ecus:
            if ecu.ecu_type == ECUType.TRANSMISSION:
                self._vehicle_state["gear"] = ecu.state.get("gear", 0)
                break

    @property
    def vehicle_state(self) -> dict[str, Any]:
        """Read-only access to current vehicle state."""
        return dict(self._vehicle_state)

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def total_messages(self) -> int:
        return self._total_messages
