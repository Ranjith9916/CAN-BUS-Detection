"""
Steering ECU simulation.

Generates: steering angle, steering torque.
CAN ID: 0x103 (STEERING_STATUS)
"""

from __future__ import annotations

import math
from typing import Any

from can_security.core.enums import ECUType
from can_security.ecu.base import BaseECU


class SteeringECU(BaseECU):
    """
    Simulates a steering ECU with realistic behavior.

    Steering angle simulates gentle lane changes and turns.
    Torque correlates with angle and speed (higher speed = more torque).
    """

    def __init__(self, can_id_definitions: dict[int, dict[str, Any]] | None = None):
        super().__init__(
            ecu_type=ECUType.STEERING,
            can_ids=[0x103],
            period_ms=20,
            can_id_definitions=can_id_definitions,
        )
        self._state = {
            "steering_angle": 0,  # -540 to 540 degrees
            "steering_torque": 0,  # -100 to 100 Nm
        }
        self._time_accumulator = 0.0

    def update_state(self, vehicle_state: dict[str, Any], dt: float) -> None:
        speed = vehicle_state.get("speed", 0)
        self._time_accumulator += dt

        # Simulate gentle steering — slow sinusoidal pattern
        # Small corrections at highway speed, larger at low speed
        if speed > 5:
            # Highway: small ±5° corrections
            amplitude = 5 + (1.0 / max(1, speed / 30)) * 20
            frequency = 0.1  # Slow oscillation
            target_angle = amplitude * math.sin(
                2 * math.pi * frequency * self._time_accumulator
            )
        else:
            # Parking/stopped: potentially larger angles but infrequent
            target_angle = 0

        # Smooth angle transition
        current = self._state["steering_angle"]
        rate = 200 * dt  # degrees per second
        diff = target_angle - current
        self._state["steering_angle"] = current + max(-rate, min(rate, diff))
        self._state["steering_angle"] = max(-540, min(540, self._state["steering_angle"]))

        # Torque correlates with angle and inversely with speed
        # (power steering assists more at low speed)
        speed_factor = max(0.1, speed / 100)
        self._state["steering_torque"] = (
            self._state["steering_angle"] * 0.1 * speed_factor
        )
        self._state["steering_torque"] = max(
            -100, min(100, self._state["steering_torque"])
        )

    def _build_signals(self, can_id: int) -> dict[str, int | float]:
        if can_id == 0x103:
            return {
                "steering_angle": int(self._state["steering_angle"]),
                "steering_torque": int(self._state["steering_torque"]),
            }
        return {}
