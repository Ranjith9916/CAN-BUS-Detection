"""
Brake ECU simulation.

Generates: brake pressure, ABS state, average wheel speed.
CAN ID: 0x102 (BRAKE_STATUS)
"""

from __future__ import annotations

from typing import Any

from can_security.core.enums import ECUType
from can_security.ecu.base import BaseECU


class BrakeECU(BaseECU):
    """
    Simulates a brake ECU with realistic behavior.

    Brake pressure correlates with deceleration.
    ABS activates under heavy braking at speed.
    Wheel speed tracks vehicle speed with slight variation during braking.
    """

    def __init__(self, can_id_definitions: dict[int, dict[str, Any]] | None = None):
        super().__init__(
            ecu_type=ECUType.BRAKE,
            can_ids=[0x102],
            period_ms=10,
            can_id_definitions=can_id_definitions,
        )
        self._state = {
            "brake_pressure": 0,  # 0–200 bar
            "abs_active": 0,  # 0 or 1
            "wheel_speed_avg": 0,  # km/h
        }

    def update_state(self, vehicle_state: dict[str, Any], dt: float) -> None:
        speed = vehicle_state.get("speed", 0)
        brake_input = vehicle_state.get("brake_input", 0)  # 0–100%

        # Brake pressure proportional to input
        target_pressure = brake_input * 2.0  # Max ~200 bar at full brake
        current = self._state["brake_pressure"]
        # Hydraulic response — fast apply, slightly slower release
        rate = 500 * dt if brake_input > 0 else 300 * dt
        diff = target_pressure - current
        self._state["brake_pressure"] = current + max(-rate, min(rate, diff))
        self._state["brake_pressure"] = max(0, min(200, self._state["brake_pressure"]))

        # ABS activates under heavy braking at speed > 10 km/h
        if self._state["brake_pressure"] > 80 and speed > 10:
            self._state["abs_active"] = 1
        else:
            self._state["abs_active"] = 0

        # Wheel speed tracks vehicle speed (slight lag during braking)
        if self._state["brake_pressure"] > 0:
            # Under braking, wheel speed slightly less than vehicle speed
            wheel_target = speed * 0.95
        else:
            wheel_target = speed
        ws = self._state["wheel_speed_avg"]
        self._state["wheel_speed_avg"] = ws + (wheel_target - ws) * min(1.0, 5.0 * dt)
        self._state["wheel_speed_avg"] = max(0, min(300, self._state["wheel_speed_avg"]))

    def _build_signals(self, can_id: int) -> dict[str, int | float]:
        if can_id == 0x102:
            return {
                "brake_pressure": int(self._state["brake_pressure"]),
                "abs_active": self._state["abs_active"],
                "wheel_speed_avg": int(self._state["wheel_speed_avg"]),
            }
        return {}
