"""
Engine ECU simulation.

Generates: RPM, engine temperature, engine state, accelerator position.
CAN IDs: 0x100 (ENGINE_STATUS), 0x104 (ACCELERATOR), 0x106 (TEMPERATURE)
"""

from __future__ import annotations

import math
from typing import Any

from can_security.core.enums import ECUType
from can_security.ecu.base import BaseECU


class EngineECU(BaseECU):
    """
    Simulates an engine ECU with realistic correlated signals.

    RPM correlates with speed and accelerator position.
    Temperature gradually rises from cold start and stabilizes.
    """

    def __init__(self, can_id_definitions: dict[int, dict[str, Any]] | None = None):
        super().__init__(
            ecu_type=ECUType.ENGINE,
            can_ids=[0x100, 0x104, 0x106],
            period_ms=10,
            can_id_definitions=can_id_definitions,
        )
        self._state = {
            "rpm": 800,  # Idle RPM
            "engine_temp": 20,  # Cold start temperature (°C)
            "engine_state": 2,  # RUNNING
            "pedal_position": 0,  # 0–100%
            "coolant_temp": 20,
            "oil_temp": 18,
            "target_rpm": 800,
        }

    def update_state(self, vehicle_state: dict[str, Any], dt: float) -> None:
        """Update engine state based on vehicle speed, gear, and pedal."""
        speed = vehicle_state.get("speed", 0)
        gear = vehicle_state.get("gear", 3)
        pedal = vehicle_state.get("pedal_position", 0)

        self._state["pedal_position"] = pedal

        # RPM = f(speed, gear, pedal) — simplified engine model
        if gear > 0:
            # Base RPM from speed and gear ratio
            gear_ratios = {1: 3.5, 2: 2.5, 3: 1.8, 4: 1.4, 5: 1.1, 6: 0.9}
            ratio = gear_ratios.get(gear, 1.5)
            speed_rpm = max(800, speed * ratio * 40)  # Linear approximation
            # Pedal adds RPM offset
            pedal_rpm = pedal * 20
            target = min(7000, speed_rpm + pedal_rpm)
        else:
            target = 800  # Idle

        self._state["target_rpm"] = target

        # Smooth RPM transition (engine inertia)
        current_rpm = self._state["rpm"]
        rpm_diff = target - current_rpm
        # Faster response when accelerating, slower when decelerating
        rate = 2000 * dt if rpm_diff > 0 else 1500 * dt
        self._state["rpm"] = current_rpm + max(-rate, min(rate, rpm_diff))
        self._state["rpm"] = max(0, min(8000, self._state["rpm"]))

        # Engine temperature — rises from cold start, stabilizes ~90°C
        target_temp = 90.0
        current_temp = self._state["engine_temp"]
        # Higher RPM = slightly more heat
        rpm_heat = self._state["rpm"] / 8000 * 10
        temp_target = target_temp + rpm_heat
        temp_rate = 2.0 * dt  # °C per second
        self._state["engine_temp"] = current_temp + (
            temp_rate if current_temp < temp_target else -temp_rate * 0.3
        )
        self._state["engine_temp"] = max(-40, min(150, self._state["engine_temp"]))

        # Coolant and oil follow engine temp with lag
        self._state["coolant_temp"] += (self._state["engine_temp"] - self._state["coolant_temp"]) * 0.5 * dt
        self._state["oil_temp"] += (self._state["engine_temp"] - 5 - self._state["oil_temp"]) * 0.3 * dt

    def _build_signals(self, can_id: int) -> dict[str, int | float]:
        if can_id == 0x100:
            return {
                "rpm": int(self._state["rpm"]),
                "engine_temp": int(self._state["engine_temp"]),
                "engine_state": self._state["engine_state"],
            }
        elif can_id == 0x104:
            return {
                "pedal_position": int(self._state["pedal_position"]),
            }
        elif can_id == 0x106:
            return {
                "coolant_temp": int(self._state["coolant_temp"]),
                "oil_temp": int(self._state["oil_temp"]),
            }
        return {}
