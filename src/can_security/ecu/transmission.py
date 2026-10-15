"""
Transmission ECU simulation.

Generates: gear position, transmission state.
CAN ID: 0x105 (GEAR_STATUS)
"""

from __future__ import annotations

from typing import Any

from can_security.core.enums import ECUType
from can_security.ecu.base import BaseECU


class TransmissionECU(BaseECU):
    """
    Simulates a transmission ECU.

    Gear automatically shifts based on vehicle speed — simplified
    automatic transmission model with hysteresis to avoid hunting.
    """

    # Speed thresholds for upshift/downshift (km/h)
    # Hysteresis: upshift at higher speed, downshift at lower speed
    SHIFT_UP = {1: 15, 2: 30, 3: 50, 4: 70, 5: 90}
    SHIFT_DOWN = {2: 10, 3: 22, 4: 40, 5: 55, 6: 75}

    def __init__(self, can_id_definitions: dict[int, dict[str, Any]] | None = None):
        super().__init__(
            ecu_type=ECUType.TRANSMISSION,
            can_ids=[0x105],
            period_ms=50,
            can_id_definitions=can_id_definitions,
        )
        self._state = {
            "gear": 0,  # 0=P, 1–6=D1–D6
            "trans_state": 0,  # 0=PARK, 1=DRIVE, 2=ERROR
        }
        self._shift_cooldown = 0.0  # Prevent rapid shifting

    def update_state(self, vehicle_state: dict[str, Any], dt: float) -> None:
        speed = vehicle_state.get("speed", 0)
        engine_running = vehicle_state.get("engine_running", True)

        self._shift_cooldown = max(0, self._shift_cooldown - dt)

        if not engine_running:
            self._state["gear"] = 0
            self._state["trans_state"] = 0
            return

        # Transition from PARK to DRIVE when speed > 0
        if speed > 0 and self._state["trans_state"] == 0:
            self._state["trans_state"] = 1
            self._state["gear"] = 1

        # Auto-shift logic with cooldown
        if self._state["trans_state"] == 1 and self._shift_cooldown <= 0:
            current_gear = self._state["gear"]

            # Check upshift
            if current_gear < 6 and current_gear in self.SHIFT_UP:
                if speed > self.SHIFT_UP[current_gear]:
                    self._state["gear"] = current_gear + 1
                    self._shift_cooldown = 0.5  # 500ms cooldown

            # Check downshift
            if current_gear > 1 and current_gear in self.SHIFT_DOWN:
                if speed < self.SHIFT_DOWN[current_gear]:
                    self._state["gear"] = current_gear - 1
                    self._shift_cooldown = 0.5

        # Return to PARK when stopped
        if speed == 0 and self._state["gear"] > 0:
            # Only shift to park after being stopped for a while
            pass  # Keep in gear for realism (driver hasn't shifted to P)

    def _build_signals(self, can_id: int) -> dict[str, int | float]:
        if can_id == 0x105:
            return {
                "gear": self._state["gear"],
                "trans_state": self._state["trans_state"],
            }
        return {}
