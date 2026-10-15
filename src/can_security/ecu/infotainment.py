"""
Infotainment ECU simulation.

Generates: media state, volume, climate temperature.
CAN IDs: 0x200 (INFOTAINMENT_STATUS), 0x201 (INFOTAINMENT_COMMAND)
"""

from __future__ import annotations

from typing import Any

from can_security.core.enums import ECUType
from can_security.ecu.base import BaseECU


class InfotainmentECU(BaseECU):
    """
    Simulates an infotainment ECU — low-priority vehicle signals.

    Generates periodic status updates for media and climate controls.
    """

    def __init__(self, can_id_definitions: dict[int, dict[str, Any]] | None = None):
        super().__init__(
            ecu_type=ECUType.INFOTAINMENT,
            can_ids=[0x200],  # 0x201 is event-driven, not periodic
            period_ms=200,
            can_id_definitions=can_id_definitions,
        )
        self._state = {
            "media_state": 1,  # 0=OFF, 1=RADIO, 2=USB, 3=BT
            "volume": 30,  # 0–100
            "climate_temp_set": 22,  # 16–30°C
        }

    def update_state(self, vehicle_state: dict[str, Any], dt: float) -> None:
        # Infotainment state is largely independent of driving state
        # Just maintain current values — changes would come from user input
        pass

    def _build_signals(self, can_id: int) -> dict[str, int | float]:
        if can_id == 0x200:
            return {
                "media_state": self._state["media_state"],
                "volume": self._state["volume"],
                "climate_temp_set": self._state["climate_temp_set"],
            }
        return {}
