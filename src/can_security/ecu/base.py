"""
Base ECU class for the vehicle simulation.

Defines the abstract interface all virtual ECUs implement:
- State management
- Periodic message generation
- Configurable timing
- Sequence counter tracking
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

from can_security.can.message import CANMessageFactory
from can_security.core.enums import ECUType
from can_security.core.models import CANMessage


class BaseECU(ABC):
    """
    Abstract base class for simulated vehicle ECUs.

    Each ECU maintains internal state, generates periodic CAN messages,
    and tracks per-ID sequence counters for freshness.
    """

    def __init__(
        self,
        ecu_type: ECUType,
        can_ids: list[int],
        period_ms: int = 10,
        can_id_definitions: dict[int, dict[str, Any]] | None = None,
    ):
        self.ecu_type = ecu_type
        self.can_ids = can_ids
        self.period_ms = period_ms
        self.period_seconds = period_ms / 1000.0
        self.can_id_definitions = can_id_definitions or {}

        # Per-CAN-ID sequence counters
        self._counters: dict[int, int] = {cid: 0 for cid in can_ids}

        # Last send time per CAN ID (for respecting configured periods)
        self._last_send: dict[int, float] = {cid: 0.0 for cid in can_ids}

        # Internal ECU state — subclasses populate
        self._state: dict[str, Any] = {}

    @abstractmethod
    def update_state(self, vehicle_state: dict[str, Any], dt: float) -> None:
        """
        Update ECU internal state based on shared vehicle state.

        Args:
            vehicle_state: Shared vehicle state dict (speed, rpm, etc.)
            dt: Time delta since last update in seconds.
        """
        ...

    @abstractmethod
    def _build_signals(self, can_id: int) -> dict[str, int | float]:
        """
        Build signal values for a specific CAN ID from internal state.

        Returns a dict of signal_name -> value.
        """
        ...

    def generate_messages(
        self,
        current_time: float,
        vehicle_state: dict[str, Any],
        dt: float,
    ) -> list[CANMessage]:
        """
        Generate CAN messages that are due based on timing.

        Respects per-CAN-ID period configuration. Updates state first,
        then generates messages for any CAN ID whose period has elapsed.
        """
        self.update_state(vehicle_state, dt)

        messages = []
        for can_id in self.can_ids:
            # Check per-ID period from config, falling back to ECU default
            id_def = self.can_id_definitions.get(can_id, {})
            period_s = id_def.get("period_ms", self.period_ms) / 1000.0

            elapsed = current_time - self._last_send[can_id]
            if elapsed >= period_s:
                signals = self._build_signals(can_id)
                sig_defs = id_def.get("signals", [])

                counter = self._next_counter(can_id)

                msg = CANMessageFactory.create_from_signals(
                    can_id=can_id,
                    signals=signals,
                    signal_defs=sig_defs,
                    source_ecu=self.ecu_type,
                    timestamp=current_time,
                    sequence_counter=counter,
                )
                messages.append(msg)
                self._last_send[can_id] = current_time

        return messages

    def _next_counter(self, can_id: int) -> int:
        """Increment and return the sequence counter for a CAN ID."""
        self._counters[can_id] = (self._counters[can_id] + 1) % (2**32)
        return self._counters[can_id]

    @property
    def state(self) -> dict[str, Any]:
        """Read-only access to internal state for debugging/testing."""
        return dict(self._state)
