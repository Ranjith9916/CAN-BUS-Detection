"""
Attack simulation module.

Generates controlled attack traffic for testing the defensive framework.
ALL attacks are SIMULATION-ONLY and must NEVER target real vehicles.
"""

from __future__ import annotations

import logging
import random
import time
from typing import Any

from can_security.can.message import CANMessageFactory
from can_security.core.enums import AttackType, ECUType
from can_security.core.models import CANMessage

logger = logging.getLogger(__name__)


class AttackSimulator:
    """
    Orchestrates simulated attacks on the virtual CAN bus.

    WARNING: SIMULATION MODE ONLY.
    Never connect to real vehicle systems.
    """

    def __init__(self, seed: int = 42):
        self._rng = random.Random(seed)
        self._running = False
        self._attack_type: AttackType = AttackType.NONE
        self._target_id: int = 0x102
        self._start_time: float = 0.0
        self._messages_generated: int = 0

    def start_attack(
        self,
        attack_type: AttackType,
        target_id: int = 0x102,
        **kwargs: Any,
    ) -> None:
        """Start a simulated attack."""
        self._running = True
        self._attack_type = attack_type
        self._target_id = target_id
        self._start_time = time.time()
        self._messages_generated = 0
        self._kwargs = kwargs
        logger.warning(
            "[SIMULATION] Attack started",
            extra={
                "attack_type": attack_type.value,
                "target_id": f"0x{target_id:03X}",
                "mode": "SIMULATION",
            },
        )

    def stop_attack(self) -> dict[str, Any]:
        """Stop the current attack and return summary."""
        self._running = False
        elapsed = time.time() - self._start_time
        summary = {
            "attack_type": self._attack_type.value,
            "target_id": f"0x{self._target_id:03X}",
            "duration_seconds": round(elapsed, 2),
            "messages_generated": self._messages_generated,
            "mode": "SIMULATION",
        }
        logger.warning("[SIMULATION] Attack stopped", extra=summary)
        self._attack_type = AttackType.NONE
        return summary

    def generate_attack_messages(
        self, current_time: float
    ) -> list[CANMessage]:
        """Generate attack messages for the current tick."""
        if not self._running:
            return []

        messages: list[CANMessage] = []

        if self._attack_type == AttackType.FLOODING:
            messages = self._gen_flooding(current_time)
        elif self._attack_type == AttackType.INJECTION:
            messages = self._gen_injection(current_time)
        elif self._attack_type == AttackType.REPLAY:
            messages = self._gen_replay(current_time)
        elif self._attack_type == AttackType.SPOOFING:
            messages = self._gen_spoofing(current_time)
        elif self._attack_type == AttackType.ABNORMAL_FREQUENCY:
            messages = self._gen_abnormal_frequency(current_time)

        self._messages_generated += len(messages)
        return messages

    def _gen_flooding(self, t: float) -> list[CANMessage]:
        """Generate a burst of messages to flood the bus."""
        rate = self._kwargs.get("rate", 20)
        messages = []
        for i in range(rate):
            data = bytes(self._rng.randint(0, 255) for _ in range(8))
            msg = CANMessageFactory.create(
                can_id=self._target_id,
                data=data,
                source_ecu=ECUType.UNKNOWN,
                timestamp=t + i * 0.0001,
            )
            messages.append(msg)
        return messages

    def _gen_injection(self, t: float) -> list[CANMessage]:
        """Inject messages with a CAN ID not in the known set."""
        unknown_id = self._kwargs.get("injected_id", 0x7FF)
        data = bytes(self._rng.randint(0, 255) for _ in range(8))
        msg = CANMessageFactory.create(
            can_id=unknown_id,
            data=data,
            source_ecu=ECUType.UNKNOWN,
            timestamp=t,
        )
        return [msg]

    def _gen_replay(self, t: float) -> list[CANMessage]:
        """
        Generate messages with stale/duplicate sequence counters.
        Simulates recording and replaying legitimate traffic.
        """
        # Use a counter that is old (lower than what the system expects)
        stale_counter = self._kwargs.get("stale_counter", 1)
        data = bytes(8)  # Valid-looking payload
        msg = CANMessageFactory.create(
            can_id=self._target_id,
            data=data,
            source_ecu=ECUType.UNKNOWN,
            timestamp=t,
            sequence_counter=stale_counter,
        )
        return [msg]

    def _gen_spoofing(self, t: float) -> list[CANMessage]:
        """
        Generate messages claiming to be from an ECU that
        shouldn't send this CAN ID.
        """
        # Brake ECU CAN ID, but sent from "infotainment"
        data = bytes(8)
        msg = CANMessageFactory.create(
            can_id=self._target_id,
            data=data,
            source_ecu=ECUType.INFOTAINMENT,  # Wrong source
            timestamp=t,
            sequence_counter=self._rng.randint(1, 1000),
        )
        return [msg]

    def _gen_abnormal_frequency(self, t: float) -> list[CANMessage]:
        """Generate messages at an abnormal rate (too fast or too slow)."""
        # Generate multiple messages with very small inter-arrival time
        rate = self._kwargs.get("rate", 5)
        messages = []
        for i in range(rate):
            data = bytes(8)
            msg = CANMessageFactory.create(
                can_id=self._target_id,
                data=data,
                source_ecu=ECUType.UNKNOWN,
                timestamp=t + i * 0.0005,
            )
            messages.append(msg)
        return messages

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def attack_type(self) -> AttackType:
        return self._attack_type

    @property
    def messages_generated(self) -> int:
        return self._messages_generated
