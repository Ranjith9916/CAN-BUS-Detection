"""
Freshness / replay protection for CAN messages.

Implements monotonic counter tracking per CAN ID to detect
replayed, stale, or out-of-order messages.
"""

from __future__ import annotations

import logging
from typing import Any

from can_security.core.enums import FreshnessStatus
from can_security.core.models import FreshnessResult

logger = logging.getLogger(__name__)


class FreshnessManager:
    """
    Manages per-CAN-ID monotonic counters for replay protection.

    Detects:
    - Replayed counters (same as last seen)
    - Stale counters (lower than last seen)
    - Excessive counter jumps (configurable threshold)
    """

    def __init__(self, max_counter_jump: int = 100, counter_bits: int = 32):
        self._max_jump = max_counter_jump
        self._counter_max = (2 ** counter_bits) - 1

        # Per-CAN-ID state: last accepted counter
        self._last_counters: dict[int, int] = {}

    def check(self, can_id: int, counter: int) -> FreshnessResult:
        """
        Check a message's freshness counter.

        Returns FRESH if the counter is valid and newer than the last seen.
        """
        if counter < 0 or counter > self._counter_max:
            return FreshnessResult(
                status=FreshnessStatus.ERROR,
                can_id=can_id,
                received_counter=counter,
                error_message=f"Counter {counter} out of valid range",
            )

        last = self._last_counters.get(can_id)

        if last is None:
            # First message from this CAN ID — accept and record
            self._last_counters[can_id] = counter
            return FreshnessResult(
                status=FreshnessStatus.FRESH,
                can_id=can_id,
                received_counter=counter,
                expected_counter=None,
            )

        expected = last + 1

        if counter == last:
            # Exact duplicate — replay
            return FreshnessResult(
                status=FreshnessStatus.REPLAY,
                can_id=can_id,
                received_counter=counter,
                expected_counter=expected,
                error_message=f"Duplicate counter {counter} (replay detected)",
            )

        if counter < last:
            # Counter went backwards — stale/replay
            return FreshnessResult(
                status=FreshnessStatus.STALE,
                can_id=can_id,
                received_counter=counter,
                expected_counter=expected,
                error_message=(
                    f"Counter {counter} < last seen {last} (stale message)"
                ),
            )

        jump = counter - last
        if jump > self._max_jump:
            # Suspiciously large jump — may indicate attack or communication loss
            # Still accept the counter but flag it
            self._last_counters[can_id] = counter
            return FreshnessResult(
                status=FreshnessStatus.COUNTER_JUMP,
                can_id=can_id,
                received_counter=counter,
                expected_counter=expected,
                error_message=(
                    f"Counter jump of {jump} exceeds max {self._max_jump}"
                ),
            )

        # Valid increment
        self._last_counters[can_id] = counter
        return FreshnessResult(
            status=FreshnessStatus.FRESH,
            can_id=can_id,
            received_counter=counter,
            expected_counter=expected,
        )

    def reset(self, can_id: int | None = None) -> None:
        """Reset counter state. If can_id is None, resets all."""
        if can_id is not None:
            self._last_counters.pop(can_id, None)
        else:
            self._last_counters.clear()

    def get_last_counter(self, can_id: int) -> int | None:
        """Get the last accepted counter for a CAN ID."""
        return self._last_counters.get(can_id)
