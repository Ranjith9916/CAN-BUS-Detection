"""
CAN traffic collector.

Receives CAN messages from the bus interface, buffers them,
tracks statistics, and emits events for downstream processing.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Any, Callable

from can_security.can.interface import CANInterface
from can_security.core.models import CANMessage

logger = logging.getLogger(__name__)


class CANCollector:
    """
    Collects CAN traffic from a bus interface and provides
    buffered access for downstream processors.

    Tracks per-CAN-ID statistics for baseline comparison.
    """

    def __init__(
        self,
        interface: CANInterface,
        buffer_size: int = 10_000,
        on_message: Callable[[CANMessage], None] | None = None,
    ):
        self._interface = interface
        self._buffer: list[CANMessage] = []
        self._buffer_size = buffer_size
        self._on_message = on_message

        # Statistics
        self._total_received = 0
        self._start_time: float | None = None
        self._last_message_time: float = 0.0

        # Per-CAN-ID tracking
        self._id_counts: dict[int, int] = defaultdict(int)
        self._id_last_time: dict[int, float] = {}
        self._id_intervals: dict[int, list[float]] = defaultdict(list)

        self._running = False

    def start(self) -> None:
        """Start collecting messages."""
        self._running = True
        self._start_time = time.time()
        logger.info("CAN collector started")

    def stop(self) -> None:
        """Stop collecting messages."""
        self._running = False
        logger.info(
            "CAN collector stopped",
            extra={"total_received": self._total_received},
        )

    def process_message(self, message: CANMessage) -> None:
        """
        Process a single CAN message — buffer it and update stats.

        Called either by polling or by the interface listener callback.
        """
        if not self._running:
            return

        # Buffer management
        if len(self._buffer) >= self._buffer_size:
            self._buffer.pop(0)
        self._buffer.append(message)

        # Update statistics
        self._total_received += 1
        self._id_counts[message.can_id] += 1
        self._last_message_time = message.timestamp

        # Track inter-arrival times (keep last 100 per ID)
        if message.can_id in self._id_last_time:
            interval = message.timestamp - self._id_last_time[message.can_id]
            intervals = self._id_intervals[message.can_id]
            intervals.append(interval)
            if len(intervals) > 100:
                intervals.pop(0)
        self._id_last_time[message.can_id] = message.timestamp

        # Notify downstream
        if self._on_message:
            try:
                self._on_message(message)
            except Exception as e:
                logger.error(
                    "Error in message callback",
                    extra={"error": str(e)},
                )

    def get_messages(self, count: int | None = None) -> list[CANMessage]:
        """
        Get buffered messages.

        Args:
            count: Max number of messages to return. None = all.
        """
        if count is None:
            return list(self._buffer)
        return list(self._buffer[-count:])

    def get_window(self, window_size: int) -> list[CANMessage]:
        """Get the last `window_size` messages."""
        return list(self._buffer[-window_size:])

    def get_statistics(self) -> dict[str, Any]:
        """Return current traffic statistics."""
        elapsed = time.time() - self._start_time if self._start_time else 0
        rate = self._total_received / elapsed if elapsed > 0 else 0

        return {
            "total_received": self._total_received,
            "buffer_size": len(self._buffer),
            "elapsed_seconds": round(elapsed, 2),
            "messages_per_second": round(rate, 2),
            "unique_can_ids": len(self._id_counts),
            "id_counts": dict(self._id_counts),
        }

    def get_id_frequency(self, can_id: int) -> float:
        """
        Get the current average message frequency for a CAN ID (msg/s).
        """
        intervals = self._id_intervals.get(can_id, [])
        if not intervals:
            return 0.0
        avg_interval = sum(intervals) / len(intervals)
        return 1.0 / avg_interval if avg_interval > 0 else 0.0

    def clear(self) -> None:
        """Clear the message buffer and reset statistics."""
        self._buffer.clear()
        self._total_received = 0
        self._id_counts.clear()
        self._id_last_time.clear()
        self._id_intervals.clear()

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def total_received(self) -> int:
        return self._total_received
