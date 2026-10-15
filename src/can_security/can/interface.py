"""
Abstract CAN bus interface.

Defines the contract all CAN backends must implement,
enabling transparent switching between simulation and SocketCAN.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable

from can_security.core.models import CANMessage


class CANInterface(ABC):
    """Abstract CAN bus interface for sending/receiving messages."""

    @abstractmethod
    def start(self) -> None:
        """Initialize and start the CAN interface."""
        ...

    @abstractmethod
    def stop(self) -> None:
        """Cleanly shut down the CAN interface."""
        ...

    @abstractmethod
    def send(self, message: CANMessage) -> None:
        """Send a CAN message onto the bus."""
        ...

    @abstractmethod
    def receive(self, timeout: float | None = None) -> CANMessage | None:
        """
        Receive a CAN message from the bus.

        Args:
            timeout: Max seconds to wait. None = blocking.
                     0 = non-blocking poll.

        Returns:
            A CANMessage if one was received, None on timeout.
        """
        ...

    @abstractmethod
    def is_active(self) -> bool:
        """Check if the interface is currently active."""
        ...


class VirtualCANInterface(CANInterface):
    """
    In-memory virtual CAN bus for simulation mode.

    Messages sent are placed into a buffer that can be received.
    Supports multiple listeners via callback registration.
    """

    def __init__(self, buffer_size: int = 10_000):
        self._buffer: list[CANMessage] = []
        self._buffer_size = buffer_size
        self._active = False
        self._listeners: list[Callable[[CANMessage], None]] = []

    def start(self) -> None:
        self._active = True
        self._buffer.clear()

    def stop(self) -> None:
        self._active = False

    def send(self, message: CANMessage) -> None:
        if not self._active:
            return

        if len(self._buffer) >= self._buffer_size:
            # Drop oldest message to prevent unbounded growth
            self._buffer.pop(0)

        self._buffer.append(message)

        # Notify listeners
        for listener in self._listeners:
            try:
                listener(message)
            except Exception:
                pass  # Don't let listener errors crash the bus

    def receive(self, timeout: float | None = None) -> CANMessage | None:
        if self._buffer:
            return self._buffer.pop(0)
        return None

    def is_active(self) -> bool:
        return self._active

    def register_listener(self, callback: Callable[[CANMessage], None]) -> None:
        """Register a callback to be invoked on every message."""
        self._listeners.append(callback)

    def clear(self) -> None:
        """Clear the message buffer."""
        self._buffer.clear()

    @property
    def buffer_size(self) -> int:
        return len(self._buffer)
