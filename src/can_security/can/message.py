"""
CAN message factory with validation and construction helpers.

Provides safe construction of CANMessage objects with:
- Automatic validation
- Signal encoding/decoding
- Authentication metadata attachment
"""

from __future__ import annotations

import struct
import time
from typing import Any

from can_security.core.enums import ECUType
from can_security.core.exceptions import InvalidCANFrame
from can_security.core.models import CANMessage


class CANMessageFactory:
    """Factory for creating validated CAN messages."""

    @staticmethod
    def create(
        can_id: int,
        data: bytes,
        source_ecu: ECUType = ECUType.UNKNOWN,
        timestamp: float | None = None,
        sequence_counter: int | None = None,
    ) -> CANMessage:
        """
        Create a validated CAN message.

        Raises InvalidCANFrame if the message parameters are invalid.
        """
        if timestamp is None:
            timestamp = time.time()

        try:
            msg = CANMessage(
                timestamp=timestamp,
                can_id=can_id,
                dlc=len(data),
                data=data,
                source_ecu=source_ecu,
                sequence_counter=sequence_counter,
            )
            return msg
        except ValueError as e:
            raise InvalidCANFrame(
                str(e), can_id=can_id, details={"dlc": len(data)}
            ) from e

    @staticmethod
    def create_from_signals(
        can_id: int,
        signals: dict[str, int | float],
        signal_defs: list[dict[str, Any]],
        source_ecu: ECUType = ECUType.UNKNOWN,
        timestamp: float | None = None,
        sequence_counter: int | None = None,
    ) -> CANMessage:
        """
        Create a CAN message by encoding signal values into the payload.

        Each signal definition specifies start_byte, length_bytes, min/max.
        Values are clamped to configured ranges.
        """
        data = bytearray(8)  # Standard CAN frame = 8 bytes

        for sig_def in signal_defs:
            name = sig_def["name"]
            if name not in signals:
                continue

            value = signals[name]
            start = sig_def["start_byte"]
            length = sig_def["length_bytes"]
            min_val = sig_def.get("min_value", 0)
            max_val = sig_def.get("max_value", 65535)

            # Clamp to valid range
            clamped = int(max(min_val, min(max_val, value)))

            # Handle signed values (e.g., steering angle)
            if min_val < 0:
                # Store as signed integer
                if length == 1:
                    struct.pack_into(">b", data, start, clamped)
                elif length == 2:
                    struct.pack_into(">h", data, start, clamped)
                elif length == 4:
                    struct.pack_into(">i", data, start, clamped)
            else:
                # Store as unsigned integer
                if length == 1:
                    struct.pack_into(">B", data, start, clamped)
                elif length == 2:
                    struct.pack_into(">H", data, start, clamped)
                elif length == 4:
                    struct.pack_into(">I", data, start, clamped)

        return CANMessageFactory.create(
            can_id=can_id,
            data=bytes(data),
            source_ecu=source_ecu,
            timestamp=timestamp,
            sequence_counter=sequence_counter,
        )

    @staticmethod
    def decode_signals(
        msg: CANMessage,
        signal_defs: list[dict[str, Any]],
    ) -> dict[str, int]:
        """Decode signal values from a CAN message payload."""
        result = {}
        for sig_def in signal_defs:
            name = sig_def["name"]
            start = sig_def["start_byte"]
            length = sig_def["length_bytes"]
            min_val = sig_def.get("min_value", 0)

            if start + length > len(msg.data):
                continue

            if min_val < 0:
                if length == 1:
                    result[name] = struct.unpack_from(">b", msg.data, start)[0]
                elif length == 2:
                    result[name] = struct.unpack_from(">h", msg.data, start)[0]
                elif length == 4:
                    result[name] = struct.unpack_from(">i", msg.data, start)[0]
            else:
                if length == 1:
                    result[name] = struct.unpack_from(">B", msg.data, start)[0]
                elif length == 2:
                    result[name] = struct.unpack_from(">H", msg.data, start)[0]
                elif length == 4:
                    result[name] = struct.unpack_from(">I", msg.data, start)[0]

        return result

    @staticmethod
    def validate_payload_range(
        msg: CANMessage,
        signal_defs: list[dict[str, Any]],
    ) -> list[str]:
        """
        Check if signal values are within configured ranges.

        Returns a list of violation descriptions (empty if all valid).
        """
        violations = []
        decoded = CANMessageFactory.decode_signals(msg, signal_defs)

        for sig_def in signal_defs:
            name = sig_def["name"]
            if name not in decoded:
                continue

            value = decoded[name]
            min_val = sig_def.get("min_value")
            max_val = sig_def.get("max_value")

            if min_val is not None and value < min_val:
                violations.append(
                    f"Signal '{name}' value {value} below minimum {min_val}"
                )
            if max_val is not None and value > max_val:
                violations.append(
                    f"Signal '{name}' value {value} above maximum {max_val}"
                )

        return violations
