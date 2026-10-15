"""
Unit tests for CAN message model and factory.

Tests validation, construction, signal encoding/decoding,
and rejection of malformed frames.
"""

import pytest

from can_security.core.enums import ECUType
from can_security.core.exceptions import InvalidCANFrame
from can_security.core.models import CANMessage
from can_security.can.message import CANMessageFactory


# =============================================================================
# CANMessage Construction & Validation
# =============================================================================

class TestCANMessageValidation:
    """Test CAN message validation rules."""

    def test_valid_message_creation(self):
        """Valid CAN message should be created without errors."""
        msg = CANMessage(
            timestamp=1000.0,
            can_id=0x100,
            dlc=8,
            data=b"\x00" * 8,
            source_ecu=ECUType.ENGINE,
        )
        assert msg.can_id == 0x100
        assert msg.dlc == 8
        assert len(msg.data) == 8
        assert msg.source_ecu == ECUType.ENGINE

    def test_can_id_lower_bound(self):
        """CAN ID 0x000 should be valid."""
        msg = CANMessage(timestamp=0.0, can_id=0x000, dlc=1, data=b"\x00")
        assert msg.can_id == 0x000

    def test_can_id_upper_bound(self):
        """CAN ID 0x7FF should be valid (max standard CAN)."""
        msg = CANMessage(timestamp=0.0, can_id=0x7FF, dlc=1, data=b"\x00")
        assert msg.can_id == 0x7FF

    def test_can_id_too_high(self):
        """CAN ID > 0x7FF should be rejected."""
        with pytest.raises(ValueError, match="out of standard range"):
            CANMessage(timestamp=0.0, can_id=0x800, dlc=1, data=b"\x00")

    def test_can_id_negative(self):
        """Negative CAN ID should be rejected."""
        with pytest.raises(ValueError, match="out of standard range"):
            CANMessage(timestamp=0.0, can_id=-1, dlc=1, data=b"\x00")

    def test_dlc_zero(self):
        """DLC 0 with empty data should be valid."""
        msg = CANMessage(timestamp=0.0, can_id=0x100, dlc=0, data=b"")
        assert msg.dlc == 0

    def test_dlc_max(self):
        """DLC 8 should be valid."""
        msg = CANMessage(timestamp=0.0, can_id=0x100, dlc=8, data=b"\x00" * 8)
        assert msg.dlc == 8

    def test_dlc_too_high(self):
        """DLC > 8 should be rejected for standard CAN."""
        with pytest.raises(ValueError, match="out of range"):
            CANMessage(timestamp=0.0, can_id=0x100, dlc=9, data=b"\x00" * 9)

    def test_dlc_data_mismatch(self):
        """DLC must match actual data length."""
        with pytest.raises(ValueError, match="does not match DLC"):
            CANMessage(timestamp=0.0, can_id=0x100, dlc=4, data=b"\x00" * 8)

    def test_negative_timestamp(self):
        """Negative timestamp should be rejected."""
        with pytest.raises(ValueError, match="non-negative"):
            CANMessage(timestamp=-1.0, can_id=0x100, dlc=1, data=b"\x00")

    def test_can_id_hex_property(self):
        """can_id_hex should format correctly."""
        msg = CANMessage(timestamp=0.0, can_id=0x102, dlc=1, data=b"\x00")
        assert msg.can_id_hex == "0x102"

    def test_to_dict(self):
        """Serialization should include all fields."""
        msg = CANMessage(
            timestamp=1000.0,
            can_id=0x100,
            dlc=2,
            data=b"\x03\xe8",
            source_ecu=ECUType.ENGINE,
            sequence_counter=42,
        )
        d = msg.to_dict()
        assert d["can_id"] == 0x100
        assert d["can_id_hex"] == "0x100"
        assert d["dlc"] == 2
        assert d["data"] == "03e8"
        assert d["source_ecu"] == "engine"
        assert d["sequence_counter"] == 42

    def test_message_id_unique(self):
        """Each message should get a unique ID."""
        m1 = CANMessage(timestamp=0.0, can_id=0x100, dlc=1, data=b"\x00")
        m2 = CANMessage(timestamp=0.0, can_id=0x100, dlc=1, data=b"\x00")
        assert m1.message_id != m2.message_id


# =============================================================================
# CANMessageFactory
# =============================================================================

class TestCANMessageFactory:
    """Test the CAN message factory."""

    def test_create_valid(self):
        """Factory should create valid messages."""
        msg = CANMessageFactory.create(
            can_id=0x100,
            data=b"\x00" * 8,
            source_ecu=ECUType.ENGINE,
        )
        assert msg.can_id == 0x100
        assert msg.dlc == 8

    def test_create_invalid_raises(self):
        """Factory should raise InvalidCANFrame for invalid params."""
        with pytest.raises(InvalidCANFrame):
            CANMessageFactory.create(can_id=0x900, data=b"\x00")

    def test_create_auto_timestamp(self):
        """Factory should auto-generate timestamp if not provided."""
        msg = CANMessageFactory.create(can_id=0x100, data=b"\x00")
        assert msg.timestamp > 0

    def test_create_from_signals(self):
        """Signal encoding should produce correct payload bytes."""
        signal_defs = [
            {"name": "rpm", "start_byte": 0, "length_bytes": 2,
             "min_value": 0, "max_value": 8000},
            {"name": "engine_temp", "start_byte": 2, "length_bytes": 2,
             "min_value": -40, "max_value": 150},
        ]
        msg = CANMessageFactory.create_from_signals(
            can_id=0x100,
            signals={"rpm": 3000, "engine_temp": 90},
            signal_defs=signal_defs,
        )
        assert msg.dlc == 8

        # Decode and verify
        decoded = CANMessageFactory.decode_signals(msg, signal_defs)
        assert decoded["rpm"] == 3000
        assert decoded["engine_temp"] == 90

    def test_signal_clamping(self):
        """Values outside range should be clamped."""
        signal_defs = [
            {"name": "rpm", "start_byte": 0, "length_bytes": 2,
             "min_value": 0, "max_value": 8000},
        ]
        msg = CANMessageFactory.create_from_signals(
            can_id=0x100,
            signals={"rpm": 9999},  # Over max
            signal_defs=signal_defs,
        )
        decoded = CANMessageFactory.decode_signals(msg, signal_defs)
        assert decoded["rpm"] == 8000  # Clamped to max

    def test_signed_signal_encoding(self):
        """Signed signals (negative min) should encode/decode correctly."""
        signal_defs = [
            {"name": "angle", "start_byte": 0, "length_bytes": 2,
             "min_value": -540, "max_value": 540},
        ]
        msg = CANMessageFactory.create_from_signals(
            can_id=0x103,
            signals={"angle": -200},
            signal_defs=signal_defs,
        )
        decoded = CANMessageFactory.decode_signals(msg, signal_defs)
        assert decoded["angle"] == -200

    def test_payload_range_validation(self):
        """Out-of-range payload values should produce violations."""
        signal_defs = [
            {"name": "rpm", "start_byte": 0, "length_bytes": 2,
             "min_value": 0, "max_value": 8000},
        ]
        # Manually craft a message with rpm = 9000 (over max)
        import struct
        data = bytearray(8)
        struct.pack_into(">H", data, 0, 9000)
        msg = CANMessageFactory.create(can_id=0x100, data=bytes(data))

        violations = CANMessageFactory.validate_payload_range(msg, signal_defs)
        assert len(violations) == 1
        assert "above maximum" in violations[0]

    def test_payload_range_valid(self):
        """In-range payload should produce no violations."""
        signal_defs = [
            {"name": "rpm", "start_byte": 0, "length_bytes": 2,
             "min_value": 0, "max_value": 8000},
        ]
        msg = CANMessageFactory.create_from_signals(
            can_id=0x100,
            signals={"rpm": 3000},
            signal_defs=signal_defs,
        )
        violations = CANMessageFactory.validate_payload_range(msg, signal_defs)
        assert violations == []
