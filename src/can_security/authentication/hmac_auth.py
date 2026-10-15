"""
HMAC-based CAN message authentication.

Uses the `cryptography` library for all crypto operations.
Never implements custom primitives. Uses constant-time comparison.
"""

from __future__ import annotations

import hmac
import logging
import struct
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC as CryptoHMAC

from can_security.core.enums import AuthStatus
from can_security.core.exceptions import AuthenticationError
from can_security.core.models import AuthenticationResult, CANMessage

logger = logging.getLogger(__name__)


class HMACAuthenticator:
    """
    HMAC-SHA256 message authenticator for CAN messages.

    Computes a truncated HMAC over the CAN ID, payload, and
    freshness counter to provide authentication and integrity.

    Uses constant-time comparison to prevent timing attacks.
    """

    def __init__(
        self,
        key: bytes,
        key_id: str = "default",
        key_version: int = 1,
        tag_length: int = 16,
    ):
        if len(key) < 16:
            raise ValueError("Key must be at least 16 bytes")

        self._key = key
        self._key_id = key_id
        self._key_version = key_version
        self._tag_length = tag_length

    def sign(self, message: CANMessage, counter: int | None = None) -> bytes:
        """
        Compute HMAC tag for a CAN message.

        The MAC covers: CAN ID || DLC || payload || counter (if provided).
        This prevents payload tampering and binds the counter.
        """
        mac_input = self._build_mac_input(message, counter)

        h = CryptoHMAC(self._key, hashes.SHA256())
        h.update(mac_input)
        full_tag = h.finalize()

        # Truncate to configured length for CAN payload constraints
        return full_tag[: self._tag_length]

    def verify(
        self,
        message: CANMessage,
        tag: bytes,
        counter: int | None = None,
    ) -> AuthenticationResult:
        """
        Verify the HMAC tag of a CAN message.

        Uses constant-time comparison to prevent timing side-channels.
        """
        try:
            expected_tag = self.sign(message, counter)

            # Constant-time comparison — critical for security
            is_valid = hmac.compare_digest(expected_tag, tag)

            if is_valid:
                return AuthenticationResult(
                    status=AuthStatus.VALID,
                    can_id=message.can_id,
                    key_id=self._key_id,
                    key_version=self._key_version,
                )
            else:
                return AuthenticationResult(
                    status=AuthStatus.INVALID,
                    can_id=message.can_id,
                    key_id=self._key_id,
                    key_version=self._key_version,
                    error_message="MAC verification failed",
                )
        except Exception as e:
            logger.error(
                "Authentication error",
                extra={"can_id": f"0x{message.can_id:03X}", "error": str(e)},
            )
            return AuthenticationResult(
                status=AuthStatus.ERROR,
                can_id=message.can_id,
                error_message=f"Authentication error: {type(e).__name__}",
            )

    def _build_mac_input(self, message: CANMessage, counter: int | None) -> bytes:
        """
        Build the MAC input bytes.

        Structure: CAN_ID (2 bytes) || DLC (1 byte) || DATA || COUNTER (4 bytes, optional)
        """
        parts = [
            struct.pack(">H", message.can_id),  # CAN ID as 2 bytes big-endian
            struct.pack(">B", message.dlc),  # DLC as 1 byte
            message.data,  # Raw payload
        ]

        if counter is not None:
            parts.append(struct.pack(">I", counter))  # Counter as 4 bytes

        return b"".join(parts)

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def key_version(self) -> int:
        return self._key_version
