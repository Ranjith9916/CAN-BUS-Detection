"""
Key management for CAN message authentication.

Handles key generation, loading from environment variables,
key rotation tracking, and key versioning. Never stores
keys in source code or logs.
"""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass
from typing import Any

from can_security.core.exceptions import KeyManagementError

logger = logging.getLogger(__name__)


@dataclass
class KeyInfo:
    """Metadata about a cryptographic key (never contains the key itself in logs)."""
    key_id: str
    version: int
    algorithm: str
    length_bytes: int
    source: str  # "generated" | "environment" | "file"


class KeyManager:
    """
    Manages cryptographic keys for CAN message authentication.

    Keys can be loaded from:
    - Environment variables (recommended for deployment)
    - Generated at runtime (for simulation/development)

    Keys are NEVER logged or printed.
    """

    def __init__(self, key_length: int = 32, algorithm: str = "HMAC-SHA256"):
        self._keys: dict[str, bytes] = {}
        self._key_infos: dict[str, KeyInfo] = {}
        self._key_length = key_length
        self._algorithm = algorithm

    def generate_key(self, key_id: str = "default", version: int = 1) -> KeyInfo:
        """
        Generate a new cryptographic key using a secure CSPRNG.

        Returns KeyInfo (without the key material itself for safety).
        """
        key = secrets.token_bytes(self._key_length)
        self._keys[key_id] = key

        info = KeyInfo(
            key_id=key_id,
            version=version,
            algorithm=self._algorithm,
            length_bytes=self._key_length,
            source="generated",
        )
        self._key_infos[key_id] = info

        logger.info(
            "Key generated",
            extra={"key_id": key_id, "version": version, "length": self._key_length},
        )
        # NEVER log the actual key material
        return info

    def load_from_environment(
        self,
        env_var: str = "CAN_AUTH_KEY_001",
        key_id: str = "default",
        version: int | None = None,
    ) -> KeyInfo:
        """
        Load a key from an environment variable.

        The env var should contain a hex-encoded key.
        """
        hex_key = os.environ.get(env_var)
        if not hex_key or hex_key == "REPLACE_WITH_GENERATED_KEY":
            raise KeyManagementError(
                f"Environment variable {env_var} not set or contains placeholder. "
                f"Generate a key with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )

        try:
            key = bytes.fromhex(hex_key)
        except ValueError as e:
            raise KeyManagementError(
                f"Invalid hex key in {env_var}: {e}"
            ) from e

        if len(key) < 16:
            raise KeyManagementError(
                f"Key from {env_var} is too short ({len(key)} bytes, minimum 16)"
            )

        key_version = version or int(
            os.environ.get("CAN_AUTH_KEY_VERSION", "1")
        )

        self._keys[key_id] = key
        info = KeyInfo(
            key_id=key_id,
            version=key_version,
            algorithm=self._algorithm,
            length_bytes=len(key),
            source="environment",
        )
        self._key_infos[key_id] = info

        logger.info(
            "Key loaded from environment",
            extra={"key_id": key_id, "version": key_version, "env_var": env_var},
        )
        return info

    def get_key(self, key_id: str = "default") -> bytes:
        """
        Retrieve a key by ID.

        Raises KeyManagementError if the key is not found.
        """
        key = self._keys.get(key_id)
        if key is None:
            raise KeyManagementError(f"Key '{key_id}' not found")
        return key

    def get_key_info(self, key_id: str = "default") -> KeyInfo | None:
        """Get metadata about a key (safe to log/display)."""
        return self._key_infos.get(key_id)

    def has_key(self, key_id: str = "default") -> bool:
        return key_id in self._keys

    def rotate_key(self, key_id: str = "default") -> KeyInfo:
        """
        Generate a new version of an existing key.

        The old key is replaced. In production, both old and new keys
        should be available during a transition period.
        """
        old_info = self._key_infos.get(key_id)
        new_version = (old_info.version + 1) if old_info else 1

        return self.generate_key(key_id=key_id, version=new_version)

    def list_keys(self) -> list[KeyInfo]:
        """List all loaded key metadata (never returns key material)."""
        return list(self._key_infos.values())

    @staticmethod
    def generate_key_hex(length: int = 32) -> str:
        """Generate a hex-encoded key string for .env files."""
        return secrets.token_hex(length)
