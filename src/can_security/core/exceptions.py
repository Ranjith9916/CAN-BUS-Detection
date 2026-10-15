"""
Custom exceptions for the CAN Security Framework.

Each exception type maps to a specific failure domain, enabling
targeted error handling without catching overly broad exception types.
"""


class CANSecurityError(Exception):
    """Base exception for all CAN security framework errors."""
    pass


# --- CAN Layer Exceptions ---

class InvalidCANFrame(CANSecurityError):
    """Raised when a CAN frame fails validation (ID, DLC, payload)."""

    def __init__(self, message: str, can_id: int | None = None, details: dict | None = None):
        self.can_id = can_id
        self.details = details or {}
        super().__init__(message)


class CANInterfaceError(CANSecurityError):
    """Raised when the CAN interface is unavailable or fails."""
    pass


class CANBufferOverflow(CANSecurityError):
    """Raised when the CAN message buffer exceeds its capacity."""
    pass


# --- Authentication Exceptions ---

class AuthenticationError(CANSecurityError):
    """Raised when message authentication fails."""

    def __init__(self, message: str, can_id: int | None = None, reason: str = ""):
        self.can_id = can_id
        self.reason = reason
        super().__init__(message)


class KeyManagementError(CANSecurityError):
    """Raised for key loading, rotation, or configuration failures."""
    pass


# --- Freshness / Replay Exceptions ---

class ReplayDetected(CANSecurityError):
    """Raised when a replayed message is detected via freshness check."""

    def __init__(self, message: str, can_id: int | None = None,
                 expected_counter: int | None = None,
                 received_counter: int | None = None):
        self.can_id = can_id
        self.expected_counter = expected_counter
        self.received_counter = received_counter
        super().__init__(message)


class StaleMessage(CANSecurityError):
    """Raised when a message's freshness counter is too old."""
    pass


# --- Configuration Exceptions ---

class ConfigurationError(CANSecurityError):
    """Raised when configuration is invalid or missing."""
    pass


# --- Detection Exceptions ---

class DetectionError(CANSecurityError):
    """Raised when the detection engine encounters an error."""
    pass


class ModelNotFoundError(CANSecurityError):
    """Raised when a required ML model file is not found."""
    pass


class ModelLoadError(CANSecurityError):
    """Raised when an ML model fails to load (corrupt, incompatible)."""
    pass


# --- Database Exceptions ---

class DatabaseError(CANSecurityError):
    """Raised for database connection or query failures."""
    pass


# --- Simulation Exceptions ---

class SimulationError(CANSecurityError):
    """Raised when the vehicle/attack simulator encounters an error."""
    pass
