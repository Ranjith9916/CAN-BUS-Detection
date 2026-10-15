"""
Enumerations for the CAN Security Framework.

Centralizes all enum types used across subsystems to ensure
consistent classification of ECUs, attacks, severities, and statuses.
"""

from enum import Enum, IntEnum, auto


class ECUType(str, Enum):
    """Vehicle ECU types in the simulation."""
    ENGINE = "engine"
    BRAKE = "brake"
    STEERING = "steering"
    TRANSMISSION = "transmission"
    INSTRUMENT_CLUSTER = "instrument_cluster"
    INFOTAINMENT = "infotainment"
    UNKNOWN = "unknown"


class MessageStatus(str, Enum):
    """Security status assigned to a CAN message after evaluation."""
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    ATTACK = "ATTACK"
    UNKNOWN = "UNKNOWN"


class AttackType(str, Enum):
    """Types of attacks the framework can simulate and detect."""
    NONE = "NONE"
    INJECTION = "INJECTION"
    FLOODING = "FLOODING"
    REPLAY = "REPLAY"
    SPOOFING = "SPOOFING"
    ABNORMAL_FREQUENCY = "ABNORMAL_FREQUENCY"
    INVALID_AUTH = "INVALID_AUTH"
    INVALID_FRESHNESS = "INVALID_FRESHNESS"


class Severity(str, Enum):
    """Risk severity levels — maps to configurable score thresholds."""
    NORMAL = "NORMAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AuthStatus(str, Enum):
    """Result of message authentication check."""
    VALID = "VALID"
    INVALID = "INVALID"
    NOT_REQUIRED = "NOT_REQUIRED"
    MISSING_KEY = "MISSING_KEY"
    ERROR = "ERROR"


class FreshnessStatus(str, Enum):
    """Result of message freshness/replay check."""
    FRESH = "FRESH"
    REPLAY = "REPLAY"
    STALE = "STALE"
    COUNTER_JUMP = "COUNTER_JUMP"
    NOT_REQUIRED = "NOT_REQUIRED"
    ERROR = "ERROR"


class ResponseAction(str, Enum):
    """Actions the response engine can take (simulation only)."""
    LOG = "LOG"
    ALERT = "ALERT"
    FLAG = "FLAG"
    QUARANTINE_SIMULATION_MESSAGE = "QUARANTINE_SIMULATION_MESSAGE"
    REJECT_SIMULATED_MESSAGE = "REJECT_SIMULATED_MESSAGE"


class DetectorType(str, Enum):
    """Types of intrusion detection engines."""
    RULE_ENGINE = "RULE_ENGINE"
    RANDOM_FOREST = "RANDOM_FOREST"
    ISOLATION_FOREST = "ISOLATION_FOREST"
    AUTOENCODER = "AUTOENCODER"
    LSTM = "LSTM"
    ENSEMBLE = "ENSEMBLE"


class SystemMode(str, Enum):
    """Operating mode of the framework."""
    SIMULATION = "simulation"
    SOCKETCAN = "socketcan"


class RuleName(str, Enum):
    """Names of individual detection rules."""
    UNKNOWN_CAN_ID = "UNKNOWN_CAN_ID"
    INVALID_DLC = "INVALID_DLC"
    ABNORMAL_FREQUENCY = "ABNORMAL_FREQUENCY"
    EXCESSIVE_BURST = "EXCESSIVE_BURST"
    INVALID_PAYLOAD_RANGE = "INVALID_PAYLOAD_RANGE"
    UNEXPECTED_SOURCE = "UNEXPECTED_SOURCE"
    COUNTER_ANOMALY = "COUNTER_ANOMALY"
    REPLAY_VIOLATION = "REPLAY_VIOLATION"
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"


class DrivingScenario(str, Enum):
    """Predefined driving scenarios for traffic generation."""
    NORMAL_DRIVING = "normal_driving"
    CITY = "city"
    HIGHWAY = "highway"
    PARKING = "parking"
    IDLE = "idle"
