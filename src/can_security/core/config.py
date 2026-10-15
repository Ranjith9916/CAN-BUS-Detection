"""
Configuration loader for the CAN Security Framework.

Loads YAML configuration files and environment variables into
a typed, validated configuration object. Supports fallback defaults
and environment variable overrides.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from can_security.core.exceptions import ConfigurationError


# =============================================================================
# Configuration Data Classes
# =============================================================================

@dataclass
class CANConfig:
    interface: str = "virtual"
    bitrate: int = 500_000
    buffer_size: int = 10_000
    max_message_rate: int = 10_000


@dataclass
class SimulationConfig:
    enabled: bool = True
    seed: int = 42
    tick_rate_hz: int = 100
    duration_seconds: int = 60
    scenario: str = "normal_driving"


@dataclass
class FeatureConfig:
    window_size: int = 100
    window_overlap: int = 50
    time_window_seconds: float = 1.0


@dataclass
class RiskThresholds:
    normal: float = 0.29
    low: float = 0.59
    medium: float = 0.79
    high: float = 0.94
    critical: float = 1.0


@dataclass
class DetectionConfig:
    anomaly_threshold: float = 0.8
    rule_engine_enabled: bool = True
    ml_engine_enabled: bool = True
    ensemble_enabled: bool = True
    risk_thresholds: RiskThresholds = field(default_factory=RiskThresholds)


@dataclass
class MLConfig:
    model_type: str = "random_forest"
    model_path: str = "ml/models/"
    train_test_split: float = 0.2
    validation_split: float = 0.1
    random_seed: int = 42
    n_estimators: int = 100
    max_depth: int = 20


@dataclass
class AuthConfig:
    enabled: bool = True
    algorithm: str = "HMAC-SHA256"
    key_length_bytes: int = 32
    tag_length_bytes: int = 16
    key_source: str = "environment"
    key_rotation_interval_hours: int = 24


@dataclass
class FreshnessConfig:
    enabled: bool = True
    mechanism: str = "monotonic_counter"
    counter_bits: int = 32
    max_counter_jump: int = 100
    stale_threshold_seconds: float = 5.0


@dataclass
class DatabaseConfig:
    url: str = "sqlite+aiosqlite:///data/can_security.db"
    echo: bool = False
    pool_size: int = 5


@dataclass
class APIConfig:
    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: list[str] = field(
        default_factory=lambda: ["http://localhost:5173", "http://localhost:3000"]
    )
    docs_enabled: bool = True


@dataclass
class AlertConfig:
    enabled: bool = True
    max_alerts_per_minute: int = 100
    log_to_file: bool = True
    log_path: str = "logs/alerts.log"


# =============================================================================
# Master Configuration
# =============================================================================

@dataclass
class AppConfig:
    """Root configuration aggregating all subsystem configs."""
    name: str = "CAN Security Framework"
    version: str = "0.1.0"
    mode: str = "simulation"
    log_level: str = "INFO"
    log_format: str = "json"

    can: CANConfig = field(default_factory=CANConfig)
    simulation: SimulationConfig = field(default_factory=SimulationConfig)
    feature_extraction: FeatureConfig = field(default_factory=FeatureConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    ml: MLConfig = field(default_factory=MLConfig)
    authentication: AuthConfig = field(default_factory=AuthConfig)
    freshness: FreshnessConfig = field(default_factory=FreshnessConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    api: APIConfig = field(default_factory=APIConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)

    # Raw CAN ID definitions loaded from can_ids.yaml
    can_id_definitions: dict[int, dict[str, Any]] = field(default_factory=dict)

    # Raw detection rules from detection_rules.yaml
    detection_rules: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Raw security policy from security_policy.yaml
    security_policy: dict[str, Any] = field(default_factory=dict)


def _deep_get(data: dict, *keys: str, default: Any = None) -> Any:
    """Safely navigate nested dicts."""
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key, default)
        else:
            return default
    return data


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML file, returning empty dict on failure."""
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise ConfigurationError(f"Failed to parse YAML file {path}: {e}") from e


def load_config(config_dir: str | Path | None = None) -> AppConfig:
    """
    Load configuration from YAML files and environment variables.

    Priority: environment variables > YAML files > defaults.

    Args:
        config_dir: Path to the config/ directory. Defaults to
                     'config/' relative to the project root.
    """
    if config_dir is None:
        # Walk up from this file to find the project root
        project_root = Path(__file__).resolve().parent.parent.parent.parent
        config_dir = project_root / "config"
    else:
        config_dir = Path(config_dir)

    # Load YAML files
    main_cfg = _load_yaml(config_dir / "config.yaml")
    can_ids_raw = _load_yaml(config_dir / "can_ids.yaml")
    rules_raw = _load_yaml(config_dir / "detection_rules.yaml")
    policy_raw = _load_yaml(config_dir / "security_policy.yaml")

    # Parse CAN ID map — convert hex string keys to int
    can_id_defs: dict[int, dict[str, Any]] = {}
    for key, value in (can_ids_raw.get("can_ids") or {}).items():
        if isinstance(key, int):
            can_id_defs[key] = value
        elif isinstance(key, str):
            can_id_defs[int(key, 0)] = value

    # Build config with env-var overrides
    mode = os.environ.get("CAN_SECURITY_MODE", _deep_get(main_cfg, "system", "mode", default="simulation"))
    log_level = os.environ.get("CAN_SECURITY_LOG_LEVEL", _deep_get(main_cfg, "system", "log_level", default="INFO"))

    can_section = main_cfg.get("can", {})
    sim_section = main_cfg.get("simulation", {})
    feat_section = main_cfg.get("feature_extraction", {})
    det_section = main_cfg.get("detection", {})
    ml_section = main_cfg.get("ml", {})
    auth_section = main_cfg.get("authentication", {})
    fresh_section = main_cfg.get("freshness", {})
    db_section = main_cfg.get("database", {})
    api_section = main_cfg.get("api", {})
    alert_section = main_cfg.get("alerts", {})

    risk_thresh = det_section.get("risk_thresholds", {})

    config = AppConfig(
        name=_deep_get(main_cfg, "system", "name", default="CAN Security Framework"),
        version=_deep_get(main_cfg, "system", "version", default="0.1.0"),
        mode=mode,
        log_level=log_level,
        log_format=_deep_get(main_cfg, "system", "log_format", default="json"),
        can=CANConfig(
            interface=os.environ.get("CAN_INTERFACE", can_section.get("interface", "virtual")),
            bitrate=can_section.get("bitrate", 500_000),
            buffer_size=can_section.get("buffer_size", 10_000),
            max_message_rate=can_section.get("max_message_rate", 10_000),
        ),
        simulation=SimulationConfig(
            enabled=sim_section.get("enabled", True),
            seed=sim_section.get("seed", 42),
            tick_rate_hz=sim_section.get("tick_rate_hz", 100),
            duration_seconds=sim_section.get("duration_seconds", 60),
            scenario=sim_section.get("scenario", "normal_driving"),
        ),
        feature_extraction=FeatureConfig(
            window_size=feat_section.get("window_size", 100),
            window_overlap=feat_section.get("window_overlap", 50),
            time_window_seconds=feat_section.get("time_window_seconds", 1.0),
        ),
        detection=DetectionConfig(
            anomaly_threshold=det_section.get("anomaly_threshold", 0.8),
            rule_engine_enabled=det_section.get("rule_engine_enabled", True),
            ml_engine_enabled=det_section.get("ml_engine_enabled", True),
            ensemble_enabled=det_section.get("ensemble_enabled", True),
            risk_thresholds=RiskThresholds(
                normal=risk_thresh.get("normal", 0.29),
                low=risk_thresh.get("low", 0.59),
                medium=risk_thresh.get("medium", 0.79),
                high=risk_thresh.get("high", 0.94),
                critical=risk_thresh.get("critical", 1.0),
            ),
        ),
        ml=MLConfig(
            model_type=os.environ.get("ML_MODEL_TYPE", ml_section.get("model_type", "random_forest")),
            model_path=os.environ.get("ML_MODEL_PATH", ml_section.get("model_path", "ml/models/")),
            train_test_split=ml_section.get("train_test_split", 0.2),
            validation_split=ml_section.get("validation_split", 0.1),
            random_seed=ml_section.get("random_seed", 42),
            n_estimators=_deep_get(ml_section, "random_forest", "n_estimators", default=100),
            max_depth=_deep_get(ml_section, "random_forest", "max_depth", default=20),
        ),
        authentication=AuthConfig(
            enabled=auth_section.get("enabled", True),
            algorithm=auth_section.get("algorithm", "HMAC-SHA256"),
            key_length_bytes=auth_section.get("key_length_bytes", 32),
            tag_length_bytes=auth_section.get("tag_length_bytes", 16),
            key_source=auth_section.get("key_source", "environment"),
            key_rotation_interval_hours=auth_section.get("key_rotation_interval_hours", 24),
        ),
        freshness=FreshnessConfig(
            enabled=fresh_section.get("enabled", True),
            mechanism=fresh_section.get("mechanism", "monotonic_counter"),
            counter_bits=fresh_section.get("counter_bits", 32),
            max_counter_jump=fresh_section.get("max_counter_jump", 100),
            stale_threshold_seconds=fresh_section.get("stale_threshold_seconds", 5.0),
        ),
        database=DatabaseConfig(
            url=os.environ.get("DATABASE_URL", db_section.get("url", "sqlite+aiosqlite:///data/can_security.db")),
            echo=db_section.get("echo", False),
            pool_size=db_section.get("pool_size", 5),
        ),
        api=APIConfig(
            host=os.environ.get("API_HOST", api_section.get("host", "0.0.0.0")),
            port=int(os.environ.get("API_PORT", api_section.get("port", 8000))),
            cors_origins=api_section.get("cors_origins", ["http://localhost:5173"]),
            docs_enabled=api_section.get("docs_enabled", True),
        ),
        alerts=AlertConfig(
            enabled=alert_section.get("enabled", True),
            max_alerts_per_minute=alert_section.get("max_alerts_per_minute", 100),
            log_to_file=alert_section.get("log_to_file", True),
            log_path=alert_section.get("log_path", "logs/alerts.log"),
        ),
        can_id_definitions=can_id_defs,
        detection_rules=rules_raw.get("rules", {}),
        security_policy=policy_raw,
    )

    return config
