"""
Database models and connection management.

Uses SQLAlchemy for ORM with SQLite (async via aiosqlite).
Stores security events, alerts, CAN messages, and metrics.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import (
    Boolean, Column, DateTime, Float, Integer, String, Text,
    create_engine, Index,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


# =============================================================================
# Database Models
# =============================================================================

class SecurityEventDB(Base):
    """Persisted security event for forensic analysis."""
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(32), unique=True, nullable=False, index=True)
    timestamp = Column(Float, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    can_id = Column(Integer, nullable=False, index=True)
    can_id_hex = Column(String(8))
    message_id = Column(String(32))
    attack_type = Column(String(32), index=True)
    severity = Column(String(16), index=True)
    risk_score = Column(Float)
    status = Column(String(16))
    source_ecu = Column(String(32))
    description = Column(Text)
    rule_evidence_json = Column(Text)
    ml_anomaly_score = Column(Float)
    ml_confidence = Column(Float)
    ml_detector = Column(String(32))
    auth_status = Column(String(16))
    freshness_status = Column(String(16))
    actions_taken = Column(Text)
    recommended_response = Column(Text)


class AlertDB(Base):
    """Persisted alert for dashboard and audit trail."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(32), unique=True, nullable=False, index=True)
    timestamp = Column(Float, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    can_id = Column(Integer, index=True)
    attack_type = Column(String(32))
    severity = Column(String(16), index=True)
    risk_score = Column(Float)
    confidence = Column(Float)
    title = Column(Text)
    description = Column(Text)
    auth_status = Column(String(16))
    freshness_status = Column(String(16))
    acknowledged = Column(Boolean, default=False)
    event_id = Column(String(32), index=True)


class SystemMetricDB(Base):
    """System performance metrics over time."""
    __tablename__ = "system_metrics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Float, nullable=False, index=True)
    messages_per_second = Column(Float)
    processing_latency_ms = Column(Float)
    ml_inference_latency_ms = Column(Float)
    cpu_percent = Column(Float)
    memory_mb = Column(Float)
    total_messages = Column(Integer)
    total_alerts = Column(Integer)
    total_attacks_detected = Column(Integer)


class AuditLogDB(Base):
    """Audit trail for security-relevant system actions."""
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Float, nullable=False, index=True)
    component = Column(String(64))
    event_type = Column(String(64), index=True)
    severity = Column(String(16))
    message = Column(Text)
    details_json = Column(Text)


# =============================================================================
# Database Manager
# =============================================================================

class DatabaseManager:
    """
    Manages database connections and provides CRUD operations.

    Uses synchronous SQLAlchemy for simplicity. The async variant
    can be swapped in for production if needed.
    """

    def __init__(self, db_url: str = "sqlite:///data/can_security.db"):
        # Convert async URL to sync for synchronous operations
        sync_url = db_url.replace("+aiosqlite", "").replace("aiosqlite:///", "sqlite:///")

        # Ensure data directory exists
        if "sqlite" in sync_url:
            db_path = sync_url.split("///")[-1]
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        self._engine = create_engine(sync_url, echo=False, connect_args={'check_same_thread': False})
        self._session_factory = sessionmaker(bind=self._engine)
        self._initialized = False

    def initialize(self) -> None:
        """Create all tables if they don't exist."""
        Base.metadata.create_all(self._engine)
        self._initialized = True
        logger.info("Database initialized")

    def get_session(self) -> Session:
        return self._session_factory()

    # --- Security Events ---

    def store_event(self, event_data: dict[str, Any]) -> None:
        """Store a security event."""
        import json
        session = self.get_session()
        try:
            db_event = SecurityEventDB(
                event_id=event_data.get("event_id", ""),
                timestamp=event_data.get("timestamp", 0.0),
                can_id=int(event_data.get("can_id", "0x000").replace("0x", ""), 16)
                    if isinstance(event_data.get("can_id"), str)
                    else event_data.get("can_id", 0),
                can_id_hex=event_data.get("can_id") if isinstance(event_data.get("can_id"), str) else f"0x{event_data.get('can_id', 0):03X}",
                message_id=event_data.get("message_id"),
                attack_type=event_data.get("attack_type"),
                severity=event_data.get("severity"),
                risk_score=event_data.get("risk_score"),
                status=event_data.get("status"),
                source_ecu=event_data.get("source_ecu"),
                description=event_data.get("description"),
                rule_evidence_json=json.dumps(event_data.get("rule_evidence", [])),
                ml_anomaly_score=event_data.get("ml_prediction", {}).get("anomaly_score") if event_data.get("ml_prediction") else None,
                ml_confidence=event_data.get("ml_prediction", {}).get("confidence") if event_data.get("ml_prediction") else None,
                ml_detector=event_data.get("ml_prediction", {}).get("detector") if event_data.get("ml_prediction") else None,
                auth_status=event_data.get("auth_status"),
                freshness_status=event_data.get("freshness_status"),
                actions_taken=json.dumps(event_data.get("actions_taken", [])),
                recommended_response=event_data.get("recommended_response"),
            )
            session.add(db_event)
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to store event: {e}")
        finally:
            session.close()

    def store_alert(self, alert_data: dict[str, Any]) -> None:
        """Store an alert."""
        session = self.get_session()
        try:
            db_alert = AlertDB(
                alert_id=alert_data.get("alert_id", ""),
                timestamp=alert_data.get("timestamp", 0.0),
                can_id=int(alert_data.get("can_id", "0x000").replace("0x", ""), 16)
                    if isinstance(alert_data.get("can_id"), str)
                    else alert_data.get("can_id", 0),
                attack_type=alert_data.get("attack_type"),
                severity=alert_data.get("severity"),
                risk_score=alert_data.get("risk_score"),
                confidence=alert_data.get("confidence"),
                title=alert_data.get("title"),
                description=alert_data.get("description"),
                auth_status=alert_data.get("auth_status"),
                freshness_status=alert_data.get("freshness_status"),
                event_id=alert_data.get("event_id"),
            )
            session.add(db_alert)
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to store alert: {e}")
        finally:
            session.close()

    def get_recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get the most recent security events."""
        import json
        session = self.get_session()
        try:
            events = (
                session.query(SecurityEventDB)
                .order_by(SecurityEventDB.timestamp.desc())
                .limit(limit)
                .all()
            )
            return [
                {
                    "event_id": e.event_id,
                    "timestamp": e.timestamp,
                    "can_id": e.can_id_hex,
                    "attack_type": e.attack_type,
                    "severity": e.severity,
                    "risk_score": e.risk_score,
                    "status": e.status,
                    "description": e.description,
                    "auth_status": e.auth_status,
                    "freshness_status": e.freshness_status,
                }
                for e in events
            ]
        finally:
            session.close()

    def get_recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get the most recent alerts."""
        session = self.get_session()
        try:
            alerts = (
                session.query(AlertDB)
                .order_by(AlertDB.timestamp.desc())
                .limit(limit)
                .all()
            )
            return [
                {
                    "alert_id": a.alert_id,
                    "timestamp": a.timestamp,
                    "can_id": a.can_id,
                    "attack_type": a.attack_type,
                    "severity": a.severity,
                    "risk_score": a.risk_score,
                    "title": a.title,
                    "description": a.description,
                    "acknowledged": a.acknowledged,
                }
                for a in alerts
            ]
        finally:
            session.close()

    def get_event_counts(self) -> dict[str, int]:
        """Get count of events by severity."""
        session = self.get_session()
        try:
            from sqlalchemy import func
            results = (
                session.query(SecurityEventDB.severity, func.count())
                .group_by(SecurityEventDB.severity)
                .all()
            )
            return {sev: count for sev, count in results}
        finally:
            session.close()

    def store_metrics(self, metrics: dict[str, Any]) -> None:
        """Store system metrics snapshot."""
        session = self.get_session()
        try:
            db_metric = SystemMetricDB(
                timestamp=metrics.get("timestamp", 0.0),
                messages_per_second=metrics.get("messages_per_second"),
                processing_latency_ms=metrics.get("processing_latency_ms"),
                ml_inference_latency_ms=metrics.get("ml_inference_latency_ms"),
                cpu_percent=metrics.get("cpu_percent"),
                memory_mb=metrics.get("memory_mb"),
                total_messages=metrics.get("total_messages"),
                total_alerts=metrics.get("total_alerts"),
                total_attacks_detected=metrics.get("total_attacks_detected"),
            )
            session.add(db_metric)
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to store metrics: {e}")
        finally:
            session.close()
