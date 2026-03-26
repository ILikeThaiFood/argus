"""SQLAlchemy ORM models for PostgreSQL / TimescaleDB."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    Index,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID

from app.core.database import Base


class Event(Base):
    """
    Raw security events table.

    -- TimescaleDB hypertable creation (run once after table exists):
    -- SELECT create_hypertable('events', 'time', if_not_exists => TRUE);
    """

    __tablename__ = "events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    time = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True)
    severity_id = Column(Integer, nullable=False, default=0)
    type_uid = Column(Integer, nullable=False, default=0)
    category_uid = Column(Integer, nullable=False, default=0)
    class_uid = Column(Integer, nullable=False, default=0)
    activity_id = Column(Integer, nullable=False, default=0)
    status = Column(String(32), nullable=False, default="new")
    src_ip = Column(String(45), nullable=False, index=True)
    dst_ip = Column(String(45), nullable=False, index=True)
    src_port = Column(Integer, nullable=False, default=0)
    dst_port = Column(Integer, nullable=False, default=0)
    protocol = Column(String(16), nullable=False, default="TCP")
    metadata_ = Column("metadata", JSONB, nullable=False, default=dict)
    observables = Column(JSONB, nullable=False, default=list)
    raw = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_events_time_severity", "time", "severity_id"),
        {"comment": "TimescaleDB hypertable on 'time' column"},
    )


class AlertRecord(Base):
    """Persisted alert records."""

    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    severity = Column(String(16), nullable=False, default="medium")
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=False, default="")
    mitre_tactic = Column(String(128), nullable=False, default="")
    mitre_technique = Column(String(128), nullable=False, default="")
    confidence = Column(Float, nullable=False, default=0.0)
    shap_values = Column(JSONB, nullable=False, default=dict)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True)
    source_ip = Column(String(45), nullable=False, default="")
    dest_ip = Column(String(45), nullable=False, default="")
    kill_chain_phase = Column(String(32), nullable=False, default="recon")

    __table_args__ = (
        Index("ix_alerts_severity_ts", "severity", "timestamp"),
    )


class ThreatIndicator(Base):
    """Threat intelligence indicators of compromise."""

    __tablename__ = "threat_indicators"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    type = Column(String(32), nullable=False, index=True)
    value = Column(String(1024), nullable=False, index=True)
    source = Column(String(256), nullable=False, default="")
    confidence = Column(Float, nullable=False, default=0.5)
    first_seen = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    last_seen = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    tags = Column(JSONB, nullable=False, default=list)
    related_ttps = Column(JSONB, nullable=False, default=list)

    __table_args__ = (
        Index("ix_ti_type_value", "type", "value"),
    )
