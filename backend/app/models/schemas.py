"""Pydantic models for the ARGUS API layer."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class SeverityLevel(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class IOCType(str, Enum):
    ip = "ip"
    domain = "domain"
    hash = "hash"
    cve = "cve"
    malware = "malware"


class EntityType(str, Enum):
    ip = "ip"
    host = "host"
    user = "user"
    service = "service"


class KillChainPhase(str, Enum):
    recon = "recon"
    weaponize = "weaponize"
    deliver = "deliver"
    exploit = "exploit"
    install = "install"
    c2 = "c2"
    actions = "actions"


# ---------------------------------------------------------------------------
# OCSF Event
# ---------------------------------------------------------------------------

class OCSFEvent(BaseModel):
    """Open Cybersecurity Schema Framework compliant event."""
    id: UUID = Field(default_factory=uuid4)
    time: datetime = Field(default_factory=datetime.utcnow)
    severity_id: int = Field(ge=0, le=5, description="0=Unknown … 5=Fatal")
    type_uid: int = Field(description="Event type unique identifier")
    category_uid: int = Field(description="Event category UID")
    class_uid: int = Field(description="Event class UID")
    activity_id: int = Field(description="Activity identifier")
    status: str = "new"
    src_ip: str
    dst_ip: str
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: str = "TCP"
    metadata: dict[str, Any] = Field(default_factory=dict)
    observables: list[dict[str, Any]] = Field(default_factory=list)

    model_config = {"json_schema_extra": {"example": {
        "severity_id": 3,
        "type_uid": 400201,
        "category_uid": 4,
        "class_uid": 4002,
        "activity_id": 1,
        "src_ip": "198.51.100.23",
        "dst_ip": "10.0.1.5",
        "src_port": 44312,
        "dst_port": 443,
        "protocol": "TCP",
    }}}


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------

class Alert(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    event_id: UUID
    severity: SeverityLevel
    title: str
    description: str
    mitre_tactic: str = ""
    mitre_technique: str = ""
    confidence: float = Field(ge=0.0, le=1.0)
    shap_values: dict[str, float] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_ip: str = ""
    dest_ip: str = ""
    kill_chain_phase: KillChainPhase = KillChainPhase.recon


class AlertListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    alerts: list[Alert]


# ---------------------------------------------------------------------------
# Threat Intelligence IOC
# ---------------------------------------------------------------------------

class ThreatIntelIOC(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    type: IOCType
    value: str
    source: str = ""
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    tags: list[str] = Field(default_factory=list)
    related_ttps: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Network / Graph
# ---------------------------------------------------------------------------

class NetworkEntity(BaseModel):
    id: str
    type: EntityType
    name: str
    properties: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = Field(ge=0.0, le=100.0, default=0.0)


class NetworkEdge(BaseModel):
    source: str
    target: str
    label: str = ""
    weight: float = 1.0


class NetworkTopology(BaseModel):
    nodes: list[NetworkEntity]
    edges: list[NetworkEdge]


# ---------------------------------------------------------------------------
# ATT&CK
# ---------------------------------------------------------------------------

class AttackTechnique(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    technique_id: str = Field(description="E.g. T1059")
    name: str
    tactic: str
    description: str = ""
    detection_count: int = 0
    severity: SeverityLevel = SeverityLevel.medium


# ---------------------------------------------------------------------------
# Kill Chain
# ---------------------------------------------------------------------------

class KillChainEvent(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    alert_id: UUID
    phase: KillChainPhase
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    description: str = ""


# ---------------------------------------------------------------------------
# Dashboard Stats
# ---------------------------------------------------------------------------

class ThreatOrigin(BaseModel):
    lat: float
    lon: float
    count: int
    country: str


class DashboardStats(BaseModel):
    total_events: int = 0
    active_alerts: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    events_per_second: float = 0.0
    top_attack_types: list[str] = Field(default_factory=list)
    threat_origins: list[ThreatOrigin] = Field(default_factory=list)
