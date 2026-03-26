"""API routes for the ARGUS platform."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from app.models.schemas import (
    Alert,
    AlertListResponse,
    AttackTechnique,
    DashboardStats,
    KillChainEvent,
    KillChainPhase,
    NetworkEdge,
    NetworkEntity,
    NetworkTopology,
    OCSFEvent,
    SeverityLevel,
    ThreatIntelIOC,
    IOCType,
    EntityType,
    ThreatOrigin,
)
from app.services.threat_feed import threat_feed
from app.services.websocket_manager import manager

router = APIRouter(prefix="/api", tags=["ARGUS API"])


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@router.get("/health")
async def health_check():
    return {
        "status": "operational",
        "service": "ARGUS",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": {
            "api": "healthy",
            "threat_feed": "active" if threat_feed._running else "inactive",
            "websocket_clients": manager.active_connections,
        },
    }


# ---------------------------------------------------------------------------
# Dashboard Stats
# ---------------------------------------------------------------------------

@router.get("/stats", response_model=DashboardStats)
async def get_stats():
    return threat_feed.get_dashboard_stats()


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

@router.get("/alerts", response_model=AlertListResponse)
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: Optional[str] = Query(None),
):
    alerts = threat_feed.alerts
    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity]

    total = len(alerts)
    start = (page - 1) * page_size
    end = start + page_size
    page_alerts = list(reversed(alerts))[start:end]

    return AlertListResponse(
        total=total,
        page=page,
        page_size=page_size,
        alerts=[Alert(**a) for a in page_alerts],
    )


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: str):
    for a in threat_feed.alerts:
        if str(a.get("id")) == alert_id:
            return a
    return {"error": "Alert not found"}


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

@router.get("/events")
async def list_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    events = threat_feed.events
    total = len(events)
    start = (page - 1) * page_size
    end = start + page_size
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "events": list(reversed(events))[start:end],
    }


# ---------------------------------------------------------------------------
# ATT&CK Matrix
# ---------------------------------------------------------------------------

_ATTACK_MATRIX_DATA: list[dict] = [
    # Reconnaissance
    {"technique_id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance", "detection_count": 0},
    {"technique_id": "T1592", "name": "Gather Victim Host Info", "tactic": "Reconnaissance", "detection_count": 0},
    {"technique_id": "T1589", "name": "Gather Victim Identity Info", "tactic": "Reconnaissance", "detection_count": 0},
    # Initial Access
    {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "detection_count": 0},
    {"technique_id": "T1566", "name": "Phishing", "tactic": "Initial Access", "detection_count": 0},
    {"technique_id": "T1133", "name": "External Remote Services", "tactic": "Initial Access", "detection_count": 0},
    # Execution
    {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution", "detection_count": 0},
    {"technique_id": "T1204", "name": "User Execution", "tactic": "Execution", "detection_count": 0},
    {"technique_id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution", "detection_count": 0},
    # Persistence
    {"technique_id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence", "detection_count": 0},
    {"technique_id": "T1053", "name": "Scheduled Task/Job", "tactic": "Persistence", "detection_count": 0},
    {"technique_id": "T1136", "name": "Create Account", "tactic": "Persistence", "detection_count": 0},
    # Privilege Escalation
    {"technique_id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "detection_count": 0},
    {"technique_id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation", "detection_count": 0},
    # Defense Evasion
    {"technique_id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion", "detection_count": 0},
    {"technique_id": "T1036", "name": "Masquerading", "tactic": "Defense Evasion", "detection_count": 0},
    {"technique_id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "detection_count": 0},
    # Credential Access
    {"technique_id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "detection_count": 0},
    {"technique_id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access", "detection_count": 0},
    {"technique_id": "T1558", "name": "Steal or Forge Kerberos Tickets", "tactic": "Credential Access", "detection_count": 0},
    # Discovery
    {"technique_id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery", "detection_count": 0},
    {"technique_id": "T1082", "name": "System Information Discovery", "tactic": "Discovery", "detection_count": 0},
    {"technique_id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery", "detection_count": 0},
    # Lateral Movement
    {"technique_id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement", "detection_count": 0},
    {"technique_id": "T1570", "name": "Lateral Tool Transfer", "tactic": "Lateral Movement", "detection_count": 0},
    {"technique_id": "T1563", "name": "Remote Service Session Hijacking", "tactic": "Lateral Movement", "detection_count": 0},
    # Collection
    {"technique_id": "T1005", "name": "Data from Local System", "tactic": "Collection", "detection_count": 0},
    {"technique_id": "T1039", "name": "Data from Network Shared Drive", "tactic": "Collection", "detection_count": 0},
    # Command and Control
    {"technique_id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control", "detection_count": 0},
    {"technique_id": "T1572", "name": "Protocol Tunneling", "tactic": "Command and Control", "detection_count": 0},
    {"technique_id": "T1573", "name": "Encrypted Channel", "tactic": "Command and Control", "detection_count": 0},
    # Exfiltration
    {"technique_id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "detection_count": 0},
    {"technique_id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "detection_count": 0},
    # Impact
    {"technique_id": "T1498", "name": "Network Denial of Service", "tactic": "Impact", "detection_count": 0},
    {"technique_id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "detection_count": 0},
    {"technique_id": "T1489", "name": "Service Stop", "tactic": "Impact", "detection_count": 0},
]


@router.get("/attack-matrix")
async def get_attack_matrix():
    technique_counts: dict[str, int] = {}
    for alert in threat_feed.alerts:
        tech = alert.get("mitre_technique", "")
        if tech:
            technique_counts[tech] = technique_counts.get(tech, 0) + 1

    result = []
    for t in _ATTACK_MATRIX_DATA:
        entry = dict(t)
        entry["detection_count"] = technique_counts.get(t["technique_id"], 0)
        if entry["detection_count"] > 10:
            entry["severity"] = "critical"
        elif entry["detection_count"] > 5:
            entry["severity"] = "high"
        elif entry["detection_count"] > 0:
            entry["severity"] = "medium"
        else:
            entry["severity"] = "low"
        result.append(entry)
    return {"techniques": result}


# ---------------------------------------------------------------------------
# Kill Chain
# ---------------------------------------------------------------------------

@router.get("/kill-chain")
async def get_kill_chain():
    phase_counts: dict[str, int] = {}
    for kc in threat_feed.kill_chain_events:
        phase = kc.get("phase", "recon")
        phase_counts[phase] = phase_counts.get(phase, 0) + 1

    phases = [
        {"phase": "recon", "label": "Reconnaissance", "count": phase_counts.get("recon", 0)},
        {"phase": "weaponize", "label": "Weaponization", "count": phase_counts.get("weaponize", 0)},
        {"phase": "deliver", "label": "Delivery", "count": phase_counts.get("deliver", 0)},
        {"phase": "exploit", "label": "Exploitation", "count": phase_counts.get("exploit", 0)},
        {"phase": "install", "label": "Installation", "count": phase_counts.get("install", 0)},
        {"phase": "c2", "label": "Command & Control", "count": phase_counts.get("c2", 0)},
        {"phase": "actions", "label": "Actions on Objectives", "count": phase_counts.get("actions", 0)},
    ]
    recent = list(reversed(threat_feed.kill_chain_events[-50:]))
    return {"phases": phases, "recent_events": recent}


# ---------------------------------------------------------------------------
# Network Topology
# ---------------------------------------------------------------------------

@router.get("/network/topology", response_model=NetworkTopology)
async def get_network_topology():
    nodes = [
        NetworkEntity(id="fw-01", type=EntityType.service, name="Firewall-01", risk_score=15.0, properties={"role": "perimeter"}),
        NetworkEntity(id="ids-01", type=EntityType.service, name="IDS-Sensor-01", risk_score=10.0, properties={"role": "detection"}),
        NetworkEntity(id="web-01", type=EntityType.host, name="Web-Server-01", risk_score=45.0, properties={"os": "Ubuntu 22.04"}),
        NetworkEntity(id="web-02", type=EntityType.host, name="Web-Server-02", risk_score=30.0, properties={"os": "Ubuntu 22.04"}),
        NetworkEntity(id="db-01", type=EntityType.host, name="DB-Primary", risk_score=55.0, properties={"os": "RHEL 9", "service": "PostgreSQL"}),
        NetworkEntity(id="db-02", type=EntityType.host, name="DB-Replica", risk_score=25.0, properties={"os": "RHEL 9", "service": "PostgreSQL"}),
        NetworkEntity(id="app-01", type=EntityType.host, name="App-Server-01", risk_score=40.0, properties={"os": "Ubuntu 22.04"}),
        NetworkEntity(id="app-02", type=EntityType.host, name="App-Server-02", risk_score=35.0, properties={"os": "Ubuntu 22.04"}),
        NetworkEntity(id="dc-01", type=EntityType.host, name="Domain-Controller", risk_score=70.0, properties={"os": "Windows Server 2022"}),
        NetworkEntity(id="vpn-01", type=EntityType.service, name="VPN-Gateway", risk_score=20.0, properties={"role": "access"}),
        NetworkEntity(id="mail-01", type=EntityType.host, name="Mail-Server", risk_score=50.0, properties={"os": "Ubuntu 22.04"}),
        NetworkEntity(id="user-admin", type=EntityType.user, name="admin@corp.local", risk_score=65.0, properties={"role": "admin"}),
        NetworkEntity(id="user-analyst", type=EntityType.user, name="analyst@corp.local", risk_score=20.0, properties={"role": "analyst"}),
        NetworkEntity(id="attacker-1", type=EntityType.ip, name="223.71.167.42", risk_score=95.0, properties={"country": "China", "reputation": "malicious"}),
        NetworkEntity(id="attacker-2", type=EntityType.ip, name="5.188.62.15", risk_score=90.0, properties={"country": "Russia", "reputation": "malicious"}),
        NetworkEntity(id="dns-01", type=EntityType.service, name="DNS-Server", risk_score=30.0, properties={"role": "infrastructure"}),
        NetworkEntity(id="proxy-01", type=EntityType.service, name="Proxy-Server", risk_score=25.0, properties={"role": "egress"}),
        NetworkEntity(id="siem-01", type=EntityType.service, name="SIEM-Collector", risk_score=10.0, properties={"role": "monitoring"}),
    ]
    edges = [
        NetworkEdge(source="attacker-1", target="fw-01", label="inbound scan", weight=3.0),
        NetworkEdge(source="attacker-2", target="vpn-01", label="brute force", weight=4.0),
        NetworkEdge(source="fw-01", target="ids-01", label="mirror traffic", weight=1.0),
        NetworkEdge(source="fw-01", target="web-01", label="HTTPS", weight=2.0),
        NetworkEdge(source="fw-01", target="web-02", label="HTTPS", weight=1.5),
        NetworkEdge(source="fw-01", target="mail-01", label="SMTP", weight=1.0),
        NetworkEdge(source="web-01", target="app-01", label="API call", weight=2.0),
        NetworkEdge(source="web-02", target="app-02", label="API call", weight=1.5),
        NetworkEdge(source="app-01", target="db-01", label="SQL query", weight=2.5),
        NetworkEdge(source="app-02", target="db-01", label="SQL query", weight=2.0),
        NetworkEdge(source="db-01", target="db-02", label="replication", weight=1.0),
        NetworkEdge(source="vpn-01", target="dc-01", label="LDAP auth", weight=2.0),
        NetworkEdge(source="user-admin", target="dc-01", label="RDP", weight=3.0),
        NetworkEdge(source="user-analyst", target="siem-01", label="dashboard", weight=1.0),
        NetworkEdge(source="dc-01", target="app-01", label="lateral SMB", weight=4.0),
        NetworkEdge(source="ids-01", target="siem-01", label="alert feed", weight=1.0),
        NetworkEdge(source="proxy-01", target="dns-01", label="DNS lookup", weight=1.0),
        NetworkEdge(source="web-01", target="proxy-01", label="outbound", weight=1.5),
        NetworkEdge(source="mail-01", target="dns-01", label="MX lookup", weight=1.0),
    ]
    return NetworkTopology(nodes=nodes, edges=edges)


# ---------------------------------------------------------------------------
# Threat Intel IOCs
# ---------------------------------------------------------------------------

@router.get("/threat-intel/iocs")
async def get_iocs():
    iocs = [
        ThreatIntelIOC(type=IOCType.ip, value="223.71.167.42", source="ARGUS Threat Feed", confidence=0.95, tags=["apt", "china"], related_ttps=["T1595", "T1071"]),
        ThreatIntelIOC(type=IOCType.ip, value="5.188.62.15", source="ARGUS Threat Feed", confidence=0.92, tags=["apt28", "russia"], related_ttps=["T1110", "T1021"]),
        ThreatIntelIOC(type=IOCType.domain, value="c2.malware-cdn.xyz", source="Threat Intel Report", confidence=0.88, tags=["c2", "cobalt-strike"], related_ttps=["T1071", "T1573"]),
        ThreatIntelIOC(type=IOCType.domain, value="exfil.darknet-proxy.io", source="NLP Extraction", confidence=0.85, tags=["exfiltration"], related_ttps=["T1041"]),
        ThreatIntelIOC(type=IOCType.hash, value="a1b2c3d4e5f67890abcdef1234567890abcdef12", source="VirusTotal", confidence=0.97, tags=["trojan", "apt29"], related_ttps=["T1204"]),
        ThreatIntelIOC(type=IOCType.hash, value="e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4", source="Malware Analysis", confidence=0.91, tags=["ransomware"], related_ttps=["T1486"]),
        ThreatIntelIOC(type=IOCType.cve, value="CVE-2024-3400", source="NVD", confidence=0.99, tags=["palo-alto", "critical"], related_ttps=["T1190"]),
        ThreatIntelIOC(type=IOCType.cve, value="CVE-2024-21887", source="NVD", confidence=0.98, tags=["ivanti", "critical"], related_ttps=["T1190", "T1133"]),
        ThreatIntelIOC(type=IOCType.malware, value="SUNBURST", source="Threat Report", confidence=0.96, tags=["apt29", "supply-chain"], related_ttps=["T1195", "T1071"]),
        ThreatIntelIOC(type=IOCType.malware, value="Cobalt Strike Beacon", source="Network Analysis", confidence=0.93, tags=["c2", "post-exploitation"], related_ttps=["T1071", "T1059"]),
    ]
    return {"iocs": [i.model_dump(mode="json") for i in iocs]}


# ---------------------------------------------------------------------------
# Threat Origins (for 3D Globe)
# ---------------------------------------------------------------------------

@router.get("/threat-origins")
async def get_threat_origins():
    stats = threat_feed.get_dashboard_stats()
    if stats.threat_origins:
        return {"origins": [o.model_dump() for o in stats.threat_origins]}
    # Fallback static data
    return {
        "origins": [
            {"lat": 39.9042, "lon": 116.4074, "count": 342, "country": "China"},
            {"lat": 55.7558, "lon": 37.6173, "count": 276, "country": "Russia"},
            {"lat": 35.6892, "lon": 51.3890, "count": 128, "country": "Iran"},
            {"lat": 39.0392, "lon": 125.7625, "count": 95, "country": "North Korea"},
            {"lat": -15.7975, "lon": -47.8919, "count": 67, "country": "Brazil"},
            {"lat": 9.0579, "lon": 7.4951, "count": 54, "country": "Nigeria"},
        ]
    }


# ---------------------------------------------------------------------------
# WebSocket Endpoints
# ---------------------------------------------------------------------------

@router.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    await manager.connect(websocket, "events")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, "events")


@router.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    await manager.connect(websocket, "alerts")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, "alerts")


@router.websocket("/ws/stats")
async def ws_stats(websocket: WebSocket):
    await manager.connect(websocket, "stats")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, "stats")
