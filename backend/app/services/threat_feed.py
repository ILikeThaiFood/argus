"""Synthetic threat event generator for the ARGUS platform.

Produces realistic OCSF-compliant security events covering a range of attack
scenarios so the frontend always has data to render, even without live
ingestion sources.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from app.models.schemas import (
    Alert,
    DashboardStats,
    KillChainPhase,
    OCSFEvent,
    SeverityLevel,
    ThreatOrigin,
)
from app.services.websocket_manager import manager

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# GeoIP look-up table for threat origins
# ---------------------------------------------------------------------------
THREAT_ORIGINS: list[dict[str, Any]] = [
    {"country": "China", "lat": 39.9042, "lon": 116.4074, "weight": 30},
    {"country": "Russia", "lat": 55.7558, "lon": 37.6173, "weight": 25},
    {"country": "Iran", "lat": 35.6892, "lon": 51.3890, "weight": 12},
    {"country": "North Korea", "lat": 39.0392, "lon": 125.7625, "weight": 10},
    {"country": "Brazil", "lat": -15.7975, "lon": -47.8919, "weight": 6},
    {"country": "Nigeria", "lat": 9.0579, "lon": 7.4951, "weight": 5},
    {"country": "Vietnam", "lat": 21.0278, "lon": 105.8342, "weight": 4},
    {"country": "India", "lat": 28.6139, "lon": 77.2090, "weight": 4},
    {"country": "Romania", "lat": 44.4268, "lon": 26.1025, "weight": 3},
    {"country": "Ukraine", "lat": 50.4501, "lon": 30.5234, "weight": 2},
    {"country": "Turkey", "lat": 39.9334, "lon": 32.8597, "weight": 2},
    {"country": "Indonesia", "lat": -6.2088, "lon": 106.8456, "weight": 2},
]

# Weighted list used by random.choice
_ORIGIN_POOL: list[dict[str, Any]] = []
for _o in THREAT_ORIGINS:
    _ORIGIN_POOL.extend([_o] * _o["weight"])

# ---------------------------------------------------------------------------
# Realistic external source IP ranges per country
# ---------------------------------------------------------------------------
_COUNTRY_IP_PREFIXES: dict[str, list[str]] = {
    "China": ["223.71", "218.92", "61.160", "124.89", "114.67"],
    "Russia": ["5.188", "77.88", "195.54", "91.240", "185.220"],
    "Iran": ["5.160", "2.144", "185.141", "91.92", "37.255"],
    "North Korea": ["175.45", "210.52"],
    "Brazil": ["177.54", "191.96", "200.147", "189.112"],
    "Nigeria": ["41.190", "102.89", "197.210"],
    "Vietnam": ["14.161", "113.160", "203.113"],
    "India": ["103.100", "117.239", "223.30"],
    "Romania": ["5.2", "79.112", "188.25"],
    "Ukraine": ["31.43", "46.211", "91.196"],
    "Turkey": ["5.11", "78.186", "88.255"],
    "Indonesia": ["36.91", "103.28", "180.241"],
}

# Internal network IPs
_INTERNAL_IPS = [
    "10.0.1.5", "10.0.1.10", "10.0.1.15", "10.0.1.20",
    "10.0.2.5", "10.0.2.10", "10.0.2.50", "10.0.2.100",
    "10.0.3.8", "10.0.3.12", "10.0.3.25", "10.0.3.200",
    "172.16.0.10", "172.16.0.20", "172.16.1.5", "172.16.1.100",
    "192.168.1.10", "192.168.1.50", "192.168.2.5", "192.168.10.1",
]

# ---------------------------------------------------------------------------
# Attack type definitions
# ---------------------------------------------------------------------------

class AttackType:
    """Encapsulates the parameters for a synthetic attack scenario."""

    def __init__(
        self,
        name: str,
        category_uid: int,
        class_uid: int,
        type_uid: int,
        activity_id: int,
        mitre_tactic: str,
        mitre_technique: str,
        kill_chain_phase: KillChainPhase,
        severity_range: tuple[int, int],
        dst_ports: list[int],
        protocol: str = "TCP",
        description_template: str = "",
    ) -> None:
        self.name = name
        self.category_uid = category_uid
        self.class_uid = class_uid
        self.type_uid = type_uid
        self.activity_id = activity_id
        self.mitre_tactic = mitre_tactic
        self.mitre_technique = mitre_technique
        self.kill_chain_phase = kill_chain_phase
        self.severity_range = severity_range
        self.dst_ports = dst_ports
        self.protocol = protocol
        self.description_template = description_template


ATTACK_TYPES: list[AttackType] = [
    AttackType(
        name="DDoS",
        category_uid=4, class_uid=4002, type_uid=400201, activity_id=1,
        mitre_tactic="Impact", mitre_technique="T1498",
        kill_chain_phase=KillChainPhase.actions,
        severity_range=(3, 5), dst_ports=[80, 443, 8080, 8443],
        description_template="Volumetric DDoS traffic detected from {src} targeting {dst}:{port}",
    ),
    AttackType(
        name="Port Scan",
        category_uid=4, class_uid=4001, type_uid=400101, activity_id=2,
        mitre_tactic="Discovery", mitre_technique="T1046",
        kill_chain_phase=KillChainPhase.recon,
        severity_range=(1, 3), dst_ports=[22, 23, 80, 443, 445, 3389, 8080],
        description_template="Sequential port scan detected from {src} against {dst}",
    ),
    AttackType(
        name="Brute Force",
        category_uid=3, class_uid=3002, type_uid=300201, activity_id=1,
        mitre_tactic="Credential Access", mitre_technique="T1110",
        kill_chain_phase=KillChainPhase.exploit,
        severity_range=(3, 4), dst_ports=[22, 3389, 445, 5432, 3306],
        description_template="Brute-force authentication attempts from {src} on {dst}:{port}",
    ),
    AttackType(
        name="C2 Communication",
        category_uid=4, class_uid=4003, type_uid=400301, activity_id=3,
        mitre_tactic="Command and Control", mitre_technique="T1071",
        kill_chain_phase=KillChainPhase.c2,
        severity_range=(4, 5), dst_ports=[443, 8443, 4444, 1337, 9001],
        description_template="Suspected C2 beacon from {src} to external host {dst}:{port}",
    ),
    AttackType(
        name="Lateral Movement",
        category_uid=2, class_uid=2001, type_uid=200101, activity_id=4,
        mitre_tactic="Lateral Movement", mitre_technique="T1021",
        kill_chain_phase=KillChainPhase.install,
        severity_range=(3, 5), dst_ports=[445, 135, 5985, 22, 3389],
        protocol="TCP",
        description_template="Lateral movement via {proto} from {src} to internal host {dst}:{port}",
    ),
    AttackType(
        name="Data Exfiltration",
        category_uid=4, class_uid=4004, type_uid=400401, activity_id=5,
        mitre_tactic="Exfiltration", mitre_technique="T1041",
        kill_chain_phase=KillChainPhase.actions,
        severity_range=(4, 5), dst_ports=[443, 53, 8080, 993],
        description_template="Anomalous outbound data transfer from {src} to {dst}:{port} ({size} bytes)",
    ),
    AttackType(
        name="Malware Delivery",
        category_uid=1, class_uid=1002, type_uid=100201, activity_id=6,
        mitre_tactic="Execution", mitre_technique="T1204",
        kill_chain_phase=KillChainPhase.deliver,
        severity_range=(3, 5), dst_ports=[80, 443, 25, 587],
        description_template="Malware payload delivery detected from {src} to {dst}:{port}",
    ),
    AttackType(
        name="DNS Tunneling",
        category_uid=4, class_uid=4003, type_uid=400302, activity_id=7,
        mitre_tactic="Command and Control", mitre_technique="T1572",
        kill_chain_phase=KillChainPhase.c2,
        severity_range=(3, 4), dst_ports=[53], protocol="UDP",
        description_template="DNS tunneling detected: {src} querying suspicious domains via {dst}:53",
    ),
    AttackType(
        name="Privilege Escalation",
        category_uid=3, class_uid=3003, type_uid=300301, activity_id=8,
        mitre_tactic="Privilege Escalation", mitre_technique="T1068",
        kill_chain_phase=KillChainPhase.exploit,
        severity_range=(4, 5), dst_ports=[445, 135, 139],
        description_template="Privilege escalation attempt detected on {dst} from {src}",
    ),
    AttackType(
        name="Reconnaissance",
        category_uid=4, class_uid=4001, type_uid=400102, activity_id=9,
        mitre_tactic="Reconnaissance", mitre_technique="T1595",
        kill_chain_phase=KillChainPhase.recon,
        severity_range=(1, 2), dst_ports=[80, 443, 8080, 8443],
        description_template="Active reconnaissance scan from {src} targeting {dst}",
    ),
]


def _random_external_ip(country: str | None = None) -> str:
    """Generate a plausible external IP for a given country."""
    if country and country in _COUNTRY_IP_PREFIXES:
        prefix = random.choice(_COUNTRY_IP_PREFIXES[country])
    else:
        prefix = random.choice(
            [p for prefixes in _COUNTRY_IP_PREFIXES.values() for p in prefixes]
        )
    return f"{prefix}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def _random_internal_ip() -> str:
    return random.choice(_INTERNAL_IPS)


# ---------------------------------------------------------------------------
# Threat Feed Service
# ---------------------------------------------------------------------------

class ThreatFeedService:
    """Generates synthetic security events and publishes them to
    WebSocket channels and optionally Redis streams."""

    def __init__(self) -> None:
        self._running = False
        self._task: asyncio.Task | None = None

        # Cumulative dashboard state
        self._total_events: int = 0
        self._alert_counts: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0,
        }
        self._events_window: list[float] = []  # timestamps for EPS calc
        self._attack_type_counts: dict[str, int] = {}
        self._origin_counts: dict[str, int] = {}

        # In-memory alert & event stores (bounded)
        self.alerts: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.kill_chain_events: list[dict[str, Any]] = []
        self._max_store = 2000

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("ThreatFeedService started.")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("ThreatFeedService stopped.")

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def _run_loop(self) -> None:
        """Continuously generate events at a variable rate."""
        # Seed some initial data so the dashboard is never empty
        await self._seed_initial_data()

        while self._running:
            try:
                # Variable delay: 0.3-2s between events
                delay = random.uniform(0.3, 2.0)
                await asyncio.sleep(delay)
                await self._generate_and_publish()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in threat feed loop")
                await asyncio.sleep(1)

    async def _seed_initial_data(self) -> None:
        """Generate a burst of historical events so the UI has data on load."""
        now = datetime.now(timezone.utc)
        for i in range(50):
            past_time = now - timedelta(seconds=random.randint(10, 600))
            await self._generate_and_publish(override_time=past_time)
        logger.info("Seeded %d initial events.", len(self.events))

    # ------------------------------------------------------------------
    # Event generation
    # ------------------------------------------------------------------

    async def _generate_and_publish(
        self, override_time: datetime | None = None,
    ) -> None:
        origin = random.choice(_ORIGIN_POOL)
        attack = random.choice(ATTACK_TYPES)

        now = override_time or datetime.now(timezone.utc)
        src_ip = _random_external_ip(origin["country"])
        dst_ip = _random_internal_ip()
        dst_port = random.choice(attack.dst_ports)
        src_port = random.randint(1024, 65535)
        severity_id = random.randint(*attack.severity_range)

        event_id = uuid.uuid4()

        event = OCSFEvent(
            id=event_id,
            time=now,
            severity_id=severity_id,
            type_uid=attack.type_uid,
            category_uid=attack.category_uid,
            class_uid=attack.class_uid,
            activity_id=attack.activity_id,
            status="new",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=attack.protocol,
            metadata={
                "attack_type": attack.name,
                "origin_country": origin["country"],
                "origin_lat": origin["lat"],
                "origin_lon": origin["lon"],
                "mitre_tactic": attack.mitre_tactic,
                "mitre_technique": attack.mitre_technique,
            },
            observables=[
                {"type": "ip", "value": src_ip, "reputation": "malicious"},
                {"type": "ip", "value": dst_ip, "reputation": "internal"},
            ],
        )

        event_dict = event.model_dump(mode="json")
        self._store_event(event_dict)

        # Broadcast event via WebSocket
        await manager.broadcast_event(event_dict)

        # Publish to Redis stream if available
        await self._publish_to_redis("events", event_dict)

        # Track EPS
        ts = time.time()
        self._events_window.append(ts)
        # Keep only the last 60s
        cutoff = ts - 60
        self._events_window = [t for t in self._events_window if t > cutoff]

        self._total_events += 1

        # Track attack type
        self._attack_type_counts[attack.name] = (
            self._attack_type_counts.get(attack.name, 0) + 1
        )

        # Track origin
        self._origin_counts[origin["country"]] = (
            self._origin_counts.get(origin["country"], 0) + 1
        )

        # Generate alert for high-severity events
        if severity_id >= 3:
            await self._generate_alert(event, attack, origin, now)

        # Broadcast updated stats every event
        stats = self.get_dashboard_stats()
        await manager.broadcast_stats(stats.model_dump(mode="json"))

    async def _generate_alert(
        self,
        event: OCSFEvent,
        attack: AttackType,
        origin: dict[str, Any],
        now: datetime,
    ) -> None:
        severity_map = {5: "critical", 4: "high", 3: "medium"}
        severity_str = severity_map.get(event.severity_id, "low")

        description = attack.description_template.format(
            src=event.src_ip,
            dst=event.dst_ip,
            port=event.dst_port,
            proto=attack.protocol,
            size=random.randint(50_000, 50_000_000),
        )

        confidence = round(random.uniform(0.70, 0.99), 3)

        # Mock SHAP values
        shap_values = {
            "src_ip_reputation": round(random.uniform(0.1, 0.4), 4),
            "dst_port_anomaly": round(random.uniform(0.05, 0.3), 4),
            "packet_rate": round(random.uniform(0.02, 0.25), 4),
            "payload_entropy": round(random.uniform(0.01, 0.2), 4),
            "geo_risk_score": round(random.uniform(0.05, 0.35), 4),
            "protocol_anomaly": round(random.uniform(0.01, 0.15), 4),
            "time_of_day": round(random.uniform(-0.05, 0.1), 4),
            "connection_frequency": round(random.uniform(0.02, 0.2), 4),
        }

        alert = Alert(
            id=uuid.uuid4(),
            event_id=event.id,
            severity=SeverityLevel(severity_str),
            title=f"{attack.name} – {attack.mitre_technique}",
            description=description,
            mitre_tactic=attack.mitre_tactic,
            mitre_technique=attack.mitre_technique,
            confidence=confidence,
            shap_values=shap_values,
            timestamp=now,
            source_ip=event.src_ip,
            dest_ip=event.dst_ip,
            kill_chain_phase=attack.kill_chain_phase,
        )

        alert_dict = alert.model_dump(mode="json")
        self._store_alert(alert_dict)

        # Kill-chain event
        kc_event = {
            "id": str(uuid.uuid4()),
            "alert_id": str(alert.id),
            "phase": attack.kill_chain_phase.value,
            "timestamp": now.isoformat(),
            "description": description,
        }
        self.kill_chain_events.append(kc_event)
        if len(self.kill_chain_events) > self._max_store:
            self.kill_chain_events = self.kill_chain_events[-self._max_store:]

        self._alert_counts[severity_str] = (
            self._alert_counts.get(severity_str, 0) + 1
        )

        await manager.broadcast_alert(alert_dict)
        await self._publish_to_redis("alerts", alert_dict)

    # ------------------------------------------------------------------
    # In-memory stores
    # ------------------------------------------------------------------

    def _store_event(self, event_dict: dict[str, Any]) -> None:
        self.events.append(event_dict)
        if len(self.events) > self._max_store:
            self.events = self.events[-self._max_store:]

    def _store_alert(self, alert_dict: dict[str, Any]) -> None:
        self.alerts.append(alert_dict)
        if len(self.alerts) > self._max_store:
            self.alerts = self.alerts[-self._max_store:]

    # ------------------------------------------------------------------
    # Dashboard stats
    # ------------------------------------------------------------------

    def get_dashboard_stats(self) -> DashboardStats:
        eps = len(self._events_window) / 60.0 if self._events_window else 0.0

        top_attacks = sorted(
            self._attack_type_counts.items(), key=lambda x: x[1], reverse=True
        )[:10]

        threat_origins = [
            ThreatOrigin(
                lat=next(o["lat"] for o in THREAT_ORIGINS if o["country"] == country),
                lon=next(o["lon"] for o in THREAT_ORIGINS if o["country"] == country),
                count=count,
                country=country,
            )
            for country, count in sorted(
                self._origin_counts.items(), key=lambda x: x[1], reverse=True
            )[:12]
        ]

        return DashboardStats(
            total_events=self._total_events,
            active_alerts=len(self.alerts),
            critical_count=self._alert_counts.get("critical", 0),
            high_count=self._alert_counts.get("high", 0),
            medium_count=self._alert_counts.get("medium", 0),
            low_count=self._alert_counts.get("low", 0),
            events_per_second=round(eps, 2),
            top_attack_types=[name for name, _ in top_attacks],
            threat_origins=threat_origins,
        )

    # ------------------------------------------------------------------
    # Redis helper
    # ------------------------------------------------------------------

    @staticmethod
    async def _publish_to_redis(stream: str, data: dict[str, Any]) -> None:
        try:
            from app.core.database import get_redis
            redis = await get_redis()
            if redis is not None:
                import json
                await redis.xadd(
                    f"argus:{stream}",
                    {"payload": json.dumps(data, default=str)},
                    maxlen=5000,
                )
        except Exception:
            pass  # Redis is optional


# Singleton
threat_feed = ThreatFeedService()
