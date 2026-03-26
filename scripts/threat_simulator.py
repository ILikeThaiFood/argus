#!/usr/bin/env python3
"""Real-time APT threat simulation for the ARGUS platform.

Simulates APT campaigns that progress through the cyber kill chain,
publishing events to Redis streams for real-time consumption.

Usage:
    python scripts/threat_simulator.py --profile apt29 --speed 1.0
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import random
import time
import uuid
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# APT Campaign Profiles
APT_PROFILES = {
    "apt29": {
        "name": "APT29 (Cozy Bear)",
        "origin": {"country": "Russia", "lat": 55.7558, "lon": 37.6173, "prefix": "5.188"},
        "kill_chain": [
            {"phase": "recon", "technique": "T1595", "name": "Active Scanning", "duration": (10, 30), "events": (5, 15)},
            {"phase": "deliver", "technique": "T1566", "name": "Spear Phishing", "duration": (5, 15), "events": (2, 5)},
            {"phase": "exploit", "technique": "T1190", "name": "Exploit Public App", "duration": (3, 10), "events": (1, 3)},
            {"phase": "install", "technique": "T1547", "name": "Persistence via Autostart", "duration": (5, 15), "events": (2, 5)},
            {"phase": "c2", "technique": "T1071", "name": "C2 via HTTPS", "duration": (20, 60), "events": (10, 30)},
            {"phase": "install", "technique": "T1021", "name": "Lateral Movement via SMB", "duration": (10, 30), "events": (5, 10)},
            {"phase": "actions", "technique": "T1041", "name": "Data Exfiltration", "duration": (10, 20), "events": (3, 8)},
        ],
    },
    "apt28": {
        "name": "APT28 (Fancy Bear)",
        "origin": {"country": "Russia", "lat": 55.7558, "lon": 37.6173, "prefix": "77.88"},
        "kill_chain": [
            {"phase": "recon", "technique": "T1046", "name": "Network Service Discovery", "duration": (15, 40), "events": (8, 20)},
            {"phase": "deliver", "technique": "T1204", "name": "Malware via User Execution", "duration": (5, 10), "events": (2, 4)},
            {"phase": "exploit", "technique": "T1068", "name": "Privilege Escalation", "duration": (5, 15), "events": (2, 5)},
            {"phase": "c2", "technique": "T1572", "name": "DNS Tunneling C2", "duration": (30, 90), "events": (15, 40)},
            {"phase": "actions", "technique": "T1486", "name": "Ransomware Deployment", "duration": (5, 15), "events": (3, 8)},
        ],
    },
    "lazarus": {
        "name": "Lazarus Group",
        "origin": {"country": "North Korea", "lat": 39.0392, "lon": 125.7625, "prefix": "175.45"},
        "kill_chain": [
            {"phase": "recon", "technique": "T1595", "name": "Active Scanning", "duration": (20, 50), "events": (10, 25)},
            {"phase": "deliver", "technique": "T1195", "name": "Supply Chain Compromise", "duration": (10, 20), "events": (3, 6)},
            {"phase": "exploit", "technique": "T1059", "name": "PowerShell Execution", "duration": (5, 15), "events": (3, 8)},
            {"phase": "c2", "technique": "T1573", "name": "Encrypted C2 Channel", "duration": (30, 60), "events": (10, 25)},
            {"phase": "actions", "technique": "T1041", "name": "Data Exfil via C2", "duration": (15, 30), "events": (5, 12)},
        ],
    },
}

INTERNAL_TARGETS = [
    "10.0.1.5", "10.0.1.10", "10.0.2.5", "10.0.2.50",
    "10.0.3.8", "10.0.3.25", "172.16.0.10", "172.16.1.5",
]

SEVERITY_MAP = {
    "recon": (1, 3),
    "deliver": (3, 4),
    "exploit": (3, 5),
    "install": (3, 5),
    "c2": (4, 5),
    "actions": (4, 5),
}


def generate_campaign_event(phase: dict, origin: dict, speed: float) -> dict:
    src_prefix = origin["prefix"]
    src_ip = f"{src_prefix}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    dst_ip = random.choice(INTERNAL_TARGETS)
    sev_range = SEVERITY_MAP.get(phase["phase"], (2, 4))

    return {
        "id": str(uuid.uuid4()),
        "time": datetime.now(timezone.utc).isoformat(),
        "severity_id": random.randint(*sev_range),
        "type_uid": 400201,
        "category_uid": 4,
        "class_uid": 4002,
        "activity_id": 1,
        "status": "new",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([22, 80, 443, 445, 3389, 4444, 8080]),
        "protocol": "TCP",
        "metadata": {
            "attack_type": phase["name"],
            "origin_country": origin["country"],
            "origin_lat": origin["lat"],
            "origin_lon": origin["lon"],
            "mitre_technique": phase["technique"],
            "kill_chain_phase": phase["phase"],
            "campaign": origin.get("name", "Unknown APT"),
        },
    }


async def run_simulation(profile_name: str, speed: float, redis_url: str | None):
    profile = APT_PROFILES.get(profile_name)
    if not profile:
        logger.error("Unknown profile: %s. Available: %s", profile_name, list(APT_PROFILES.keys()))
        return

    redis = None
    if redis_url:
        try:
            import redis.asyncio as aioredis
            redis = aioredis.from_url(redis_url, decode_responses=True)
            await redis.ping()
            logger.info("Connected to Redis at %s", redis_url)
        except Exception as exc:
            logger.warning("Redis not available: %s. Events will be printed to stdout.", exc)
            redis = None

    logger.info("Starting simulation: %s", profile["name"])
    logger.info("Kill chain phases: %d", len(profile["kill_chain"]))

    for step in profile["kill_chain"]:
        num_events = random.randint(*step["events"])
        phase_duration = random.uniform(*step["duration"]) / speed

        logger.info(
            "[%s] Phase: %s | Technique: %s | Events: %d | Duration: %.1fs",
            profile["name"], step["phase"], step["technique"], num_events, phase_duration,
        )

        for i in range(num_events):
            event = generate_campaign_event(step, profile["origin"], speed)
            event["metadata"]["campaign"] = profile["name"]

            if redis:
                await redis.xadd("argus:events", {"payload": json.dumps(event, default=str)}, maxlen=5000)
            else:
                print(json.dumps(event, default=str))

            delay = phase_duration / num_events
            await asyncio.sleep(delay)

    logger.info("Simulation complete: %s", profile["name"])
    if redis:
        await redis.close()


def main():
    parser = argparse.ArgumentParser(description="ARGUS APT threat simulator")
    parser.add_argument("--profile", type=str, default="apt29", choices=list(APT_PROFILES.keys()))
    parser.add_argument("--speed", type=float, default=1.0, help="Simulation speed multiplier")
    parser.add_argument("--redis-url", type=str, default="redis://localhost:6379/0")
    parser.add_argument("--no-redis", action="store_true", help="Print events to stdout instead of Redis")
    args = parser.parse_args()

    redis_url = None if args.no_redis else args.redis_url
    asyncio.run(run_simulation(args.profile, args.speed, redis_url))


if __name__ == "__main__":
    main()
