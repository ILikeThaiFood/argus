#!/usr/bin/env python3
"""Generate synthetic OCSF-compliant threat events for the ARGUS platform.

Usage:
    python scripts/generate_synthetic_data.py --events 100000 --duration 24h --output data/events.jsonl
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone

# OCSF Category/Class UIDs
NETWORK_ACTIVITY_CLASS = 4001
NETWORK_TRAFFIC_CLASS = 4002
DNS_ACTIVITY_CLASS = 4003
AUTH_CLASS = 3002

THREAT_ORIGINS = [
    {"country": "China", "lat": 39.9042, "lon": 116.4074, "weight": 30, "prefixes": ["223.71", "218.92", "61.160"]},
    {"country": "Russia", "lat": 55.7558, "lon": 37.6173, "weight": 25, "prefixes": ["5.188", "77.88", "195.54"]},
    {"country": "Iran", "lat": 35.6892, "lon": 51.389, "weight": 12, "prefixes": ["5.160", "2.144", "185.141"]},
    {"country": "North Korea", "lat": 39.0392, "lon": 125.7625, "weight": 10, "prefixes": ["175.45", "210.52"]},
    {"country": "Brazil", "lat": -15.7975, "lon": -47.8919, "weight": 6, "prefixes": ["177.54", "191.96"]},
    {"country": "Nigeria", "lat": 9.0579, "lon": 7.4951, "weight": 5, "prefixes": ["41.190", "102.89"]},
    {"country": "United States", "lat": 38.9072, "lon": -77.0369, "weight": 5, "prefixes": ["8.8", "1.1"]},
    {"country": "Germany", "lat": 52.52, "lon": 13.405, "weight": 4, "prefixes": ["46.101", "78.46"]},
    {"country": "Japan", "lat": 35.6762, "lon": 139.6503, "weight": 3, "prefixes": ["103.5", "210.130"]},
]

INTERNAL_IPS = [f"10.0.{s}.{h}" for s in range(1, 5) for h in [5, 10, 15, 20, 50, 100]]

ATTACK_PROFILES = [
    {"name": "DDoS", "severity": (3, 5), "class_uid": 4002, "ports": [80, 443, 8080], "mitre": "T1498", "tactic": "Impact", "phase": "actions", "benign": False},
    {"name": "Port Scan", "severity": (1, 3), "class_uid": 4001, "ports": [22, 23, 80, 443, 445, 3389], "mitre": "T1046", "tactic": "Discovery", "phase": "recon", "benign": False},
    {"name": "Brute Force", "severity": (3, 4), "class_uid": 3002, "ports": [22, 3389, 445], "mitre": "T1110", "tactic": "Credential Access", "phase": "exploit", "benign": False},
    {"name": "C2 Beacon", "severity": (4, 5), "class_uid": 4003, "ports": [443, 8443, 4444], "mitre": "T1071", "tactic": "Command and Control", "phase": "c2", "benign": False},
    {"name": "Lateral Movement", "severity": (3, 5), "class_uid": 4001, "ports": [445, 135, 5985], "mitre": "T1021", "tactic": "Lateral Movement", "phase": "install", "benign": False},
    {"name": "Data Exfiltration", "severity": (4, 5), "class_uid": 4002, "ports": [443, 53, 8080], "mitre": "T1041", "tactic": "Exfiltration", "phase": "actions", "benign": False},
    {"name": "Malware Download", "severity": (3, 5), "class_uid": 4002, "ports": [80, 443], "mitre": "T1204", "tactic": "Execution", "phase": "deliver", "benign": False},
    {"name": "Normal HTTP", "severity": (0, 1), "class_uid": 4002, "ports": [80, 443], "mitre": "", "tactic": "", "phase": "", "benign": True},
    {"name": "Normal DNS", "severity": (0, 0), "class_uid": 4003, "ports": [53], "mitre": "", "tactic": "", "phase": "", "benign": True},
    {"name": "Normal SSH", "severity": (0, 1), "class_uid": 4001, "ports": [22], "mitre": "", "tactic": "", "phase": "", "benign": True},
    {"name": "Normal SMTP", "severity": (0, 0), "class_uid": 4002, "ports": [25, 587], "mitre": "", "tactic": "", "phase": "", "benign": True},
]

ORIGIN_POOL = []
for o in THREAT_ORIGINS:
    ORIGIN_POOL.extend([o] * o["weight"])


def random_ip(origin: dict) -> str:
    prefix = random.choice(origin["prefixes"])
    return f"{prefix}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def generate_event(base_time: datetime, offset_seconds: float) -> dict:
    is_attack = random.random() > 0.80
    profiles = [p for p in ATTACK_PROFILES if p["benign"] != is_attack]
    profile = random.choice(profiles)
    origin = random.choice(ORIGIN_POOL)

    ts = base_time + timedelta(seconds=offset_seconds)
    src_ip = random_ip(origin)
    dst_ip = random.choice(INTERNAL_IPS)
    dst_port = random.choice(profile["ports"])

    event = {
        "id": str(uuid.uuid4()),
        "time": ts.isoformat(),
        "severity_id": random.randint(*profile["severity"]),
        "type_uid": profile["class_uid"] * 100 + random.randint(1, 9),
        "category_uid": profile["class_uid"] // 1000,
        "class_uid": profile["class_uid"],
        "activity_id": random.randint(1, 10),
        "status": "new",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(1024, 65535),
        "dst_port": dst_port,
        "protocol": "UDP" if dst_port == 53 else "TCP",
        "metadata": {
            "product": "ARGUS Synthetic Generator",
            "version": "1.0.0",
            "attack_type": profile["name"],
            "origin_country": origin["country"],
            "origin_lat": origin["lat"],
            "origin_lon": origin["lon"],
            "mitre_technique": profile["mitre"],
            "mitre_tactic": profile["tactic"],
            "kill_chain_phase": profile["phase"],
            "is_attack": not profile["benign"],
        },
        "observables": [
            {"type": "ip", "value": src_ip},
            {"type": "ip", "value": dst_ip},
            {"type": "port", "value": str(dst_port)},
        ],
    }
    return event


def parse_duration(duration_str: str) -> float:
    """Parse duration string like '24h', '30m', '7d' to seconds."""
    unit = duration_str[-1].lower()
    value = float(duration_str[:-1])
    if unit == "h":
        return value * 3600
    elif unit == "m":
        return value * 60
    elif unit == "d":
        return value * 86400
    elif unit == "s":
        return value
    return value * 3600


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic OCSF threat events")
    parser.add_argument("--events", type=int, default=10000, help="Number of events")
    parser.add_argument("--duration", type=str, default="24h", help="Time span (e.g., 24h, 7d)")
    parser.add_argument("--output", type=str, default="-", help="Output file (- for stdout)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    random.seed(args.seed)
    duration_secs = parse_duration(args.duration)
    base_time = datetime.now(timezone.utc) - timedelta(seconds=duration_secs)

    out = sys.stdout if args.output == "-" else open(args.output, "w")

    for i in range(args.events):
        offset = random.uniform(0, duration_secs)
        event = generate_event(base_time, offset)
        out.write(json.dumps(event, default=str) + "\n")

        if (i + 1) % 10000 == 0:
            print(f"Generated {i + 1}/{args.events} events", file=sys.stderr)

    if out is not sys.stdout:
        out.close()

    print(f"Done. Generated {args.events} events over {args.duration}.", file=sys.stderr)


if __name__ == "__main__":
    main()
