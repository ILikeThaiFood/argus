#!/usr/bin/env python3
"""Import MITRE ATT&CK STIX 2.1 data for the ARGUS platform.

Downloads the ATT&CK Enterprise data from MITRE GitHub (or loads from
local cache) and outputs structured JSON for consumption by the app.

Usage:
    python scripts/import_attack.py --output data/attack_matrix.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


def download_attack_data(cache_path: Path) -> dict:
    """Download ATT&CK STIX data or load from cache."""
    if cache_path.exists():
        logger.info("Loading cached ATT&CK data from %s", cache_path)
        with open(cache_path) as f:
            return json.load(f)

    logger.info("Downloading ATT&CK Enterprise data from MITRE …")
    try:
        import urllib.request
        with urllib.request.urlopen(ATTACK_STIX_URL, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_path, "w") as f:
            json.dump(data, f)
        logger.info("Cached to %s", cache_path)
        return data
    except Exception as exc:
        logger.error("Failed to download ATT&CK data: %s", exc)
        logger.info("Using built-in minimal ATT&CK dataset instead.")
        return _builtin_attack_data()


def _builtin_attack_data() -> dict:
    """Minimal built-in ATT&CK data for offline use."""
    return {"type": "bundle", "objects": []}


def parse_techniques(stix_data: dict) -> list[dict]:
    """Extract tactics and techniques from STIX bundle."""
    objects = stix_data.get("objects", [])

    # Build tactic lookup from x-mitre-tactic
    tactic_map: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            short_name = obj.get("x_mitre_shortname", "")
            name = obj.get("name", "")
            if short_name:
                tactic_map[short_name] = name

    techniques: list[dict] = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        ext_refs = obj.get("external_references", [])
        technique_id = ""
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                break

        if not technique_id:
            continue

        kill_chain = obj.get("kill_chain_phases", [])
        tactics = []
        for kc in kill_chain:
            if kc.get("kill_chain_name") == "mitre-attack":
                phase = kc.get("phase_name", "")
                tactic_name = tactic_map.get(phase, phase.replace("-", " ").title())
                tactics.append(tactic_name)

        platforms = obj.get("x_mitre_platforms", [])
        is_subtechnique = obj.get("x_mitre_is_subtechnique", False)

        techniques.append({
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "description": (obj.get("description", "") or "")[:500],
            "tactics": tactics,
            "platforms": platforms,
            "is_subtechnique": is_subtechnique,
            "detection": (obj.get("x_mitre_detection", "") or "")[:300],
        })

    techniques.sort(key=lambda t: t["technique_id"])
    return techniques


def main():
    parser = argparse.ArgumentParser(description="Import MITRE ATT&CK data for ARGUS")
    parser.add_argument("--output", type=str, default="data/attack_matrix.json")
    parser.add_argument("--cache", type=str, default="data/raw/enterprise-attack.json")
    parser.add_argument("--format", choices=["json", "jsonl"], default="json")
    args = parser.parse_args()

    cache_path = Path(args.cache)
    stix_data = download_attack_data(cache_path)
    techniques = parse_techniques(stix_data)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if args.format == "jsonl":
        with open(output_path, "w") as f:
            for tech in techniques:
                f.write(json.dumps(tech) + "\n")
    else:
        with open(output_path, "w") as f:
            json.dump({
                "version": "ATT&CK v16",
                "total_techniques": len(techniques),
                "techniques": techniques,
            }, f, indent=2)

    logger.info("Exported %d techniques to %s", len(techniques), output_path)


if __name__ == "__main__":
    main()
