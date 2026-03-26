"""TTP classification to MITRE ATT&CK techniques + STIX 2.1 bundle generation.

Maps extracted threat intelligence to ATT&CK techniques using transformer
embeddings and outputs structured STIX 2.1 bundles for interoperability.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Simplified ATT&CK technique mapping for classification
ATTACK_TECHNIQUES: dict[str, dict[str, str]] = {
    "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1204": {"name": "User Execution", "tactic": "Execution"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion"},
    "T1036": {"name": "Masquerading", "tactic": "Defense Evasion"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1572": {"name": "Protocol Tunneling", "tactic": "Command and Control"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1498": {"name": "Network Denial of Service", "tactic": "Impact"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1195": {"name": "Supply Chain Compromise", "tactic": "Initial Access"},
    "T1133": {"name": "External Remote Services", "tactic": "Initial Access"},
    "T1573": {"name": "Encrypted Channel", "tactic": "Command and Control"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
}

# Keyword-to-technique mapping for rule-based classification
KEYWORD_TECHNIQUE_MAP: dict[str, list[str]] = {
    "phishing": ["T1566"],
    "spear phishing": ["T1566"],
    "brute force": ["T1110"],
    "credential dumping": ["T1003"],
    "lateral movement": ["T1021", "T1570"],
    "remote desktop": ["T1021"],
    "rdp": ["T1021"],
    "smb": ["T1021"],
    "command and control": ["T1071", "T1573"],
    "c2 beacon": ["T1071"],
    "exfiltration": ["T1041", "T1048"],
    "data theft": ["T1041"],
    "ransomware": ["T1486"],
    "encryption": ["T1486"],
    "denial of service": ["T1498"],
    "ddos": ["T1498"],
    "port scan": ["T1046"],
    "reconnaissance": ["T1595"],
    "scanning": ["T1595"],
    "privilege escalation": ["T1068"],
    "persistence": ["T1547", "T1053"],
    "scheduled task": ["T1053"],
    "powershell": ["T1059"],
    "script": ["T1059"],
    "supply chain": ["T1195"],
    "dns tunnel": ["T1572"],
    "tunneling": ["T1572"],
    "vpn": ["T1133"],
    "masquerading": ["T1036"],
    "indicator removal": ["T1070"],
    "log deletion": ["T1070"],
}


@dataclass
class TTPResult:
    """A single TTP classification result."""
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    evidence: str = ""


class TTPClassifier:
    """Classify threat descriptions into MITRE ATT&CK TTPs.

    Uses keyword-based matching with optional transformer embeddings
    for enhanced classification accuracy.
    """

    def __init__(self, model_name: str = "distilbert-base-uncased", use_model: bool = False):
        self.model_name = model_name
        self.classifier = None
        if use_model:
            self._load_model()

    def _load_model(self) -> None:
        try:
            from transformers import pipeline as hf_pipeline
            self.classifier = hf_pipeline(
                "zero-shot-classification",
                model=self.model_name,
                device=-1,
            )
            logger.info("TTP classifier model loaded: %s", self.model_name)
        except Exception as exc:
            logger.warning("Could not load TTP model: %s", exc)

    def classify(self, text: str, top_k: int = 5) -> list[TTPResult]:
        """Classify text into ATT&CK techniques.

        Args:
            text: Threat description or report excerpt.
            top_k: Maximum number of techniques to return.

        Returns:
            List of TTPResult sorted by confidence.
        """
        results: list[TTPResult] = []

        # Keyword-based classification
        text_lower = text.lower()
        seen_techniques = set()

        for keyword, tech_ids in KEYWORD_TECHNIQUE_MAP.items():
            if keyword in text_lower:
                for tid in tech_ids:
                    if tid in ATTACK_TECHNIQUES and tid not in seen_techniques:
                        seen_techniques.add(tid)
                        tech = ATTACK_TECHNIQUES[tid]
                        confidence = 0.85 if len(keyword.split()) > 1 else 0.70
                        results.append(TTPResult(
                            technique_id=tid,
                            technique_name=tech["name"],
                            tactic=tech["tactic"],
                            confidence=confidence,
                            evidence=keyword,
                        ))

        # Model-based classification (if available)
        if self.classifier and len(results) < top_k:
            try:
                candidate_labels = [
                    f"{v['tactic']}: {v['name']}"
                    for k, v in ATTACK_TECHNIQUES.items()
                    if k not in seen_techniques
                ][:20]

                if candidate_labels:
                    output = self.classifier(text, candidate_labels, multi_label=True)
                    for label, score in zip(output["labels"][:top_k], output["scores"][:top_k]):
                        if score > 0.3:
                            for tid, tech in ATTACK_TECHNIQUES.items():
                                if tech["name"] in label and tid not in seen_techniques:
                                    seen_techniques.add(tid)
                                    results.append(TTPResult(
                                        technique_id=tid,
                                        technique_name=tech["name"],
                                        tactic=tech["tactic"],
                                        confidence=round(score, 3),
                                        evidence="model",
                                    ))
                                    break
            except Exception as exc:
                logger.warning("Model classification error: %s", exc)

        results.sort(key=lambda r: r.confidence, reverse=True)
        return results[:top_k]


def generate_stix_bundle(
    iocs: list[dict[str, Any]],
    ttps: list[TTPResult],
    report_name: str = "ARGUS Threat Report",
) -> dict[str, Any]:
    """Generate a STIX 2.1 bundle from extracted IOCs and TTPs.

    Args:
        iocs: List of IOC dicts with keys: type, value, confidence.
        ttps: List of TTPResult from classification.
        report_name: Name for the STIX report object.

    Returns:
        STIX 2.1 bundle as a dictionary.
    """
    objects: list[dict[str, Any]] = []
    indicator_ids: list[str] = []
    attack_pattern_ids: list[str] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # Create indicators from IOCs
    for ioc in iocs:
        indicator_id = f"indicator--{uuid.uuid4()}"
        indicator_ids.append(indicator_id)

        ioc_type = ioc.get("type", "unknown")
        value = ioc.get("value", "")

        # Map IOC type to STIX pattern
        if ioc_type == "ip":
            pattern = f"[ipv4-addr:value = '{value}']"
        elif ioc_type == "domain":
            pattern = f"[domain-name:value = '{value}']"
        elif "hash" in ioc_type:
            hash_type = "SHA-256" if "256" in ioc_type else "SHA-1" if "sha1" in ioc_type else "MD5"
            pattern = f"[file:hashes.'{hash_type}' = '{value}']"
        elif ioc_type == "cve":
            pattern = f"[vulnerability:name = '{value}']"
        else:
            pattern = f"[artifact:payload_bin = '{value}']"

        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now,
            "modified": now,
            "name": f"{ioc_type}: {value}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
            "confidence": int(ioc.get("confidence", 0.5) * 100),
        })

    # Create attack patterns from TTPs
    for ttp in ttps:
        ap_id = f"attack-pattern--{uuid.uuid4()}"
        attack_pattern_ids.append(ap_id)
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": ap_id,
            "created": now,
            "modified": now,
            "name": ttp.technique_name,
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": ttp.technique_id,
            }],
            "kill_chain_phases": [{
                "kill_chain_name": "mitre-attack",
                "phase_name": ttp.tactic.lower().replace(" ", "-"),
            }],
        })

    # Create relationships
    for ind_id in indicator_ids:
        for ap_id in attack_pattern_ids:
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "created": now,
                "modified": now,
                "relationship_type": "indicates",
                "source_ref": ind_id,
                "target_ref": ap_id,
            })

    # Create report
    report_id = f"report--{uuid.uuid4()}"
    objects.append({
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created": now,
        "modified": now,
        "name": report_name,
        "published": now,
        "object_refs": indicator_ids + attack_pattern_ids,
    })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
