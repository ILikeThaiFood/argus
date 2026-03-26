"""NLP pipeline for IOC extraction from threat intelligence reports.

Uses HuggingFace Transformers (SecureBERT/DistilBERT) for Named Entity
Recognition, with regex fallback for structured IOC patterns.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns for structured IOC extraction (fallback / supplement)
# ---------------------------------------------------------------------------
IOC_PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "ipv6": re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|io|xyz|info|biz|ru|cn|top|tk|ml|ga|cf|cc|pw|su|onion)\b"
    ),
    "md5": re.compile(r"\b[0-9a-fA-F]{32}\b"),
    "sha1": re.compile(r"\b[0-9a-fA-F]{40}\b"),
    "sha256": re.compile(r"\b[0-9a-fA-F]{64}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "email": re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
    "url": re.compile(r"https?://[^\s<>\"']+"),
}

# Private/reserved IP ranges to exclude
_PRIVATE_IP_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                        "172.30.", "172.31.", "192.168.", "127.", "0.")


@dataclass
class ExtractedIOC:
    """A single extracted Indicator of Compromise."""
    type: str  # ip, domain, hash_md5, hash_sha1, hash_sha256, cve, email, url
    value: str
    confidence: float = 0.0
    source: str = "regex"
    context: str = ""  # surrounding text


@dataclass
class ExtractionResult:
    """Result of IOC extraction from a document."""
    iocs: list[ExtractedIOC] = field(default_factory=list)
    raw_text: str = ""
    model_used: str = "regex"


class IOCExtractor:
    """Extract IOCs from unstructured threat reports.

    Uses a HuggingFace NER model when available, with regex fallback
    for structured patterns like IPs, hashes, and CVE IDs.
    """

    def __init__(self, model_name: str = "jackaduma/SecBERT", use_gpu: bool = False):
        self.model_name = model_name
        self.ner_pipeline = None
        self._load_model(use_gpu)

    def _load_model(self, use_gpu: bool) -> None:
        """Attempt to load NER model from HuggingFace."""
        try:
            from transformers import pipeline as hf_pipeline
            device = 0 if use_gpu else -1
            self.ner_pipeline = hf_pipeline(
                "ner",
                model=self.model_name,
                tokenizer=self.model_name,
                aggregation_strategy="simple",
                device=device,
            )
            logger.info("NER model loaded: %s", self.model_name)
        except Exception as exc:
            logger.warning("Could not load NER model '%s': %s. Using regex only.", self.model_name, exc)
            self.ner_pipeline = None

    def extract(self, text: str) -> ExtractionResult:
        """Extract IOCs from text using NER + regex patterns.

        Args:
            text: Raw threat report text.

        Returns:
            ExtractionResult with deduplicated IOCs.
        """
        result = ExtractionResult(raw_text=text)

        # Phase 1: Regex extraction (always runs)
        regex_iocs = self._regex_extract(text)
        result.iocs.extend(regex_iocs)

        # Phase 2: NER extraction (if model available)
        if self.ner_pipeline is not None:
            ner_iocs = self._ner_extract(text)
            result.iocs.extend(ner_iocs)
            result.model_used = self.model_name

        # Deduplicate by (type, value)
        seen = set()
        deduped = []
        for ioc in result.iocs:
            key = (ioc.type, ioc.value.lower())
            if key not in seen:
                seen.add(key)
                deduped.append(ioc)
        result.iocs = deduped

        logger.info("Extracted %d unique IOCs from %d chars of text", len(result.iocs), len(text))
        return result

    def _regex_extract(self, text: str) -> list[ExtractedIOC]:
        """Extract IOCs using regex patterns."""
        iocs: list[ExtractedIOC] = []

        # IPs
        for match in IOC_PATTERNS["ipv4"].finditer(text):
            ip = match.group()
            if not ip.startswith(_PRIVATE_IP_PREFIXES):
                context = text[max(0, match.start() - 50):match.end() + 50]
                iocs.append(ExtractedIOC(type="ip", value=ip, confidence=0.95, context=context))

        # Domains
        for match in IOC_PATTERNS["domain"].finditer(text):
            domain = match.group().lower()
            if len(domain) > 5 and domain not in ("example.com", "test.com"):
                iocs.append(ExtractedIOC(type="domain", value=domain, confidence=0.85))

        # Hashes
        for match in IOC_PATTERNS["sha256"].finditer(text):
            iocs.append(ExtractedIOC(type="hash_sha256", value=match.group().lower(), confidence=0.98))
        for match in IOC_PATTERNS["sha1"].finditer(text):
            val = match.group().lower()
            if not any(i.value == val for i in iocs):
                iocs.append(ExtractedIOC(type="hash_sha1", value=val, confidence=0.95))
        for match in IOC_PATTERNS["md5"].finditer(text):
            val = match.group().lower()
            if not any(i.value == val for i in iocs):
                iocs.append(ExtractedIOC(type="hash_md5", value=val, confidence=0.90))

        # CVEs
        for match in IOC_PATTERNS["cve"].finditer(text):
            iocs.append(ExtractedIOC(type="cve", value=match.group().upper(), confidence=0.99))

        return iocs

    def _ner_extract(self, text: str) -> list[ExtractedIOC]:
        """Extract IOCs using NER model."""
        iocs: list[ExtractedIOC] = []
        try:
            # Process in chunks to handle long documents
            max_len = 512
            chunks = [text[i:i + max_len] for i in range(0, len(text), max_len - 50)]

            for chunk in chunks:
                entities = self.ner_pipeline(chunk)
                for ent in entities:
                    word = ent.get("word", "").strip()
                    label = ent.get("entity_group", "")
                    score = ent.get("score", 0.0)

                    if score < 0.5:
                        continue

                    ioc_type = self._map_ner_label(label, word)
                    if ioc_type:
                        iocs.append(ExtractedIOC(
                            type=ioc_type,
                            value=word,
                            confidence=round(score, 3),
                            source="ner",
                        ))
        except Exception as exc:
            logger.warning("NER extraction error: %s", exc)

        return iocs

    @staticmethod
    def _map_ner_label(label: str, word: str) -> Optional[str]:
        """Map NER entity label to IOC type."""
        label_lower = label.lower()
        if "malware" in label_lower or "mal" in label_lower:
            return "malware"
        if "ip" in label_lower or "address" in label_lower:
            return "ip"
        if "domain" in label_lower or "url" in label_lower:
            return "domain"
        if "hash" in label_lower:
            return "hash"
        if "cve" in label_lower or "vuln" in label_lower:
            return "cve"
        if "threat" in label_lower or "actor" in label_lower or "group" in label_lower:
            return "threat_actor"
        return None
