"""Fortnox API awareness analyzer.

Detects Fortnox REST API endpoint references and cross-references
them against a risk database. Flags endpoints that handle PII
without declared protection measures.
"""

from __future__ import annotations

import hashlib
import re

import yaml

from skill_scanner.core.analyzers.base import BaseAnalyzer
from skill_scanner.core.models import Finding, Severity, Skill, ThreatCategory
from skill_scanner.core.scan_policy import ScanPolicy

from nackensec.data import DATA_DIR


_RISK_MAP_PATH = DATA_DIR / "fortnox_risk_map.yaml"

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}

# Broad Fortnox detection: any /3/... path or the word "fortnox"
_FORTNOX_GENERAL = re.compile(r"(?:fortnox|/3/\w+)", re.IGNORECASE)


def _make_id(rule_id: str, context: str) -> str:
    h = hashlib.sha256(f"{rule_id}:{context}".encode()).hexdigest()[:10]
    return f"{rule_id}_{h}"


def _load_risk_map() -> dict:
    return yaml.safe_load(_RISK_MAP_PATH.read_text(encoding="utf-8"))


def _has_protection(text: str, keywords: list[str]) -> bool:
    text_lower = text.lower()
    return any(kw.lower() in text_lower for kw in keywords)


class FortnoxAnalyzer(BaseAnalyzer):
    """
    Detects Fortnox API references and checks for PII protection.

    Tiers:
      Tier 1 (employees, salary, tax) -> HIGH if no protection declared
      Tier 2 (customers, suppliers)   -> MEDIUM if no protection
      Tier 3 (invoices, orders, etc.) -> LOW if no protection
    """

    def __init__(self, policy: ScanPolicy | None = None):
        super().__init__(name="nackensec_fortnox", policy=policy)
        self._risk_map = _load_risk_map()

    def analyze(self, skill: Skill) -> list[Finding]:
        # Collect full text corpus
        texts: list[str] = []
        for sf in skill.files:
            if sf.file_type != "binary":
                c = sf.read_content()
                if c:
                    texts.append(c)
        full_text = "\n".join(texts)

        # Quick check: any Fortnox reference at all?
        if not _FORTNOX_GENERAL.search(full_text):
            return []

        protection_keywords: list[str] = self._risk_map.get("protection_keywords", [])
        protected = _has_protection(full_text, protection_keywords)

        findings: list[Finding] = []
        for tier_key in ("tier_1_critical", "tier_2_high", "tier_3_medium"):
            tier = self._risk_map.get(tier_key, {})
            if not tier:
                continue

            for endpoint in tier.get("endpoints", []):
                # Check if this specific endpoint is mentioned
                pattern = re.compile(re.escape(endpoint), re.IGNORECASE)
                if not pattern.search(full_text):
                    continue

                if protected:
                    # Protection declared — lower severity by one tier for tier1/2, skip tier3
                    if tier_key == "tier_3_medium":
                        continue
                    effective_severity = Severity.LOW if tier_key == "tier_1_critical" else Severity.INFO
                else:
                    effective_severity = _SEVERITY_MAP.get(tier.get("severity", "MEDIUM"), Severity.MEDIUM)

                findings.append(Finding(
                    id=_make_id(tier["rule_id"], endpoint),
                    rule_id=tier["rule_id"],
                    category=ThreatCategory.DATA_EXFILTRATION,
                    severity=effective_severity,
                    title=f"Fortnox {endpoint} utan PII-skydd",
                    description=(
                        f"Agenten refererar till Fortnox-endpoint {endpoint!r}. "
                        f"Risk: {tier.get('risk', '')}. "
                        + ("Inget PII-skydd (mask, redact, anonymize) deklarerat."
                           if not protected else
                           "PII-skydd identifierat men Tier 1-data kräver explicit verifiering.")
                    ),
                    file_path=str(skill.skill_md_path.name),
                    remediation=tier.get("remediation", ""),
                    analyzer=self.name,
                    metadata={
                        "endpoint": endpoint,
                        "tier": tier_key,
                        "protection_found": protected,
                        "pii_types": tier.get("pii_types", []),
                    },
                ))

        return findings
