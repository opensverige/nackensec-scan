"""EU AI Act compliance analyzer for Swedish AI agent definitions."""

from __future__ import annotations

import hashlib

from skill_scanner.core.analyzers.base import BaseAnalyzer
from skill_scanner.core.models import Finding, Severity, Skill, ThreatCategory
from skill_scanner.core.scan_policy import ScanPolicy


_PROHIBITED_KEYWORDS = [
    "social scoring",
    "social credit",
    "real-time biometric",
    "realtids-biometri",
    "predictive policing",
    "predikativ polisverksamhet",
    "mass surveillance",
    "massövervakning",
    "emotion recognition",
    "känsloigenkänning",
]

_HIGH_RISK_REQUIRED_FIELDS = [
    "risk_management_plan",
    "human_oversight",
    "technical_documentation",
]

_HIGH_RISK_REQUIRED_KEYWORDS = [
    "human_oversight",
    "human oversight",
    "mänsklig tillsyn",
    "risk_management",
    "risk management",
    "riskhantering",
    "technical_documentation",
    "technical documentation",
    "teknisk dokumentation",
]

# AI disclosure: agent must identify itself as AI (Konsumentverket requirement)
_AI_DISCLOSURE_KEYWORDS = [
    "ai-agent",
    "ai agent",
    "artificiell intelligens",
    "artificial intelligence",
    "automatiserat",
    "automated",
    "robot",
]


def _make_id(rule_id: str, context: str) -> str:
    h = hashlib.sha256(f"{rule_id}:{context}".encode()).hexdigest()[:10]
    return f"{rule_id}_{h}"


class EuAiActAnalyzer(BaseAnalyzer):
    """
    Checks agent definitions for EU AI Act compliance.

    Rules:
      1. risk_classification == "prohibited" -> CRITICAL (Art. 5)
      2. risk_classification == "high-risk" without oversight docs -> HIGH (Art. 9-15)
      3. No AI disclosure -> LOW (Konsumentverket / Art. 50)
    """

    def __init__(self, policy: ScanPolicy | None = None):
        super().__init__(name="nackensec_eu_ai_act", policy=policy)

    def analyze(self, skill: Skill) -> list[Finding]:
        # Use already-loaded data from the Skill object to avoid reading from disk
        # (the file may no longer exist if loaded from a temp directory).
        # risk_classification is stored in skill.manifest.metadata by the loader.
        extra_meta: dict = skill.manifest.metadata or {}
        risk_class = str(extra_meta.get("risk_classification", "")).lower().strip()

        # Build full_text from instruction_body for keyword scanning.
        # Also include manifest name/description so keyword checks cover all text.
        full_text = (
            skill.manifest.name + " " +
            skill.manifest.description + " " +
            skill.instruction_body
        ).lower()

        findings: list[Finding] = []

        # Rule 1: Prohibited agent
        if risk_class == "prohibited":
            findings.append(Finding(
                id=_make_id("EUAIA_PROHIBITED", skill.name),
                rule_id="EUAIA_PROHIBITED",
                category=ThreatCategory.POLICY_VIOLATION,
                severity=Severity.CRITICAL,
                title="Forbjuden agent enligt EU AI Act Art. 5",
                description=(
                    f"Agenten {skill.name!r} klassificeras som 'prohibited'. "
                    "EU AI Act Art. 5 forbjuder: social scoring, realtids-biometri pa allman plats, "
                    "predikativ polisverksamhet och manipulation av sarbara grupper."
                ),
                file_path=str(skill.skill_md_path.name),
                remediation=(
                    "Forbjudna AI-system far inte publiceras eller driftsattas i EU. "
                    "Granska EU AI Act Art. 5 och omklassificera eller avveckla agenten. "
                    "Referens: Forordning (EU) 2024/1689 Art. 5."
                ),
                analyzer=self.name,
                metadata={"risk_classification": risk_class},
            ))

            # Also check for prohibited use-case keywords in body
            for kw in _PROHIBITED_KEYWORDS:
                if kw in full_text:
                    findings.append(Finding(
                        id=_make_id("EUAIA_PROHIBITED_USECASE", kw),
                        rule_id="EUAIA_PROHIBITED_USECASE",
                        category=ThreatCategory.POLICY_VIOLATION,
                        severity=Severity.CRITICAL,
                        title=f"Forbjuden anvandning: {kw}",
                        description=(
                            f"Agenten beskriver en forbjuden anvandning: {kw!r}. "
                            "EU AI Act Art. 5 forbjuder dessa system explicit."
                        ),
                        file_path=str(skill.skill_md_path.name),
                        remediation=(
                            "Ta bort eller omdesigna funktionalitet som bryter mot Art. 5. "
                            "Referens: Forordning (EU) 2024/1689 Art. 5."
                        ),
                        analyzer=self.name,
                        metadata={"keyword": kw},
                    ))

        # Rule 2: High-risk without oversight documentation
        elif risk_class == "high-risk":
            has_oversight = any(kw in full_text for kw in _HIGH_RISK_REQUIRED_KEYWORDS)
            if not has_oversight:
                findings.append(Finding(
                    id=_make_id("EUAIA_HIGH_RISK_NO_OVERSIGHT", skill.name),
                    rule_id="EUAIA_HIGH_RISK_NO_OVERSIGHT",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.HIGH,
                    title="Hogrisk-agent utan dokumenterad mansklig tillsyn",
                    description=(
                        "Agenten klassificeras som 'high-risk' men saknar dokumentation om "
                        "mansklig tillsyn (human_oversight), riskhanteringsplan (risk_management_plan) "
                        "eller teknisk dokumentation (technical_documentation). "
                        "EU AI Act Art. 9-15 kraver dessa for hogrisk-system."
                    ),
                    file_path=str(skill.skill_md_path.name),
                    remediation=(
                        "EU AI Act Art. 9-15 kraver for hogrisk-system: "
                        "(1) riskhanteringssystem, "
                        "(2) datakvalitetskrav, "
                        "(3) teknisk dokumentation, "
                        "(4) loggning och transparens, "
                        "(5) mansklig tillsyn. "
                        "Lagg till falten risk_management_plan, human_oversight och "
                        "technical_documentation i frontmatter. "
                        "Referens: Forordning (EU) 2024/1689 Art. 9-15."
                    ),
                    analyzer=self.name,
                    metadata={"risk_classification": risk_class, "missing": _HIGH_RISK_REQUIRED_FIELDS},
                ))

        # Rule 3: AI disclosure (all agents except prohibited)
        if risk_class not in ("prohibited",):
            has_disclosure = any(kw in full_text for kw in _AI_DISCLOSURE_KEYWORDS)
            if not has_disclosure:
                findings.append(Finding(
                    id=_make_id("EUAIA_NO_AI_DISCLOSURE", skill.name),
                    rule_id="EUAIA_NO_AI_DISCLOSURE",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.LOW,
                    title="Saknar AI-identifiering (Konsumentverket-krav)",
                    description=(
                        "Agentdefinitionen nämner inte att systemet är ett AI. "
                        "EU AI Act Art. 50 och Konsumentverkets riktlinjer kräver "
                        "tydlig identifiering av AI-system mot slutanvändare."
                    ),
                    file_path=str(skill.skill_md_path.name),
                    remediation=(
                        "Lagg till tydlig AI-identifiering i agentens instruktioner, "
                        "t.ex. 'Du ar en AI-agent' eller 'agent_is_ai: true' i frontmatter. "
                        "Referens: EU AI Act Art. 50, Konsumentverket KIFS 2023."
                    ),
                    analyzer=self.name,
                    metadata={},
                ))

        return findings
