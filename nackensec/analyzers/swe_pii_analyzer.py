"""Swedish PII analyzer with Luhn-validated personnummer detection."""

from __future__ import annotations

import hashlib
import re

import yara_x

from skill_scanner.core.analyzers.base import BaseAnalyzer
from skill_scanner.core.models import Finding, Severity, Skill, ThreatCategory
from skill_scanner.core.scan_policy import ScanPolicy

from nackensec.data import SWEDISH_RULES_DIR
from nackensec.validators import is_valid_personnummer, is_valid_organisationsnummer, normalize_personnummer


# Regex patterns for candidate extraction (same semantics as YARA, used for Luhn validation)
_PNR_PATTERNS = [
    re.compile(r"\b(19|20)\d{6}[-]?\d{4}\b"),  # YYYYMMDD-XXXX
    re.compile(r"\b\d{6}[-]\d{4}\b"),            # YYMMDD-XXXX
    re.compile(r"\b\d{10}\b"),                    # YYMMDDXXXX
]

_ORGNR_PATTERNS = [
    re.compile(r"\b16[2-9]\d{5}[-]?\d{4}\b"),
    re.compile(r"\b[2-9]\d{5}[-]\d{4}\b"),
]

_BANK_PATTERNS = [
    re.compile(r"\bSE\d{2}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}\b"),  # IBAN SE
    re.compile(r"\b[Bb]ankgiro\s*:?\s*\d{3,4}-\d{4}\b"),
    re.compile(r"\bBG\s+\d{3,4}-\d{4}\b"),
    re.compile(r"\b[Pp]lusgiro\s*:?\s*\d{2,7}-\d\b"),
    re.compile(r"\bPG\s+\d{2,7}-\d\b"),
]

_PHONE_PATTERNS = [
    re.compile(r"\b07[0-9][-\s]?\d{3}[\s]?\d{2}[\s]?\d{2}\b"),   # Swedish mobile
    re.compile(r"\b0[1-9]\d[-\s]?\d{3}[\s]?\d{2}[\s]?\d{2}\b"),   # Swedish landline
    re.compile(r"\+46\s?[0-9]{1,2}\s?\d{3}\s?\d{2}\s?\d{2}"),     # International
]


def _make_id(rule_id: str, context: str) -> str:
    h = hashlib.sha256(f"{rule_id}:{context}".encode()).hexdigest()[:10]
    return f"{rule_id}_{h}"


def _line_of(text: str, match_start: int) -> int:
    return text[:match_start].count("\n") + 1


class SwePIIAnalyzer(BaseAnalyzer):
    """
    Detects Swedish PII in agent skill definitions.

    Layer 1 (YARA): fast pattern matching for candidates.
    Layer 2 (Python): Luhn-10 validation distinguishes confirmed PII
    from test data or false positives.

    Severity mapping:
      Personnummer (valid Luhn) → HIGH   (GDPR-adjacent, IMY special category)
      Personnummer (bad Luhn)   → INFO   (possible test data), rule_id SWE_PII_PNR_SUSPECT
      Organisationsnummer       → MEDIUM (public but compliance-relevant)
      Bankgiro / IBAN           → HIGH   (financial PII)
      Telefonnummer             → LOW    (basic contact PII)
    """

    def __init__(self, policy: ScanPolicy | None = None):
        super().__init__(name="nackensec_swe_pii", policy=policy)
        self._yara_rules = self._load_yara()
        self._scanner = yara_x.Scanner(self._yara_rules) if self._yara_rules is not None else None

    def _load_yara(self) -> yara_x.Rules | None:
        yara_files = list(SWEDISH_RULES_DIR.glob("*.yara"))
        if not yara_files:
            return None
        compiler = yara_x.Compiler()
        for yf in yara_files:
            compiler.new_namespace(yf.stem)
            compiler.add_source(yf.read_text(encoding="utf-8"), origin=str(yf))
        return compiler.build()

    def _yara_matches(self, text: str) -> bool:
        """Return True if YARA finds any Swedish PII pattern in text."""
        if self._scanner is None:
            return False
        results = self._scanner.scan(text.encode("utf-8", errors="replace"))
        return len(list(results.matching_rules)) > 0

    def analyze(self, skill: Skill) -> list[Finding]:
        findings: list[Finding] = []

        # Collect all text content to scan
        texts: list[tuple[str, str]] = []  # (content, file_path_label)

        for sf in skill.files:
            if sf.file_type in ("binary",):
                continue
            content = sf.read_content()
            if content:
                texts.append((content, sf.relative_path))

        for text, file_label in texts:
            # Quick YARA pre-filter — skip expensive Python regex if no match
            if not self._yara_matches(text):
                continue

            findings.extend(self._scan_personnummer(text, file_label))
            findings.extend(self._scan_organisationsnummer(text, file_label))
            findings.extend(self._scan_bank(text, file_label))
            findings.extend(self._scan_phone(text, file_label))

        return findings

    def _scan_personnummer(self, text: str, file_label: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for pattern in _PNR_PATTERNS:
            for m in pattern.finditer(text):
                candidate = m.group(0)
                normalized = normalize_personnummer(candidate)
                if normalized is None:
                    normalized = candidate
                if normalized in seen:
                    continue
                seen.add(normalized)

                luhn_ok = is_valid_personnummer(normalized)

                # Skip if this is more likely an organisationsnummer
                if not luhn_ok and is_valid_organisationsnummer(candidate):
                    continue

                if luhn_ok:
                    rule_id = "SWE_PII_PNR"
                    severity = Severity.HIGH
                    desc = (
                        f"Personnummer i klartext: {candidate!r}. "
                        "Kontrollsiffra validerad — sannolikt ett riktigt personnummer."
                    )
                else:
                    rule_id = "SWE_PII_PNR_SUSPECT"
                    severity = Severity.INFO
                    desc = (
                        f"Möjligt personnummer i klartext: {candidate!r}. "
                        "Kontrollsiffra misslyckas — möjligen testdata eller falsk positiv."
                    )

                findings.append(Finding(
                    id=_make_id(rule_id, normalized),
                    rule_id=rule_id,
                    category=ThreatCategory.HARDCODED_SECRETS,
                    severity=severity,
                    title="Personnummer exponerat i agentdefinition",
                    description=desc,
                    file_path=file_label,
                    line_number=_line_of(text, m.start()),
                    snippet=text[max(0, m.start() - 20): m.end() + 20].strip(),
                    remediation=(
                        "Ta bort personnumret från agentdefinitionen. "
                        "Använd SveaGuard mask_json() eller anonymisera data innan agenten ser den. "
                        "Referens: IMY GDPR Art. 9, Dataskyddsförordningen 2016/679."
                    ),
                    analyzer=self.name,
                    metadata={"luhn_valid": luhn_ok, "candidate": normalized},
                ))

        return findings

    def _scan_organisationsnummer(self, text: str, file_label: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for pattern in _ORGNR_PATTERNS:
            for m in pattern.finditer(text):
                candidate = m.group(0)
                if candidate in seen:
                    continue
                seen.add(candidate)

                luhn_ok = is_valid_organisationsnummer(candidate)
                if not luhn_ok:
                    continue  # Skip clear false positives

                findings.append(Finding(
                    id=_make_id("SWE_PII_ORGNR", candidate),
                    rule_id="SWE_PII_ORGNR",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.MEDIUM,
                    title="Organisationsnummer i agentdefinition",
                    description=(
                        f"Organisationsnummer {candidate!r} hittades i klartext. "
                        "Hårdkodade org-nummer kan exponera affärsrelationer och bör undvikas."
                    ),
                    file_path=file_label,
                    line_number=_line_of(text, m.start()),
                    snippet=text[max(0, m.start() - 20): m.end() + 20].strip(),
                    remediation=(
                        "Flytta organisationsnumret till en konfigurationsfil eller miljövariabel. "
                        "Undvik att hårdkoda affärsidentiteter i agentdefinitioner."
                    ),
                    analyzer=self.name,
                    metadata={"luhn_valid": True, "candidate": candidate},
                ))

        return findings

    def _scan_bank(self, text: str, file_label: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for pattern in _BANK_PATTERNS:
            for m in pattern.finditer(text):
                candidate = m.group(0)
                if candidate in seen:
                    continue
                seen.add(candidate)

                findings.append(Finding(
                    id=_make_id("SWE_PII_BANK", candidate),
                    rule_id="SWE_PII_BANK",
                    category=ThreatCategory.HARDCODED_SECRETS,
                    severity=Severity.HIGH,
                    title="Bankuppgifter exponerade i agentdefinition",
                    description=(
                        f"Bankuppgift i klartext: {candidate!r}. "
                        "Bankgiro, plusgiro och IBAN är känslig finansiell PII."
                    ),
                    file_path=file_label,
                    line_number=_line_of(text, m.start()),
                    snippet=text[max(0, m.start() - 20): m.end() + 20].strip(),
                    remediation=(
                        "Ta bort bankuppgifter från agentdefinitionen omedelbart. "
                        "Hämta kontouppgifter från säker vault (t.ex. SveaGuard) vid körning. "
                        "Referens: PCI DSS, Betaltjänstlagen (2010:751)."
                    ),
                    analyzer=self.name,
                    metadata={"candidate": candidate},
                ))

        return findings

    def _scan_phone(self, text: str, file_label: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for pattern in _PHONE_PATTERNS:
            for m in pattern.finditer(text):
                candidate = m.group(0)
                if candidate in seen:
                    continue
                seen.add(candidate)

                findings.append(Finding(
                    id=_make_id("SWE_PII_PHONE", candidate),
                    rule_id="SWE_PII_PHONE",
                    category=ThreatCategory.POLICY_VIOLATION,
                    severity=Severity.LOW,
                    title="Telefonnummer i agentdefinition",
                    description=(
                        f"Telefonnummer i klartext: {candidate!r}. "
                        "Kontaktuppgifter räknas som personuppgifter under GDPR."
                    ),
                    file_path=file_label,
                    line_number=_line_of(text, m.start()),
                    snippet=text[max(0, m.start() - 20): m.end() + 20].strip(),
                    remediation=(
                        "Undvik att hårdkoda telefonnummer i agentdefinitioner. "
                        "Använd dynamisk konfiguration eller pseudonymisering. "
                        "Referens: GDPR Art. 4(1), IMY vägledning om personuppgifter."
                    ),
                    analyzer=self.name,
                    metadata={"candidate": candidate},
                ))

        return findings
