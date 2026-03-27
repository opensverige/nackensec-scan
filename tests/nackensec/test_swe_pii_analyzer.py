"""Integration tests for SwePIIAnalyzer."""

import pytest
from skill_scanner.core.models import Severity
from nackensec.analyzers.swe_pii_analyzer import SwePIIAnalyzer


@pytest.fixture
def analyzer():
    return SwePIIAnalyzer()


class TestSwePIIAnalyzerOnMaliciousSkill:
    def test_finds_valid_personnummer_as_high(self, analyzer, malicious_skill):
        findings = analyzer.analyze(malicious_skill)
        pnr_findings = [f for f in findings if f.rule_id == "SWE_PII_PNR"]
        assert len(pnr_findings) >= 1
        assert all(f.severity == Severity.HIGH for f in pnr_findings)

    def test_finds_orgnr(self, analyzer, malicious_skill):
        findings = analyzer.analyze(malicious_skill)
        orgnr_findings = [f for f in findings if f.rule_id == "SWE_PII_ORGNR"]
        assert len(orgnr_findings) >= 1
        assert all(f.severity == Severity.MEDIUM for f in orgnr_findings)

    def test_finds_bankgiro(self, analyzer, malicious_skill):
        findings = analyzer.analyze(malicious_skill)
        bank_findings = [f for f in findings if f.rule_id == "SWE_PII_BANK"]
        assert len(bank_findings) >= 1
        assert all(f.severity == Severity.HIGH for f in bank_findings)

    def test_finds_phone(self, analyzer, malicious_skill):
        findings = analyzer.analyze(malicious_skill)
        phone_findings = [f for f in findings if f.rule_id == "SWE_PII_PHONE"]
        assert len(phone_findings) >= 1
        assert all(f.severity == Severity.LOW for f in phone_findings)

    def test_all_findings_have_remediation(self, analyzer, malicious_skill):
        findings = analyzer.analyze(malicious_skill)
        for f in findings:
            assert f.remediation is not None
            assert len(f.remediation) > 20

    def test_all_findings_have_analyzer_name(self, analyzer, malicious_skill):
        findings = analyzer.analyze(malicious_skill)
        for f in findings:
            assert f.analyzer == "nackensec_swe_pii"

    def test_failed_luhn_reported_as_info(self, analyzer, malicious_skill):
        # The fixture contains "19901231-4589" — invalid Luhn personnummer
        # We verify that findings include INFO level for pattern-only matches
        findings = analyzer.analyze(malicious_skill)
        suspect = [f for f in findings if f.rule_id == "SWE_PII_PNR_SUSPECT"]
        assert len(suspect) >= 1
        assert all(f.severity == Severity.INFO for f in suspect)


class TestSwePIIAnalyzerOnCleanSkill:
    def test_no_pnr_findings_on_clean_skill(self, analyzer, clean_fortnox_skill):
        findings = analyzer.analyze(clean_fortnox_skill)
        pnr_findings = [f for f in findings if f.rule_id in ("SWE_PII_PNR", "SWE_PII_PNR_SUSPECT")]
        assert len(pnr_findings) == 0

    def test_no_bank_findings_on_clean_skill(self, analyzer, clean_fortnox_skill):
        findings = analyzer.analyze(clean_fortnox_skill)
        bank_findings = [f for f in findings if f.rule_id == "SWE_PII_BANK"]
        assert len(bank_findings) == 0
