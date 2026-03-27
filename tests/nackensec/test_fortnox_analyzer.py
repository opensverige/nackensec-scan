"""Tests for Fortnox API awareness analyzer."""

import pytest
from skill_scanner.core.models import Severity
from nackensec.analyzers.fortnox_analyzer import FortnoxAnalyzer


@pytest.fixture
def analyzer():
    return FortnoxAnalyzer()


class TestFortnoxOnMaliciousSkill:
    def test_tier1_endpoint_without_protection_is_high(self, analyzer, malicious_skill):
        findings = analyzer.analyze(malicious_skill)
        tier1 = [f for f in findings if f.rule_id == "FORTNOX_TIER1_UNPROTECTED"]
        assert len(tier1) >= 1
        assert all(f.severity == Severity.HIGH for f in tier1)

    def test_finding_lists_affected_endpoint(self, analyzer, malicious_skill):
        findings = analyzer.analyze(malicious_skill)
        tier1 = [f for f in findings if f.rule_id == "FORTNOX_TIER1_UNPROTECTED"]
        for f in tier1:
            assert "endpoint" in f.metadata
            assert f.metadata["endpoint"] in ["/3/employees", "/3/salarytransactions", "/3/taxreductions", "/3/vacationdebtbasis"]

    def test_all_findings_have_remediation(self, analyzer, malicious_skill):
        findings = analyzer.analyze(malicious_skill)
        for f in findings:
            assert f.remediation is not None


class TestFortnoxOnCleanSkill:
    def test_no_unprotected_tier1_on_clean_skill(self, analyzer, clean_fortnox_skill):
        findings = analyzer.analyze(clean_fortnox_skill)
        tier1 = [f for f in findings if f.rule_id == "FORTNOX_TIER1_UNPROTECTED"]
        assert len(tier1) == 0

    def test_tier3_with_protection_is_low_or_absent(self, analyzer, clean_fortnox_skill):
        findings = analyzer.analyze(clean_fortnox_skill)
        critical = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical) == 0
