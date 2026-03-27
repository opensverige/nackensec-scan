"""Tests for EU AI Act compliance analyzer."""

import pytest
from pathlib import Path
from skill_scanner.core.models import Severity
from skill_scanner.core.loader import SkillLoader
from nackensec.analyzers.eu_ai_act_analyzer import EuAiActAnalyzer

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def analyzer():
    return EuAiActAnalyzer()


def load(name):
    return SkillLoader().load_skill(FIXTURES / name)


class TestHighRiskWithoutDocumentation:
    def test_high_risk_no_oversight_is_high_finding(self, analyzer):
        # malicious_agent has risk_classification: high-risk but no oversight docs
        skill = load("malicious_agent")
        findings = analyzer.analyze(skill)
        oversight = [f for f in findings if f.rule_id == "EUAIA_HIGH_RISK_NO_OVERSIGHT"]
        assert len(oversight) >= 1
        assert all(f.severity == Severity.HIGH for f in oversight)

    def test_finding_references_eu_ai_act_article(self, analyzer):
        skill = load("malicious_agent")
        findings = analyzer.analyze(skill)
        for f in findings:
            assert "AI Act" in f.description or "Art." in (f.remediation or "")


class TestProhibitedAgent:
    def test_prohibited_classification_is_critical(self, analyzer):
        import tempfile, textwrap
        content = textwrap.dedent("""
            ---
            name: "Social Scorer"
            description: "Scores citizens based on social behaviour"
            version: "1.0.0"
            framework: "custom"
            spec_version: "sweden-v1"
            agent_type: "single"
            risk_classification: "prohibited"
            ---

            ## Instructions
            Score citizens and block access based on social credit.
        """).strip()
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "SKILL.md"
            p.write_text(content)
            skill = SkillLoader().load_skill(Path(tmpdir))
        findings = analyzer.analyze(skill)
        prohibited = [f for f in findings if f.rule_id == "EUAIA_PROHIBITED"]
        assert len(prohibited) >= 1
        assert all(f.severity == Severity.CRITICAL for f in prohibited)


class TestCleanSkillCompliance:
    def test_minimal_risk_clean_skill_passes(self, analyzer, clean_fortnox_skill):
        findings = analyzer.analyze(clean_fortnox_skill)
        critical_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical_high) == 0
