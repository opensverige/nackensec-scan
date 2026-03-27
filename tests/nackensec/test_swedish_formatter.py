"""Tests for Swedish output formatter and --lang sv CLI wiring."""

from __future__ import annotations

import pytest
from skill_scanner.core.models import Severity

from nackensec.output.swedish_formatter import (
    format_scan_result_sv,
    format_finding_sv,
    sv_severity,
    sv_category,
)


class TestSvSeverity:
    def test_critical_maps_to_kritisk(self):
        assert sv_severity(Severity.CRITICAL) == "KRITISK"

    def test_high_maps_to_hog(self):
        assert sv_severity(Severity.HIGH) == "HÖG"

    def test_medium_maps_to_medel(self):
        assert sv_severity(Severity.MEDIUM) == "MEDEL"

    def test_low_maps_to_lag(self):
        assert sv_severity(Severity.LOW) == "LÅG"

    def test_info_stays_info(self):
        assert sv_severity(Severity.INFO) == "INFO"

    def test_safe_maps_to_saker(self):
        assert sv_severity(Severity.SAFE) == "SÄKER"


class TestSvCategory:
    def test_hardcoded_secrets_in_swedish(self):
        assert sv_category("hardcoded_secrets") == "Hårdkodad hemlighet"

    def test_prompt_injection_in_swedish(self):
        assert sv_category("prompt_injection") == "Prompt-injektion"

    def test_unknown_category_falls_through(self):
        assert sv_category("unknown_future_category") == "unknown_future_category"


class TestFormatScanResultSv:
    def test_empty_findings_gives_swedish_no_findings_message(self, malicious_skill):
        from nackensec.analyzers.swe_pii_analyzer import SwePIIAnalyzer
        from skill_scanner.core.scanner import SkillScanner

        # Scan a clean skill to get a no-findings result
        from tests.nackensec.conftest import load_skill
        clean = load_skill("clean_fortnox_agent")
        scanner = SkillScanner(analyzers=[SwePIIAnalyzer()])
        from pathlib import Path
        result = scanner.scan_skill(Path(clean.skill_md_path).parent)
        output = format_scan_result_sv(result)
        assert "Inga säkerhetsfynd hittades" in output

    def test_malicious_skill_shows_fynd_header(self, malicious_skill):
        from nackensec.analyzers.swe_pii_analyzer import SwePIIAnalyzer
        from skill_scanner.core.scanner import SkillScanner
        from pathlib import Path

        scanner = SkillScanner(analyzers=[SwePIIAnalyzer()])
        result = scanner.scan_skill(Path(malicious_skill.skill_md_path).parent)
        output = format_scan_result_sv(result)
        assert "Säkerhetsfynd:" in output
        assert "NäckenSec Skanningsrapport" in output

    def test_swedish_severity_labels_in_output(self, malicious_skill):
        from nackensec.analyzers.swe_pii_analyzer import SwePIIAnalyzer
        from skill_scanner.core.scanner import SkillScanner
        from pathlib import Path

        scanner = SkillScanner(analyzers=[SwePIIAnalyzer()])
        result = scanner.scan_skill(Path(malicious_skill.skill_md_path).parent)
        output = format_scan_result_sv(result)
        # At least one severity label should be in Swedish
        assert any(label in output for label in ("KRITISK", "HÖG", "MEDEL", "LÅG", "INFO"))

    def test_header_contains_skill_name(self, malicious_skill):
        from nackensec.analyzers.swe_pii_analyzer import SwePIIAnalyzer
        from skill_scanner.core.scanner import SkillScanner
        from pathlib import Path

        scanner = SkillScanner(analyzers=[SwePIIAnalyzer()])
        result = scanner.scan_skill(Path(malicious_skill.skill_md_path).parent)
        output = format_scan_result_sv(result)
        assert result.skill_name in output
