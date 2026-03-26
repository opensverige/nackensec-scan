"""Shared fixtures for NäckenSec tests."""

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_skill(fixture_name: str):
    """Load a skill from fixtures using Cisco's SkillLoader."""
    from skill_scanner.core.loader import SkillLoader

    skill_dir = FIXTURES_DIR / fixture_name
    loader = SkillLoader()
    return loader.load_skill(skill_dir)


@pytest.fixture
def clean_fortnox_skill():
    return load_skill("clean_fortnox_agent")


@pytest.fixture
def malicious_skill():
    return load_skill("malicious_agent")
