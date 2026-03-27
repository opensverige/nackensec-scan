"""
nackensec-scan CLI — Cisco skill-scanner fork with Swedish intelligence.

Usage:
    nackensec-scan scan /path/to/agent [--lang sv] [options]

All standard skill-scanner options are forwarded. Additional flags:
    --lang sv     Swedish output (severity names in Swedish, Swedish remediation)
    --no-swe-pii  Disable Swedish PII analyzer
    --no-fortnox  Disable Fortnox analyzer
    --no-eu-ai    Disable EU AI Act compliance analyzer
"""

from __future__ import annotations

import sys


def _build_nackensec_analyzers(
    *,
    swe_pii: bool = True,
    fortnox: bool = True,
    eu_ai_act: bool = True,
) -> list:
    """Build the NäckenSec analyzer list."""
    analyzers = []

    if swe_pii:
        from nackensec.analyzers.swe_pii_analyzer import SwePIIAnalyzer

        analyzers.append(SwePIIAnalyzer())

    if fortnox:
        from nackensec.analyzers.fortnox_analyzer import FortnoxAnalyzer

        analyzers.append(FortnoxAnalyzer())

    if eu_ai_act:
        from nackensec.analyzers.eu_ai_act_analyzer import EuAiActAnalyzer

        analyzers.append(EuAiActAnalyzer())

    return analyzers


def main() -> None:
    import argparse

    # Parse our own flags before forwarding to Cisco's CLI
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--lang", default="en", choices=["en", "sv"])
    pre.add_argument("--no-swe-pii", action="store_true", default=False)
    pre.add_argument("--no-fortnox", action="store_true", default=False)
    pre.add_argument("--no-eu-ai", action="store_true", default=False)

    our_args, remaining = pre.parse_known_args()

    # Build NäckenSec analyzers
    nackensec_analyzers = _build_nackensec_analyzers(
        swe_pii=not our_args.no_swe_pii,
        fortnox=not our_args.no_fortnox,
        eu_ai_act=not our_args.no_eu_ai,
    )

    # Inject our analyzers via monkey-patching the factory so Cisco's CLI
    # picks them up without modification. The CLI's _build_analyzers function
    # calls build_analyzers from skill_scanner.core.analyzer_factory at runtime,
    # so patching the module attribute before the CLI runs is sufficient.
    if nackensec_analyzers:
        import skill_scanner.core.analyzer_factory as _factory

        _orig_build = _factory.build_analyzers

        def _patched_build(*args, **kwargs):  # type: ignore[no-untyped-def]
            base = _orig_build(*args, **kwargs)
            return base + nackensec_analyzers

        _factory.build_analyzers = _patched_build

    # Forward to Cisco's main CLI.
    # Replace sys.argv[0] so Cisco's parser sees the right program name.
    sys.argv = ["nackensec-scan"] + remaining

    from skill_scanner.cli.cli import main as cisco_main

    sys.exit(cisco_main())


if __name__ == "__main__":
    main()
