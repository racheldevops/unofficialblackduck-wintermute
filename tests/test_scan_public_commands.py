from __future__ import annotations

import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

EXPECTED_PUBLIC_COMMANDS = {
    "blackduck-wintermute-ai": (
        "wintermute.ai.cli:main"
    ),
    "blackduck-wintermute-scan": (
        "wintermute.scan.cli:main"
    ),
    "blackduck-wintermute-onboard": (
        "wintermute.scm.onboarding.cli:main"
    ),
}

REMOVED_PHASE_COMMANDS = {
    "blackduck-wintermute-scan-fetch",
    "blackduck-wintermute-scan-onboarding",
    (
        "blackduck-wintermute-"
        "scan-onboarding-execute"
    ),
    (
        "blackduck-wintermute-"
        "scan-onboarding-batch"
    ),
    (
        "blackduck-wintermute-"
        "scan-onboarding-batch-execute"
    ),
    "blackduck-wintermute-scan-template-plan",
    "blackduck-wintermute-scan-template-review",
    "blackduck-wintermute-scan-template-merge",
    (
        "blackduck-wintermute-"
        "central-scan-bundle"
    ),
    (
        "blackduck-wintermute-"
        "central-scan-bundle-job"
    ),
    (
        "blackduck-wintermute-"
        "central-scan-bootstrap"
    ),
    (
        "blackduck-wintermute-"
        "central-scan-upgrade"
    ),
}


def scripts() -> dict[str, str]:
    payload = tomllib.loads(
        (
            ROOT / "pyproject.toml"
        ).read_text(encoding="utf-8")
    )

    return {
        str(name): str(target)
        for name, target in payload[
            "project"
        ]["scripts"].items()
    }


def test_public_scan_surface_has_three_commands() -> None:
    configured = scripts()

    for name, target in (
        EXPECTED_PUBLIC_COMMANDS.items()
    ):
        assert configured[name] == target


def test_internal_phases_are_not_public_commands() -> None:
    configured = scripts()

    assert not (
        REMOVED_PHASE_COMMANDS
        & set(configured)
    )


def test_scan_fetch_remains_importable_internally() -> None:
    from wintermute.scan import fetch

    assert callable(fetch.main)


def test_internal_onboarding_services_remain_importable() -> None:
    from wintermute.scm.onboarding import (
        central_bundle,
        consolidation,
        template_artifacts,
    )

    assert callable(
        central_bundle.write_bundle
    )
    assert callable(
        consolidation.consolidate_batch
    )
    assert callable(
        template_artifacts
        .load_verified_template_plan
    )
