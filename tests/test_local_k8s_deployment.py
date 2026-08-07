from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OVERLAY = (
    ROOT
    / "deploy"
    / "overlays"
    / "docker-desktop-cohort"
)
SCRIPT = ROOT / "scripts" / "local_cohort_k8s.zsh"


def test_local_overlay_is_suspended_and_dry_run() -> None:
    text = (
        OVERLAY / "schedule-patch.yaml"
    ).read_text(encoding="utf-8")

    assert "suspend: true" in text
    assert "value: dry-run" in text
    assert 'value: "false"' in text

    for image in (
        "blackduck-wintermute-source:local",
        "blackduck-wintermute-jira:local",
        "blackduck-wintermute-datadog:local",
    ):
        assert image in text


def test_local_script_refuses_wrong_context() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert (
        'expected_context="${LOCAL_K8S_CONTEXT:-docker-desktop}"'
        in text
    )
    assert "Expected Kubernetes context" in text


def test_local_script_never_places_secrets_in_command_arguments() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert "--from-literal" not in text
    assert (
        "BLACKDUCK_API_TOKEN"
        in text
    )
    assert (
        'data": {'
        in text
    )


def test_intellij_run_configs_are_shared() -> None:
    files = list((ROOT / ".run").glob("*.run.xml"))

    assert len(files) >= 8
    assert any(
        "Full_Dry_Run"
        in path.name
        for path in files
    )
