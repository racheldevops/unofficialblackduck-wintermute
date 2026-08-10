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
    script = SCRIPT.read_text(encoding="utf-8")
    helper = (
        ROOT
        / "scripts"
        / "local_cohort_k8s_helper.py"
    ).read_text(encoding="utf-8")

    assert "--from-literal" not in script
    assert "--from-literal" not in helper
    assert (
        "BLACKDUCK_API_TOKEN"
        in helper
    )
    assert (
        '["apply", "--filename", "-"]'
        in helper.replace("\n", " ")
        or '"apply",' in helper
    )
