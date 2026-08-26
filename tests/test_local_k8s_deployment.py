from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OVERLAY = (
    ROOT
    / "deploy"
    / "overlays"
    / "docker-desktop-cohort"
)
SCRIPT = (
    ROOT
    / "scripts"
    / "local_cohort_k8s.zsh"
)
HELPER = (
    ROOT
    / "scripts"
    / "local_cohort_k8s_helper.py"
)


def test_local_overlay_is_suspended_and_safe() -> None:
    text = (
        OVERLAY / "schedule-patch.yaml"
    ).read_text(encoding="utf-8")

    assert "suspend: true" in text
    assert "value: dry-run" in text
    assert "name: scm-mode" in text
    assert "value: disabled" in text
    assert 'value: "false"' in text

    for image in (
        "blackduck-wintermute-source:local",
        "blackduck-wintermute-jira:local",
        "blackduck-wintermute-datadog:local",
        "blackduck-wintermute-scm:local",
    ):
        assert image in text


def test_local_script_refuses_wrong_context() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert (
        'expected_context="${LOCAL_K8S_CONTEXT:-docker-desktop}"'
        in text
    )
    assert "Expected Kubernetes context" in text


def test_local_script_builds_all_four_images() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    for target in (
        "source",
        "jira",
        "datadog",
        "scm",
    ):
        assert target in text

    assert (
        'scm_image="blackduck-wintermute-scm:local"'
        in text
    )
    assert '--scm-mode)' in text
    assert '--scm-image "${scm_image}"' in text


def test_local_secret_creation_uses_stdin() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    helper = HELPER.read_text(encoding="utf-8")

    assert "--from-literal" not in script
    assert "--from-literal" not in helper
    assert "BLACKDUCK_API_TOKEN" in helper
    assert "GITHUB_TOKEN" in helper
    assert (
        "blackduck-wintermute-scm-credentials"
        in helper
    )
    assert '"apply",' in helper


def test_scm_prompt_values_are_not_returned_by_substitution() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert "read_scm_credentials" not in text
    assert (
        'local github_org="${GITHUB_ORG:-}"'
        in text
    )
    assert (
        'local github_token="${GITHUB_TOKEN:-}"'
        in text
    )
    assert (
        'GITHUB_ORG="${github_org}"'
        in text
    )
    assert (
        'GITHUB_TOKEN="${github_token}"'
        in text
    )
    assert (
        'read -r -s \\\n'
        '        "github_token?GitHub read-only token: "'
        in text
    )


def test_local_scm_requires_real_credentials() -> None:
    helper = HELPER.read_text(encoding="utf-8")

    assert "--require-scm" in helper
    assert (
        "SCM read-only credentials are not configured"
        in helper
    )
    assert (
        'args.scm_mode == "read-only"'
        in helper
    )
