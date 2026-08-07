from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_local_apply_requires_confirmation_and_limits() -> None:
    text = (
        ROOT
        / "scripts"
        / "local_cohort_apply.zsh"
    ).read_text(encoding="utf-8")

    assert 'confirmation?Type APPLY to continue' in text
    assert '--jira-only-vulnerability' in text
    assert '--jira-max-create 100' in text
    assert '--datadog-max-send 10' in text
    assert '--confirm-apply' in text


def test_local_deploy_does_not_overwrite_destination_credentials() -> None:
    helper = (
        ROOT
        / "scripts"
        / "local_cohort_k8s_helper.py"
    ).read_text(encoding="utf-8")

    assert "secret_exists(" in helper
    assert (
        "Jira apply credentials are not configured"
        in helper
    )
    assert (
        "Datadog apply credentials are not configured"
        in helper
    )


def test_local_destination_configuration_avoids_literal_secret_arguments() -> None:
    text = (
        ROOT
        / "scripts"
        / "configure_local_destinations.zsh"
    ).read_text(encoding="utf-8")

    assert "--from-literal" not in text
    assert "DATADOG_API_KEY" in text
    assert "JIRA_API_TOKEN" in text
