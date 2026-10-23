from __future__ import annotations

import sys

import pytest

from wintermute.jira import pipeline
from wintermute.jira import product_reporting


def test_recovery_flag_reaches_product_run_without_changing_config(
    monkeypatch,
):
    original = {
        "jira": {"project_key": "SEC"},
        "product_reporting": {
            "enabled": True,
            "policy_custom_field": "Policy",
            "entity_custom_field": "Entity",
        },
    }
    received = []

    monkeypatch.setattr(pipeline, "load_config", lambda path: original)

    def fake_run(args, config):
        received.append((
            args.reconcile_missing_jira_issues,
            product_reporting.settings_from(config)[
                "reconcile_missing_jira_issues"
            ],
        ))
        return 0

    monkeypatch.setattr(product_reporting, "run", fake_run)

    monkeypatch.setattr(sys, "argv", [
        "blackduck-jira-pipeline",
        "--apply",
        "--max-create",
        "2",
        "--reconcile-missing-jira-issues",
    ])
    assert pipeline.main() == 0

    monkeypatch.setattr(sys, "argv", [
        "blackduck-jira-pipeline",
        "--apply",
        "--max-create",
        "2",
    ])
    assert pipeline.main() == 0

    assert received == [(True, True), (False, False)]
    assert "reconcile_missing_jira_issues" not in original["product_reporting"]


@pytest.mark.parametrize("mode", [
    ["--dry-run"],
    ["--apply", "--preflight-only"],
])
def test_recovery_flag_rejects_non_applying_run(
    monkeypatch, mode, capsys,
):
    monkeypatch.setattr(
        pipeline,
        "load_config",
        lambda path: {"product_reporting": {"enabled": True}},
    )
    monkeypatch.setattr(
        product_reporting,
        "run",
        lambda *args: pytest.fail("Product run must not start"),
    )
    monkeypatch.setattr(sys, "argv", [
        "blackduck-jira-pipeline",
        *mode,
        "--reconcile-missing-jira-issues",
    ])

    assert pipeline.main() == pipeline.EXIT_ARGUMENT_ERROR
    assert "--reconcile-missing-jira-issues" in capsys.readouterr().err


def test_recovery_flag_rejects_legacy_pipeline(monkeypatch, capsys):
    monkeypatch.setattr(
        pipeline,
        "load_config",
        lambda path: {"product_reporting": {"enabled": False}},
    )
    monkeypatch.setattr(
        pipeline,
        "_wintermute_legacy_run_pipeline",
        lambda args: pytest.fail("Legacy pipeline must not start"),
    )
    monkeypatch.setattr(sys, "argv", [
        "blackduck-jira-pipeline",
        "--apply",
        "--reconcile-missing-jira-issues",
    ])

    assert pipeline.main() == pipeline.EXIT_ARGUMENT_ERROR
    assert "--reconcile-missing-jira-issues" in capsys.readouterr().err


def test_duplicate_recovery_flag_is_rejected(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", [
        "blackduck-jira-pipeline",
        "--apply",
        "--reconcile-missing-jira-issues",
        "--reconcile-missing-jira-issues",
    ])

    assert pipeline.main() == pipeline.EXIT_ARGUMENT_ERROR
    assert "only once" in capsys.readouterr().err
