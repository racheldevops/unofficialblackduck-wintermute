from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

from wintermute.blackduck import (
    cohort_finalize,
)


ROOT = Path(__file__).resolve().parents[1]


def load_validator():
    script = (
        ROOT
        / "scripts"
        / "validate_cohort_cluster.py"
    )
    spec = importlib.util.spec_from_file_location(
        "disabled_mode_validator",
        script,
    )
    assert spec is not None
    assert spec.loader is not None
    validator = importlib.util.module_from_spec(
        spec
    )
    sys.modules[spec.name] = validator
    spec.loader.exec_module(validator)
    return validator


def test_workflow_can_skip_destinations_and_scm() -> None:
    text = (
        ROOT
        / "deploy"
        / "cohort"
        / "workflow-template.yaml"
    ).read_text(encoding="utf-8")

    assert text.count("          - disabled") == 3

    for mode in (
        "jira",
        "datadog",
        "scm",
    ):
        assert (
            f"workflow.parameters['{mode}-mode'] "
            "!= 'disabled'"
            in text
        )

    assert "jira.Skipped || jira.Omitted" in text
    assert "datadog.Skipped || datadog.Omitted" in text


def test_finalizer_records_disabled_destinations(
    monkeypatch,
    tmp_path: Path,
) -> None:
    captured = {}
    cohort_directory = tmp_path / "cohorts" / "one"
    cohort_directory.mkdir(parents=True)

    class Cohort:
        cohort_id = "one"
        directory = cohort_directory

    monkeypatch.setattr(
        cohort_finalize,
        "load_cohort",
        lambda path: Cohort(),
    )
    monkeypatch.setattr(
        cohort_finalize,
        "mark_cohort_complete",
        lambda directory, **kwargs: captured.update(
            kwargs
        ),
    )
    monkeypatch.setattr(
        cohort_finalize,
        "prune_cohorts",
        lambda *args, **kwargs: (),
    )

    result = cohort_finalize.run(
        argparse.Namespace(
            cohort_root=str(tmp_path / "cohorts"),
            cohort_id="one",
            retain_cohorts=3,
            jira_mode="dry-run",
            datadog_mode="disabled",
            jira_status="Succeeded",
            datadog_status="Skipped",
        )
    )

    assert result == 0
    assert captured["destination_statuses"] == {
        "jira": "succeeded",
        "datadog": "disabled",
    }


def manifest(
    *,
    jira_mode: str,
    datadog_mode: str,
    scm_mode: str,
) -> str:
    return f"""
apiVersion: argoproj.io/v1alpha1
kind: CronWorkflow
spec:
  workflowSpec:
    arguments:
      parameters:
        - name: jira-mode
          value: {jira_mode}
        - name: datadog-mode
          value: {datadog_mode}
        - name: scm-mode
          value: {scm_mode}
"""


def test_cluster_preflight_omits_disabled_secrets() -> None:
    validator = load_validator()
    secrets = (
        validator.required_secrets_for_manifest(
            manifest(
                jira_mode="dry-run",
                datadog_mode="disabled",
                scm_mode="disabled",
            )
        )
    )

    assert (
        "blackduck-wintermute-jira-credentials"
        in secrets
    )
    assert (
        "blackduck-wintermute-datadog-credentials"
        not in secrets
    )
    assert (
        "blackduck-wintermute-scm-credentials"
        not in secrets
    )


def test_cluster_preflight_requires_enabled_scm_secret() -> None:
    validator = load_validator()
    secrets = (
        validator.required_secrets_for_manifest(
            manifest(
                jira_mode="disabled",
                datadog_mode="disabled",
                scm_mode="read-only",
            )
        )
    )

    assert (
        "blackduck-wintermute-scm-credentials"
        in secrets
    )
