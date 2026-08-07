from __future__ import annotations

import argparse
from pathlib import Path

from wintermute.blackduck import (
    cohort_finalize,
)


ROOT = Path(__file__).resolve().parents[1]


def test_workflow_can_skip_each_destination() -> None:
    text = (
        ROOT
        / "deploy"
        / "cohort"
        / "workflow-template.yaml"
    ).read_text(encoding="utf-8")

    assert text.count("          - disabled") == 2
    assert (
        "when: \"{{=workflow.parameters['jira-mode'] "
        "!= 'disabled'}}\""
        in text
    )
    assert (
        "when: \"{{=workflow.parameters['datadog-mode'] "
        "!= 'disabled'}}\""
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


def test_cluster_preflight_omits_disabled_secret() -> None:
    import importlib.util
    import sys

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

    manifest = """
apiVersion: argoproj.io/v1alpha1
kind: CronWorkflow
spec:
  workflowSpec:
    arguments:
      parameters:
        - name: jira-mode
          value: dry-run
        - name: datadog-mode
          value: disabled
"""

    secrets = (
        validator.required_secrets_for_manifest(
            manifest
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
