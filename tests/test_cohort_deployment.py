from __future__ import annotations

import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_cohort_entrypoints_exist() -> None:
    payload = tomllib.loads(
        (ROOT / "pyproject.toml").read_text(
            encoding="utf-8"
        )
    )
    scripts = payload["project"]["scripts"]

    assert scripts[
        "blackduck-wintermute-cohort-source"
    ] == "wintermute.blackduck.cohort_source:main"
    assert scripts[
        "blackduck-wintermute-jira-cohort"
    ] == "wintermute.jira.cohort_pipeline:main"
    assert scripts[
        "blackduck-wintermute-datadog-cohort"
    ] == "wintermute.datadog.cohort_pipeline:main"


def test_dockerfile_has_three_cohort_targets() -> None:
    text = (ROOT / "Dockerfile").read_text(
        encoding="utf-8"
    )

    assert "FROM runtime-base AS source" in text
    assert "FROM runtime-base AS jira" in text
    assert "FROM runtime-base AS datadog" in text
    assert (
        'ENTRYPOINT ["blackduck-wintermute-cohort-source"]'
        in text
    )
    assert (
        'ENTRYPOINT ["blackduck-wintermute-jira-cohort"]'
        in text
    )
    assert (
        'ENTRYPOINT ["blackduck-wintermute-datadog-cohort"]'
        in text
    )


def test_cohort_dag_orders_consumers_and_supports_disabled_modes() -> None:
    text = (
        ROOT
        / "deploy"
        / "cohort"
        / "workflow-template.yaml"
    ).read_text(encoding="utf-8")

    assert "failFast: false" in text
    assert "name: source" in text
    assert "name: jira" in text
    assert "name: datadog" in text
    assert "name: finalize" in text
    assert "depends: source.Succeeded" in text

    assert (
        "jira.Succeeded || jira.Failed || jira.Errored ||"
        in text
    )
    assert (
        "jira.Skipped || jira.Omitted"
        in text
    )
    assert (
        "datadog.Succeeded || datadog.Failed || "
        "datadog.Errored ||"
        in text
    )
    assert (
        "datadog.Skipped || datadog.Omitted"
        in text
    )

    assert (
        'when: "{{workflow.parameters.jira-mode}} '
        '!= disabled"'
        in text
    )
    assert (
        'when: "{{workflow.parameters.datadog-mode}} '
        '!= disabled"'
        in text
    )

    assert "blackduck-wintermute-cohorts" in text
    assert "blackduck-wintermute-source-data" in text
    assert "blackduck-wintermute-jira-data" in text
    assert "blackduck-wintermute-datadog-data" in text
    assert (
        "{{tasks.source.outputs.parameters.cohort-id}}"
        in text
    )


def test_cohort_schedule_is_safe_by_default() -> None:
    text = (
        ROOT
        / "deploy"
        / "cohort"
        / "cron-workflow.yaml"
    ).read_text(encoding="utf-8")

    assert "suspend: true" in text
    assert "concurrencyPolicy: Forbid" in text


def test_cohort_containers_have_explicit_commands_for_argo() -> None:
    text = (
        ROOT
        / "deploy"
        / "cohort"
        / "workflow-template.yaml"
    ).read_text(encoding="utf-8")

    assert (
        "command:\n"
        "          - blackduck-wintermute-cohort-source"
        in text
    )
    assert (
        "command:\n"
        "          - blackduck-wintermute-jira-cohort"
        in text
    )
    assert (
        "command:\n"
        "          - blackduck-wintermute-datadog-cohort"
        in text
    )
