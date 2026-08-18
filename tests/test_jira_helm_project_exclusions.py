from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
CHART = (
    ROOT
    / "deploy"
    / "charts"
    / "blackduck-wintermute-jira"
)
VALUES = CHART / "values.yaml"
CI = CHART / "ci" / "gitlab-ci.example.yml"


def test_exclusion_defaults_are_empty() -> None:
    values = yaml.safe_load(
        VALUES.read_text(encoding="utf-8")
    )

    assert (
        values["pipeline"]["excludeParentProjects"]
        == []
    )
    assert (
        values["pipeline"]["excludeChildProjects"]
        == []
    )


def test_gitlab_exclusion_defaults_are_empty_json() -> None:
    payload = yaml.safe_load(
        CI.read_text(encoding="utf-8")
    )
    variables = payload["variables"]

    assert (
        variables["WINTERMUTE_EXCLUDE_PARENT_PROJECTS"]
        == "[]"
    )
    assert (
        variables["WINTERMUTE_EXCLUDE_CHILD_PROJECTS"]
        == "[]"
    )


def test_helm_renders_repeatable_exclusion_flags() -> None:
    helm = shutil.which("helm")

    if not helm:
        pytest.skip("helm is not installed")

    completed = subprocess.run(
        [
            helm,
            "template",
            "wintermute-jira",
            str(CHART),
            "--set-string",
            (
                "image.repository="
                "registry.example.invalid/team/wintermute"
            ),
            "--set-string",
            "image.tag=test-exclusions",
            "--set-string",
            "jira.url=https://jira.example.invalid",
            "--set-string",
            "jira.projectKey=TEST",
            "--set-json",
            (
                "pipeline.excludeParentProjects="
                '["Excluded-Parent","Another-Parent"]'
            ),
            "--set-json",
            (
                "pipeline.excludeChildProjects="
                '["Excluded-Child"]'
            ),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr

    documents = [
        document
        for document in yaml.safe_load_all(
            completed.stdout
        )
        if isinstance(document, dict)
    ]
    cronjob = next(
        document
        for document in documents
        if (
            document.get("kind") == "CronJob"
            and any(
                container.get("name")
                == "jira-pipeline"
                for container in (
                    document["spec"]["jobTemplate"]["spec"]
                    ["template"]["spec"]["containers"]
                )
            )
        )
    )
    arguments = (
        cronjob["spec"]["jobTemplate"]["spec"]
        ["template"]["spec"]["containers"][0]["args"]
    )

    assert arguments.count(
        "--exclude-parent-project"
    ) == 2
    assert arguments.count(
        "--exclude-child-project"
    ) == 1
    assert "Excluded-Parent" in arguments
    assert "Another-Parent" in arguments
    assert "Excluded-Child" in arguments
