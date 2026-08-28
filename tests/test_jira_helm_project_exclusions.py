from __future__ import annotations

import ast
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CHART = (
    ROOT
    / "deploy"
    / "charts"
    / "blackduck-wintermute-jira"
)
VALUES = CHART / "values.yaml"
CI = CHART / "ci" / "gitlab-ci.example.yml"


def indentation(value: str) -> int:
    return len(value) - len(
        value.lstrip(" ")
    )


def yaml_block(
    text: str,
    key: str,
) -> str:
    lines = text.splitlines()
    marker_index = -1
    marker_indent = 0

    for index, line in enumerate(lines):
        if line.strip() == f"{key}:":
            marker_index = index
            marker_indent = indentation(line)
            break

    if marker_index < 0:
        raise AssertionError(
            f"YAML key was not found: {key}"
        )

    selected: list[str] = []

    for line in lines[marker_index + 1:]:
        if (
            line.strip()
            and not line.lstrip().startswith("#")
            and indentation(line)
            <= marker_indent
        ):
            break

        selected.append(line)

    return "\n".join(selected)


def scalar_text(value: str) -> str:
    selected = value.strip()

    if (
        len(selected) >= 2
        and selected[0] == selected[-1]
        and selected[0] in {"'", '"'}
    ):
        return str(
            ast.literal_eval(selected)
        )

    return selected


def yaml_value(
    block: str,
    key: str,
) -> str:
    for line in block.splitlines():
        stripped = line.strip()

        if not stripped.startswith(
            f"{key}:"
        ):
            continue

        return scalar_text(
            stripped.split(":", 1)[1]
        )

    raise AssertionError(
        f"YAML value was not found: {key}"
    )


def sequence_values(text: str) -> list[str]:
    values: list[str] = []

    for line in text.splitlines():
        stripped = line.strip()

        if not stripped.startswith("- "):
            continue

        value = stripped[2:].strip()

        if (
            not value
            or value.startswith(("|", ">"))
        ):
            continue

        values.append(
            scalar_text(value)
        )

    return values


def test_exclusion_defaults_are_empty() -> None:
    pipeline = yaml_block(
        VALUES.read_text(encoding="utf-8"),
        "pipeline",
    )

    assert yaml_value(
        pipeline,
        "excludeParentProjects",
    ) == "[]"
    assert yaml_value(
        pipeline,
        "excludeChildProjects",
    ) == "[]"


def test_gitlab_exclusion_defaults_are_empty_json() -> None:
    variables = yaml_block(
        CI.read_text(encoding="utf-8"),
        "variables",
    )

    assert yaml_value(
        variables,
        "WINTERMUTE_EXCLUDE_PARENT_PROJECTS",
    ) == "[]"
    assert yaml_value(
        variables,
        "WINTERMUTE_EXCLUDE_CHILD_PROJECTS",
    ) == "[]"


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
    arguments = sequence_values(
        completed.stdout
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
