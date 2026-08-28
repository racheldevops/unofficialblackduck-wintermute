from __future__ import annotations

import ast
import json
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
SCHEMA = CHART / "values.schema.json"
CRONJOB = CHART / "templates" / "cronjob.yaml"


EXPECTED_ENVIRONMENT = {
    "WINTERMUTE_BLACKDUCK_REQUEST_INTERVAL_SECONDS": "0.5",
    "WINTERMUTE_BLACKDUCK_CIRCUIT_BREAKER_THRESHOLD": "5",
    "WINTERMUTE_BLACKDUCK_CIRCUIT_BREAKER_WINDOW_SECONDS": "60",
    "WINTERMUTE_BLACKDUCK_CACHE_CHECKPOINT_ENTRIES": "25",
    "WINTERMUTE_BLACKDUCK_CACHE_CHECKPOINT_SECONDS": "30",
}


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


def environment_values(
    text: str,
    name: str,
) -> list[str]:
    lines = text.splitlines()
    values: list[str] = []

    for index, line in enumerate(lines):
        if line.strip() != f"- name: {name}":
            continue

        item_indent = indentation(line)

        for candidate in lines[index + 1:]:
            if not candidate.strip():
                continue

            if indentation(candidate) <= item_indent:
                break

            stripped = candidate.strip()

            if stripped.startswith("value:"):
                values.append(
                    scalar_text(
                        stripped.split(
                            ":",
                            1,
                        )[1]
                    )
                )
                break

    return values


def test_values_define_safe_blackduck_defaults() -> None:
    block = yaml_block(
        VALUES.read_text(encoding="utf-8"),
        "blackDuck",
    )
    expected = {
        "insecure": "false",
        "requestIntervalSeconds": "0.5",
        "circuitBreakerThreshold": "5",
        "circuitBreakerWindowSeconds": "60",
        "cacheCheckpointEntries": "25",
        "cacheCheckpointSeconds": "30",
    }

    assert {
        key: yaml_value(block, key)
        for key in expected
    } == expected


def test_schema_validates_blackduck_safety_values() -> None:
    payload = json.loads(
        SCHEMA.read_text(encoding="utf-8")
    )
    blackduck = payload["properties"]["blackDuck"]

    assert set(blackduck["required"]) == {
        "insecure",
        "requestIntervalSeconds",
        "circuitBreakerThreshold",
        "circuitBreakerWindowSeconds",
        "cacheCheckpointEntries",
        "cacheCheckpointSeconds",
    }

    assert (
        blackduck["properties"]
        ["requestIntervalSeconds"]["minimum"]
        == 0
    )
    assert (
        blackduck["properties"]
        ["circuitBreakerThreshold"]["minimum"]
        == 1
    )


def test_cronjob_injects_blackduck_safety_environment() -> None:
    text = CRONJOB.read_text(encoding="utf-8")

    for name in EXPECTED_ENVIRONMENT:
        assert f"- name: {name}" in text


def test_helm_renders_blackduck_safety_environment() -> None:
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
            "image.tag=test-safety",
            "--set-string",
            "jira.url=https://jira.example.invalid",
            "--set-string",
            "jira.projectKey=TEST",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert (
        "name: "
        "wintermute-jira-blackduck-wintermute-jira"
        in completed.stdout
    )

    for name, expected in (
        EXPECTED_ENVIRONMENT.items()
    ):
        assert expected in environment_values(
            completed.stdout,
            name,
        )
