from __future__ import annotations

import json
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
SCHEMA = CHART / "values.schema.json"
CRONJOB = CHART / "templates" / "cronjob.yaml"


EXPECTED_ENVIRONMENT = {
    "WINTERMUTE_BLACKDUCK_REQUEST_INTERVAL_SECONDS": "0.5",
    "WINTERMUTE_BLACKDUCK_CIRCUIT_BREAKER_THRESHOLD": "5",
    "WINTERMUTE_BLACKDUCK_CIRCUIT_BREAKER_WINDOW_SECONDS": "60",
    "WINTERMUTE_BLACKDUCK_CACHE_CHECKPOINT_ENTRIES": "25",
    "WINTERMUTE_BLACKDUCK_CACHE_CHECKPOINT_SECONDS": "30",
}


def test_values_define_safe_blackduck_defaults() -> None:
    payload = yaml.safe_load(
        VALUES.read_text(encoding="utf-8")
    )

    assert payload["blackDuck"] == {
        "insecure": False,
        "requestIntervalSeconds": 0.5,
        "circuitBreakerThreshold": 5,
        "circuitBreakerWindowSeconds": 60,
        "cacheCheckpointEntries": 25,
        "cacheCheckpointSeconds": 30,
    }


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
            and document.get("metadata", {}).get("name")
            == "wintermute-jira-blackduck-wintermute-jira"
        )
    )
    container = (
        cronjob["spec"]["jobTemplate"]["spec"]
        ["template"]["spec"]["containers"][0]
    )
    environment = {
        item["name"]: item.get("value")
        for item in container["env"]
    }

    for name, expected in EXPECTED_ENVIRONMENT.items():
        assert environment[name] == expected
