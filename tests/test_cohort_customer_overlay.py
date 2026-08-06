from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
OVERLAY = (
    ROOT
    / "deploy"
    / "overlays"
    / "customer-cohort"
)


def test_customer_cohort_overlay_uses_three_images() -> None:
    kustomization = (
        OVERLAY / "kustomization.yaml"
    ).read_text(encoding="utf-8")
    image_patch = (
        OVERLAY / "workflow-images-patch.yaml"
    ).read_text(encoding="utf-8")

    assert (
        "path: workflow-images-patch.yaml"
        in kustomization
    )
    assert image_patch.count(
        "registry.invalid/customer/"
        "blackduck-wintermute-source:replace-me"
    ) == 2
    assert image_patch.count(
        "registry.invalid/customer/"
        "blackduck-wintermute-jira:replace-me"
    ) == 1
    assert image_patch.count(
        "registry.invalid/customer/"
        "blackduck-wintermute-datadog:replace-me"
    ) == 1
    assert image_patch.count("- op: replace") == 4


def test_customer_schedule_is_safe_by_default() -> None:
    text = (
        OVERLAY / "schedule-patch.yaml"
    ).read_text(encoding="utf-8")

    assert "suspend: true" in text
    assert "concurrencyPolicy: Forbid" in text
    assert "name: jira-mode\n          value: dry-run" in text
    assert "name: datadog-mode\n          value: dry-run" in text
    assert "name: confirm-apply\n          value: \"false\"" in text


def test_customer_secrets_are_destination_scoped() -> None:
    blackduck = (
        OVERLAY
        / "blackduck-credentials-secret.example.yaml"
    ).read_text(encoding="utf-8")
    jira = (
        OVERLAY
        / "jira-credentials-secret.example.yaml"
    ).read_text(encoding="utf-8")
    datadog = (
        OVERLAY
        / "datadog-credentials-secret.example.yaml"
    ).read_text(encoding="utf-8")

    assert "BLACKDUCK_API_TOKEN" in blackduck
    assert "JIRA_API_TOKEN" not in blackduck
    assert "DATADOG_API_KEY" not in blackduck

    assert "JIRA_API_TOKEN" in jira
    assert "BLACKDUCK_API_TOKEN" not in jira
    assert "DATADOG_API_KEY" not in jira

    assert "DATADOG_API_KEY" in datadog
    assert "BLACKDUCK_API_TOKEN" not in datadog
    assert "JIRA_API_TOKEN" not in datadog


@pytest.mark.parametrize(
    ("filename", "claim_name"),
    (
        (
            "cohort-storage-class-patch.yaml.example",
            "blackduck-wintermute-cohorts",
        ),
        (
            "source-storage-class-patch.yaml.example",
            "blackduck-wintermute-source-data",
        ),
        (
            "jira-storage-class-patch.yaml.example",
            "blackduck-wintermute-jira-data",
        ),
        (
            "datadog-storage-class-patch.yaml.example",
            "blackduck-wintermute-datadog-data",
        ),
    ),
)
def test_storage_class_examples_are_complete(
    filename: str,
    claim_name: str,
) -> None:
    text = (
        OVERLAY / filename
    ).read_text(encoding="utf-8")

    assert f"name: {claim_name}" in text
    assert (
        "storageClassName: "
        "REPLACE_WITH_CUSTOMER_STORAGE_CLASS"
        in text
    )


def test_customer_overlay_renders_when_kubectl_is_available() -> None:
    kubectl = shutil.which("kubectl")

    if not kubectl:
        pytest.skip("kubectl is not installed")

    completed = subprocess.run(
        [
            kubectl,
            "kustomize",
            str(OVERLAY),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, (
        completed.stderr
    )
    assert (
        "kind: WorkflowTemplate"
        in completed.stdout
    )
    assert (
        "kind: CronWorkflow"
        in completed.stdout
    )

def test_customer_render_rewrites_argo_images() -> None:
    import shutil
    import subprocess

    kubectl = shutil.which("kubectl")

    if not kubectl:
        pytest.skip("kubectl is not installed")

    completed = subprocess.run(
        [
            kubectl,
            "kustomize",
            str(OVERLAY),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr

    expected_images = {
        (
            "registry.invalid/customer/"
            "blackduck-wintermute-source:replace-me"
        ),
        (
            "registry.invalid/customer/"
            "blackduck-wintermute-jira:replace-me"
        ),
        (
            "registry.invalid/customer/"
            "blackduck-wintermute-datadog:replace-me"
        ),
    }

    for image in expected_images:
        assert f"image: {image}" in completed.stdout

    for logical_name in (
        "blackduck-wintermute-source",
        "blackduck-wintermute-jira",
        "blackduck-wintermute-datadog",
    ):
        assert (
            f"image: {logical_name}\n"
            not in completed.stdout
        )

