from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
CHART = (
    ROOT
    / "deploy"
    / "charts"
    / "blackduck-wintermute-jira"
)
CI = CHART / "ci" / "gitlab-ci.example.yml"
README = CHART / "README.md"


def load_ci() -> dict[str, Any]:
    return yaml.safe_load(
        CI.read_text(encoding="utf-8")
    )


def deploy_script() -> str:
    payload = load_ci()
    job = payload["helm:deploy:wintermute-jira"]

    return "\n".join(job["script"])


def test_deployment_script_has_valid_shell_syntax() -> None:
    completed = subprocess.run(
        ["sh", "-n"],
        input=deploy_script(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr


def test_deployment_uses_helm_without_kubectl() -> None:
    script = deploy_script()

    assert "command -v helm" in script
    assert "helm upgrade" in script
    assert '--namespace "${KUBE_NAMESPACE}"' in script

    for forbidden in (
        "kubectl",
        "python3",
        "apply-secrets.py",
        "WINTERMUTE_CREATE_NAMESPACE",
        "--create-namespace",
    ):
        assert forbidden not in script


def test_deployment_does_not_require_secret_values() -> None:
    script = deploy_script()

    for forbidden in (
        "ARTIFACTORY_USERNAME",
        "ARTIFACTORY_PASSWORD",
        "BLACKDUCK_API_TOKEN",
        "JIRA_USER",
        "JIRA_API_TOKEN",
        "CA_BUNDLE_FILE",
    ):
        assert forbidden not in script


def test_deployment_references_manual_resources() -> None:
    payload = load_ci()
    variables = payload["variables"]
    script = deploy_script()

    assert (
        variables["WINTERMUTE_IMAGE_PULL_SECRET"]
        == "wintermute-registry-credentials"
    )
    assert (
        variables["WINTERMUTE_RUNTIME_SECRET"]
        == "blackduck-wintermute-credentials"
    )
    assert (
        variables["WINTERMUTE_CA_BUNDLE_CONFIGMAP"]
        == ""
    )

    assert (
        "imagePullSecrets[0].name="
        "${WINTERMUTE_IMAGE_PULL_SECRET}"
        in script
    )
    assert (
        "credentials.existingSecret="
        "${WINTERMUTE_RUNTIME_SECRET}"
        in script
    )
    assert (
        "caBundle.existingConfigMap="
        "${WINTERMUTE_CA_BUNDLE_CONFIGMAP}"
        in script
    )


def test_documentation_describes_manual_resources() -> None:
    text = README.read_text(encoding="utf-8")

    for required in (
        "wintermute-registry-credentials",
        "blackduck-wintermute-credentials",
        "does not need kubectl or Python",
        "must already exist",
        "WINTERMUTE_CA_BUNDLE_CONFIGMAP=",
    ):
        assert required in text
