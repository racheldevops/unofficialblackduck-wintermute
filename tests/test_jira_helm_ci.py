from __future__ import annotations

import ast
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHART = (
    ROOT
    / "deploy"
    / "charts"
    / "blackduck-wintermute-jira"
)
CI = CHART / "ci" / "gitlab-ci.example.yml"
README = CHART / "README.md"


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


def script_value(text: str) -> str:
    block = yaml_block(
        yaml_block(
            text,
            "helm:deploy:wintermute-jira",
        ),
        "script",
    )
    lines = block.splitlines()
    output: list[str] = []
    index = 0

    while index < len(lines):
        line = lines[index]
        stripped = line.strip()

        if not stripped:
            output.append("")
            index += 1
            continue

        if stripped.startswith("- "):
            value = stripped[2:].strip()

            if value.startswith(("|", ">")):
                item_indent = indentation(line)
                content: list[str] = []
                index += 1

                while index < len(lines):
                    candidate = lines[index]

                    if (
                        candidate.strip()
                        and indentation(candidate)
                        <= item_indent
                    ):
                        break

                    content.append(candidate)
                    index += 1

                content_indents = [
                    indentation(candidate)
                    for candidate in content
                    if candidate.strip()
                ]
                remove = (
                    min(content_indents)
                    if content_indents
                    else 0
                )
                output.extend(
                    candidate[remove:]
                    if len(candidate) >= remove
                    else ""
                    for candidate in content
                )
                continue

            output.append(
                scalar_text(value)
            )

        index += 1

    return "\n".join(output)


def ci_text() -> str:
    return CI.read_text(encoding="utf-8")


def deploy_script() -> str:
    return script_value(ci_text())


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
    assert (
        '--namespace "${KUBE_NAMESPACE}"'
        in script
    )

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
    variables = yaml_block(
        ci_text(),
        "variables",
    )
    script = deploy_script()

    assert yaml_value(
        variables,
        "WINTERMUTE_IMAGE_PULL_SECRET",
    ) == "wintermute-registry-credentials"
    assert yaml_value(
        variables,
        "WINTERMUTE_RUNTIME_SECRET",
    ) == "blackduck-wintermute-credentials"
    assert yaml_value(
        variables,
        "WINTERMUTE_CA_BUNDLE_CONFIGMAP",
    ) == ""

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
