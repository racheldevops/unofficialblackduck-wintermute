from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (
    ROOT
    / "scripts"
    / "validate_cohort_cluster.py"
)
SPEC = importlib.util.spec_from_file_location(
    "validate_cohort_cluster",
    SCRIPT,
)
assert SPEC is not None
assert SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)


def valid_manifest() -> str:
    return """
apiVersion: argoproj.io/v1alpha1
kind: CronWorkflow
metadata:
  name: blackduck-wintermute-cohort
  namespace: blackduck-wintermute
spec:
  suspend: true
---
apiVersion: argoproj.io/v1alpha1
kind: WorkflowTemplate
metadata:
  name: blackduck-wintermute-cohort
  namespace: blackduck-wintermute
spec:
  templates:
    - name: validate-modes
      script:
        image: registry.example/security/blackduck-wintermute-source:abc123
    - name: source
      container:
        image: registry.example/security/blackduck-wintermute-source:abc123
    - name: jira
      container:
        image: registry.example/security/blackduck-wintermute-jira:abc123
    - name: datadog
      container:
        image: registry.example/security/blackduck-wintermute-datadog:abc123
"""


def test_valid_rendered_manifest_passes_policy() -> None:
    assert validator.validate_rendered_manifest(
        valid_manifest(),
        "blackduck-wintermute",
    ) == []


def test_placeholders_are_rejected() -> None:
    errors = validator.validate_rendered_manifest(
        valid_manifest().replace(
            "registry.example",
            "registry.invalid",
        ),
        "blackduck-wintermute",
    )

    assert any(
        "registry.invalid" in error
        for error in errors
    )


def test_missing_destination_image_is_rejected() -> None:
    errors = validator.validate_rendered_manifest(
        valid_manifest().replace(
            "    - name: datadog\n"
            "      container:\n"
            "        image: registry.example/security/"
            "blackduck-wintermute-datadog:abc123\n",
            "",
        ),
        "blackduck-wintermute",
    )

    assert any(
        "datadog image" in error
        for error in errors
    )


def test_validator_never_requires_secret_contents() -> None:
    names = validator.REQUIRED_SECRETS

    assert (
        "blackduck-wintermute-blackduck-credentials"
        in names
    )
    assert (
        "blackduck-wintermute-jira-credentials"
        in names
    )
    assert (
        "blackduck-wintermute-datadog-credentials"
        in names
    )


def test_redaction_hides_values_but_preserves_booleans() -> None:
    value = (
        "BLACKDUCK_API_TOKEN=secret-value\n"
        "automountServiceAccountToken: false"
    )
    rendered = validator.redact(value)

    assert "secret-value" not in rendered
    assert (
        "automountServiceAccountToken: false"
        in rendered
    )
