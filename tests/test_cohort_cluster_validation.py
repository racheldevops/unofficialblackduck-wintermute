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
  workflowSpec:
    arguments:
      parameters:
        - name: jira-mode
          value: dry-run
        - name: datadog-mode
          value: dry-run
        - name: scm-mode
          value: disabled
---
apiVersion: argoproj.io/v1alpha1
kind: WorkflowTemplate
metadata:
  name: blackduck-wintermute-cohort
  namespace: blackduck-wintermute
spec:
  arguments:
    parameters:
      - name: source-image
        value: registry.example/security/blackduck-wintermute-source:abc123
      - name: jira-image
        value: registry.example/security/blackduck-wintermute-jira:abc123
      - name: datadog-image
        value: registry.example/security/blackduck-wintermute-datadog:abc123
      - name: scm-image
        value: registry.example/security/blackduck-wintermute-scm:abc123
  templates:
    - name: validate-modes
      script:
        image: '{{workflow.parameters.source-image}}'
    - name: source
      container:
        image: '{{workflow.parameters.source-image}}'
    - name: jira
      container:
        image: '{{workflow.parameters.jira-image}}'
    - name: datadog
      container:
        image: '{{workflow.parameters.datadog-image}}'
    - name: scm
      container:
        image: '{{workflow.parameters.scm-image}}'
    - name: finalize
      container:
        image: '{{workflow.parameters.source-image}}'
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
    datadog_template = (
        "    - name: datadog\n"
        "      container:\n"
        "        image: "
        "'{{workflow.parameters.datadog-image}}'\n"
    )
    manifest = valid_manifest()

    assert datadog_template in manifest

    errors = validator.validate_rendered_manifest(
        manifest.replace(
            datadog_template,
            "",
            1,
        ),
        "blackduck-wintermute",
    )

    assert any(
        "runtime datadog image parameter"
        in error
        for error in errors
    )


def test_missing_scm_image_is_rejected() -> None:
    scm_template = (
        "    - name: scm\n"
        "      container:\n"
        "        image: "
        "'{{workflow.parameters.scm-image}}'\n"
    )
    manifest = valid_manifest()

    assert scm_template in manifest

    errors = validator.validate_rendered_manifest(
        manifest.replace(
            scm_template,
            "",
            1,
        ),
        "blackduck-wintermute",
    )

    assert any(
        "runtime scm image parameter"
        in error
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
    assert (
        "blackduck-wintermute-scm-credentials"
        in names
    )


def test_disabled_scm_does_not_require_scm_secret() -> None:
    secrets = validator.required_secrets_for_manifest(
        valid_manifest()
    )

    assert (
        "blackduck-wintermute-scm-credentials"
        not in secrets
    )


def test_enabled_scm_requires_scm_secret() -> None:
    manifest = valid_manifest().replace(
        "name: scm-mode\n          value: disabled",
        "name: scm-mode\n          value: read-only",
        1,
    )
    secrets = validator.required_secrets_for_manifest(
        manifest
    )

    assert (
        "blackduck-wintermute-scm-credentials"
        in secrets
    )


def test_redaction_hides_values_but_preserves_booleans() -> None:
    value = (
        "BLACKDUCK_API_TOKEN=secret-value\n"
        "GITHUB_TOKEN=another-secret\n"
        "automountServiceAccountToken: false"
    )
    rendered = validator.redact(value)

    assert "secret-value" not in rendered
    assert "another-secret" not in rendered
    assert (
        "automountServiceAccountToken: false"
        in rendered
    )
