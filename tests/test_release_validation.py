from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_release.py"
SPEC = importlib.util.spec_from_file_location(
    "validate_release",
    SCRIPT,
)
assert SPEC is not None
assert SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


def valid_manifest() -> str:
    return """
apiVersion: batch/v1
kind: CronJob
spec:
  suspend: true
  jobTemplate:
    spec:
      template:
        spec:
          automountServiceAccountToken: false
          securityContext:
            runAsNonRoot: true
          containers:
            - name: wintermute
              args:
                - --dry-run
                - --resolve-bom-names
                - --workers
                - "8"
                - --parent-workers
                - "8"
                - --rollup-workers
                - "8"
              resources:
                requests:
                  cpu: "1"
                  memory: 1Gi
                limits:
                  cpu: "4"
                  memory: 4Gi
              securityContext:
                readOnlyRootFilesystem: true
                allowPrivilegeEscalation: false
              volumeMounts:
                - mountPath: /var/lib/blackduck-wintermute
          volumes:
            - persistentVolumeClaim:
                claimName: blackduck-wintermute-data
"""


def test_valid_manifest_passes() -> None:
    assert validator.validate_manifest(
        valid_manifest()
    ) == []


def test_manifest_rejects_old_name_and_missing_workers() -> None:
    errors = validator.validate_manifest(
        valid_manifest()
        .replace(
            "blackduck-wintermute-data",
            "blackduck-harness-data",
        )
        .replace(
            '                - --rollup-workers\n'
            '                - "8"\n',
            "",
        )
    )

    assert any(
        "--rollup-workers" in error
        for error in errors
    )
    assert any(
        "blackduck-harness" in error
        for error in errors
    )


def test_redaction_hides_secret_values() -> None:
    rendered = validator.redact(
        "api_token=secret-value password: another"
    )

    assert "secret-value" not in rendered
    assert "another" not in rendered


def test_redaction_preserves_kubernetes_boolean_fields() -> None:
    value = "automountServiceAccountToken: false"

    assert validator.redact(value) == value
