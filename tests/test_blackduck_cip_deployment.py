from __future__ import annotations

from pathlib import Path


ROOT = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "cip-actions"
)


def test_cip_cronjob_safe_defaults() -> None:
    text = (
        ROOT / "cronjob.yaml"
    ).read_text(encoding="utf-8")

    assert "suspend: true" in text
    assert "concurrencyPolicy: Forbid" in text
    assert "backoffLimit: 0" in text
    assert "- --dry-run" in text
    assert "automountServiceAccountToken: false" in text
    assert "readOnlyRootFilesystem: true" in text
    assert "allowPrivilegeEscalation: false" in text


def test_cip_deployment_is_separate() -> None:
    text = (
        ROOT / "kustomization.yaml"
    ).read_text(encoding="utf-8")

    assert "pvc.yaml" in text
    assert "cronjob.yaml" in text
    assert "jira" not in text.casefold()
    assert "datadog" not in text.casefold()


def test_cip_targets_are_not_in_base() -> None:
    text = (
        ROOT
        / "config"
        / "cip-remediation.json"
    ).read_text(encoding="utf-8")

    assert "PROJECT_ID" not in text
    assert '"targets"' not in text
