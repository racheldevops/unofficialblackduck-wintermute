from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (
    ROOT
    / ".github"
    / "workflows"
    / "cohort-kubernetes-deploy.yml"
)


def workflow_text() -> str:
    return WORKFLOW.read_text(
        encoding="utf-8"
    )


def test_deployment_is_manual_only() -> None:
    text = workflow_text()

    assert "workflow_dispatch:" in text
    assert "\n  push:" not in text
    assert "\n  pull_request:" not in text


def test_deployment_supports_render_diff_and_apply() -> None:
    text = workflow_text()

    for operation in (
        "render",
        "diff",
        "apply",
    ):
        assert f"          - {operation}" in text

    assert "kubectl diff" in text
    assert "kubectl apply" in text
    assert "--server-side" in text


def test_apply_requires_confirmation() -> None:
    text = workflow_text()

    assert "confirm_apply:" in text
    assert (
        "Apply mode requires confirm_apply=true"
        in text
    )
    assert (
        'inputs.confirm_apply }}" == "true"'
        in text
    )


def test_deployment_checks_argo_crds() -> None:
    text = workflow_text()

    assert (
        "workflowtemplates.argoproj.io"
        in text
    )
    assert (
        "cronworkflows.argoproj.io"
        in text
    )


def test_deployment_uses_immutable_renderer() -> None:
    text = workflow_text()

    assert (
        "scripts/render_cohort_manifest.py"
        in text
    )
    assert "--image-tag" in text
    assert "sha256sum" in text
    assert "rendered-cohort-manifest.yaml" in text
    assert ":latest" not in text


def test_deployment_runs_cluster_preflight_before_diff() -> None:
    text = workflow_text()

    preflight = text.index(
        "Validate cluster prerequisites"
    )
    diff = text.index("      - name: Diff")

    assert preflight < diff
    assert (
        "scripts/validate_cohort_cluster.py"
        in text
    )
    assert "--require-secrets" in text
    assert "cohort-cluster-preflight.json" in text
