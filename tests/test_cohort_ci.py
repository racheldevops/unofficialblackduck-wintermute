from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (
    ROOT
    / ".github"
    / "workflows"
    / "cohort-container-build.yml"
)


def test_cohort_workflow_builds_all_targets() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    for target in (
        "source",
        "jira",
        "datadog",
    ):
        assert f"target: {target}" in text
        assert f"image_suffix: {target}" in text


def test_cohort_workflow_tests_before_building() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "needs: test" in text
    assert "python -m pytest -q tests" in text
    assert (
        "python scripts/validate_entrypoints.py "
        "--require-installed"
        in text
    )


def test_cohort_workflow_push_is_manual_and_immutable() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "push_images:" in text
    assert "inputs.push_images" in text
    assert "${{ github.sha }}" in text
    assert "--push" in text
    assert ":latest" not in text
