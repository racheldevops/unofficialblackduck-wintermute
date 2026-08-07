from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (
    ROOT
    / "scripts"
    / "local_cohort_full_apply.zsh"
)


def test_full_apply_has_two_confirmation_gates() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert "JIRA PROJECT REVIEWED" in text
    assert "APPLY FULL COHORT" in text
    assert text.index(
        "jira-mode dry-run"
    ) < text.index(
        "jira-mode apply"
    )


def test_full_apply_has_hard_caps() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert "--jira-max-create 5000" in text
    assert "--datadog-max-send 100" in text
    assert "archive_local_jira_state.zsh" in text
