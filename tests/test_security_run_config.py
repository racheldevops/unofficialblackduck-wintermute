from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG = (
    ROOT
    / ".run"
    / "Security_GitGuardian_Scan.run.xml"
)


def test_gitguardian_run_configuration_is_shared() -> None:
    text = CONFIG.read_text(encoding="utf-8")

    assert (
        'name="Security - GitGuardian Scan"'
        in text
    )
    assert (
        "$PROJECT_DIR$/scripts/check_secrets.zsh"
        in text
    )
    assert (
        '<option name="INTERPRETER_PATH" '
        'value="/bin/zsh" />'
        in text
    )
