from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (
    ROOT
    / "scripts"
    / "nonargo"
    / "no_argo_jira_k8s.ps1"
)


def test_windows_script_is_safe_by_default() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    lowered = text.casefold()

    assert '"dry-run"' in text
    assert '"10Gi"' in text
    assert '"false"' in text
    assert "CONFIRM_APPLY=APPLY" in text
    assert "blackduck-jira-pipeline" in text
    assert "render_jira_cronjob.py" in text

    for forbidden in (
        "workflowtemplate",
        "cronworkflow",
        "argoproj.io",
    ):
        assert forbidden not in lowered


def test_windows_script_contains_no_credentials() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    for forbidden in (
        "ghp_",
        "github_pat_",
        "Bearer ey",
        "Basic ey",
    ):
        assert forbidden not in text


def test_windows_script_uses_secure_prompts() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert "Read-Host $Prompt -AsSecureString" in text
    assert "BLACKDUCK_API_TOKEN" in text
    assert "JIRA_API_TOKEN" in text
    assert "REGISTRY_PASSWORD" in text


def test_windows_script_parses_when_powershell_is_available() -> None:
    powershell = (
        shutil.which("pwsh")
        or shutil.which("powershell")
    )

    if not powershell:
        pytest.skip(
            "PowerShell is unavailable"
        )

    completed = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-Command",
            (
                "$tokens=$null;"
                "$errors=$null;"
                "[System.Management.Automation.Language.Parser]"
                "::ParseFile("
                f"'{SCRIPT}',"
                "[ref]$tokens,"
                "[ref]$errors)"
                " | Out-Null;"
                "if($errors.Count){"
                "$errors | ForEach-Object {"
                "Write-Error $_.Message"
                "}; exit 1}"
            ),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout
