from __future__ import annotations

import importlib.util
import xml.etree.ElementTree as ET
from pathlib import Path
from types import ModuleType

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (
    ROOT
    / "scripts"
    / "run_scm_coverage_read_only.py"
)
CONFIGURATION = (
    ROOT
    / ".run"
    / "SCM_GitHub_Coverage_Read_Only.run.xml"
)


def load_runner() -> ModuleType:
    spec = (
        importlib.util.spec_from_file_location(
            "run_scm_coverage_read_only",
            SCRIPT,
        )
    )

    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(
        spec
    )
    spec.loader.exec_module(module)

    return module


def test_intellij_scm_run_is_shared_and_read_only() -> None:
    root = ET.parse(
        CONFIGURATION
    ).getroot()
    configuration = root.find(
        "configuration"
    )

    assert configuration is not None
    assert configuration.get("name") == (
        "SCM GitHub Coverage Read Only"
    )
    assert configuration.get("type") == (
        "PythonConfigurationType"
    )

    options = {
        option.get("name"): option.get("value")
        for option in configuration.findall(
            "option"
        )
    }

    assert options["SCRIPT_NAME"] == (
        "$PROJECT_DIR$/scripts/"
        "run_scm_coverage_read_only.py"
    )
    assert (
        "--output-root "
        "$PROJECT_DIR$/.wintermute"
        in options["PARAMETERS"]
    )

    text = CONFIGURATION.read_text(
        encoding="utf-8",
    ).casefold()

    for forbidden in (
        "github_token",
        "blackduck_api_token",
        "--apply",
        "--api-token",
    ):
        assert forbidden not in text


def test_runner_orders_inventory_before_coverage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runner = load_runner()
    calls: list[
        tuple[str, list[str]]
    ] = []

    for name, value in (
        ("GITHUB_ORG", "acme"),
        ("GITHUB_TOKEN", "github-token"),
        (
            "BLACKDUCK_URL",
            "https://bd.example",
        ),
        (
            "BLACKDUCK_API_TOKEN",
            "blackduck-token",
        ),
    ):
        monkeypatch.setenv(
            name,
            value,
        )

    def inventory_operation(
        arguments: list[str] | None,
    ) -> int:
        selected = list(arguments or [])
        calls.append(
            ("inventory", selected)
        )
        return 0

    def coverage_operation(
        arguments: list[str] | None,
    ) -> int:
        selected = list(arguments or [])
        calls.append(
            ("coverage", selected)
        )
        return 0

    result = runner.run(
        runner.parse_args(
            [
                "--output-root",
                str(tmp_path),
                "--snapshot-id",
                "test-run",
            ]
        ),
        inventory_operation=(
            inventory_operation
        ),
        coverage_operation=(
            coverage_operation
        ),
    )

    assert result == 0
    assert [
        name
        for name, _
        in calls
    ] == [
        "inventory",
        "coverage",
    ]
    assert "--snapshot-id" in calls[0][1]
    assert "test-run" in calls[0][1]
    assert "--scm-snapshot" in calls[1][1]
    assert str(
        tmp_path
        / "scm"
        / "inventory"
        / "snapshots"
        / "test-run"
    ) in calls[1][1]


def test_runner_requires_credentials(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runner = load_runner()

    for name in (
        "GITHUB_ORG",
        "GITHUB_TOKEN",
        "BLACKDUCK_URL",
        "BLACKDUCK_API_TOKEN",
    ):
        monkeypatch.delenv(
            name,
            raising=False,
        )

    with pytest.raises(
        RuntimeError,
        match="Missing required",
    ):
        runner.run(
            runner.parse_args(
                [
                    "--output-root",
                    str(tmp_path),
                ]
            )
        )


def test_runner_uses_integer_timeout() -> None:
    runner = load_runner()
    args = runner.parse_args([])

    assert type(args.timeout) is int
    assert args.timeout == 30


def test_runner_defaults_to_metadata_overview() -> None:
    runner = load_runner()
    args = runner.parse_args([])

    assert args.collect_direct_scan_evidence is False
