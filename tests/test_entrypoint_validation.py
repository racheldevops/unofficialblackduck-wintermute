from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_entrypoints.py"
SPEC = importlib.util.spec_from_file_location(
    "validate_entrypoints",
    SCRIPT,
)
assert SPEC is not None
assert SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


def test_all_declared_entrypoints_import_and_show_help() -> None:
    result = validator.validate_entrypoints(ROOT)

    assert result["script_count"] > 0
    assert result["ok"] is True
    assert all(
        item["ok"]
        for item in result["targets"]
    )
    assert all(
        item["ok"]
        for item in result["module_help"]
    )


def test_validation_report_does_not_contain_environment_secrets(
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "BLACKDUCK_API_TOKEN",
        "must-not-appear",
    )

    result = validator.validate_entrypoints(ROOT)
    rendered = str(result)

    assert "must-not-appear" not in rendered
