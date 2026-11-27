from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = ROOT / "scripts"


def load_script(path: Path) -> ModuleType:
    relative = path.relative_to(ROOT).as_posix()
    digest = hashlib.sha256(relative.encode("utf-8")).hexdigest()[:16]
    name = f"_wintermute_script_test_{digest}"
    specification = importlib.util.spec_from_file_location(name, path)

    if specification is None or specification.loader is None:
        raise RuntimeError(f"Could not create import specification for {path}")

    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module

    try:
        specification.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise

    return module


def test_scan_bootstrap_job_error_handler(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = load_script(SCRIPTS_ROOT / "run_scan_bootstrap_job.py")

    def fail() -> None:
        raise RuntimeError("expected test failure")

    monkeypatch.setattr(module, "parse_args", fail)

    assert module.main() == 2
    assert "ERROR: expected test failure" in capsys.readouterr().err


def test_scan_bootstrap_result_supports_group_list(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = load_script(SCRIPTS_ROOT / "run_scan_bootstrap_job.py")
    result_path = tmp_path / "result"

    module.print_access_result(
        phase="test",
        result={
            "plan_id": "plan-one",
            "plan_digest": "sha256:" + "a" * 64,
            "mode": "dry-run",
            "status": "ok",
            "outcome": "planned",
            "estimated_writes": 1,
            "writes": 0,
            "requests": 3,
            "before": {
                "consumer_groups": ["bd-releng", "platform"],
                "projects": [{"project": "rhorner/wintermute"}],
            },
        },
        path=result_path,
    )
    rendered = capsys.readouterr().out

    assert '"consumer_groups": [' in rendered
    assert '"bd-releng"' in rendered
    assert '"platform"' in rendered
