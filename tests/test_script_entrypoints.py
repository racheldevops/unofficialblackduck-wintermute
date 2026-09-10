from __future__ import annotations

import ast
import hashlib
import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = ROOT / "scripts"
SECRET_NAME_RE = re.compile(
    r"(TOKEN|PASSWORD|SECRET|API_KEY|AUTHORIZATION)",
    re.IGNORECASE,
)


def python_scripts() -> tuple[Path, ...]:
    return tuple(
        sorted(
            path
            for path in SCRIPTS_ROOT.rglob("*.py")
            if "__pycache__" not in path.parts
        )
    )


def relative_name(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def module_name(path: Path) -> str:
    relative = relative_name(path)
    digest = hashlib.sha256(
        relative.encode("utf-8")
    ).hexdigest()[:16]

    return (
        f"_wintermute_script_test_{digest}"
    )


def load_script(path: Path) -> ModuleType:
    name = module_name(path)
    specification = (
        importlib.util.spec_from_file_location(
            name,
            path,
        )
    )

    if (
        specification is None
        or specification.loader is None
    ):
        raise RuntimeError(
            "Could not create import "
            f"specification for {path}"
        )

    module = importlib.util.module_from_spec(
        specification
    )
    sys.modules[name] = module

    try:
        specification.loader.exec_module(
            module
        )
    except BaseException:
        sys.modules.pop(name, None)
        raise

    return module


def imports_argparse(path: Path) -> bool:
    tree = ast.parse(
        path.read_text(encoding="utf-8"),
        filename=str(path),
    )

    for node in tree.body:
        if isinstance(node, ast.Import):
            if any(
                alias.name == "argparse"
                for alias in node.names
            ):
                return True

        if (
            isinstance(node, ast.ImportFrom)
            and node.module == "argparse"
        ):
            return True

    return False


def user_facing_scripts() -> tuple[
    Path,
    ...
]:
    return tuple(
        path
        for path in python_scripts()
        if (
            imports_argparse(path)
            or path.name.startswith("run_")
        )
    )


def clean_environment() -> dict[str, str]:
    environment = {
        name: value
        for name, value in os.environ.items()
        if not SECRET_NAME_RE.search(name)
    }
    existing_python_path = environment.get(
        "PYTHONPATH",
        "",
    )
    environment["PYTHONPATH"] = (
        os.pathsep.join(
            value
            for value in (
                str(ROOT / "src"),
                existing_python_path,
            )
            if value
        )
    )
    environment[
        "PYTHONDONTWRITEBYTECODE"
    ] = "1"

    return environment


@pytest.mark.parametrize(
    "script_path",
    python_scripts(),
    ids=relative_name,
)
def test_every_python_script_imports(
    script_path: Path,
) -> None:
    module = load_script(script_path)

    assert callable(
        getattr(module, "main", None)
    ), (
        f"{relative_name(script_path)} "
        "does not expose a callable main()"
    )


@pytest.mark.parametrize(
    "script_path",
    user_facing_scripts(),
    ids=relative_name,
)
def test_user_facing_script_help(
    script_path: Path,
) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(script_path),
            "--help",
        ],
        cwd=ROOT,
        env=clean_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, (
        f"{relative_name(script_path)} "
        "--help exited with "
        f"{completed.returncode}:\n"
        f"{completed.stdout[-2000:]}"
    )


def test_scan_bootstrap_job_error_handler(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = load_script(
        SCRIPTS_ROOT
        / "run_scan_bootstrap_job.py"
    )

    def fail() -> None:
        raise RuntimeError(
            "expected test failure"
        )

    monkeypatch.setattr(
        module,
        "parse_args",
        fail,
    )

    assert module.main() == 2
    assert (
        "ERROR: expected test failure"
        in capsys.readouterr().err
    )


def test_scan_bootstrap_result_supports_group_list(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = load_script(
        SCRIPTS_ROOT
        / "run_scan_bootstrap_job.py"
    )
    result_path = tmp_path / "result"

    module.print_access_result(
        phase="test",
        result={
            "plan_id": "plan-one",
            "plan_digest": (
                "sha256:" + "a" * 64
            ),
            "mode": "dry-run",
            "status": "ok",
            "outcome": "planned",
            "estimated_writes": 1,
            "writes": 0,
            "requests": 3,
            "before": {
                "consumer_groups": [
                    "bd-releng",
                    "platform",
                ],
                "projects": [
                    {
                        "project": (
                            "rhorner/wintermute"
                        )
                    }
                ],
            },
        },
        path=result_path,
    )
    rendered = capsys.readouterr().out

    assert '"consumer_groups": [' in rendered
    assert '"bd-releng"' in rendered
    assert '"platform"' in rendered
