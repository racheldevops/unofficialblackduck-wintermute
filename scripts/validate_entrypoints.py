#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any


SECRET_NAME_RE = re.compile(
    r"(TOKEN|PASSWORD|SECRET|API_KEY|AUTHORIZATION)",
    re.IGNORECASE,
)
SECRET_VALUE_RE = re.compile(
    r"(?i)(token|password|secret|api[_-]?key)"
    r"([=:]\s*)(\S+)"
)


def clean_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if not SECRET_NAME_RE.search(key)
    }


def redact(value: str) -> str:
    return SECRET_VALUE_RE.sub(
        r"\1\2<redacted>",
        value,
    )


def load_scripts(
    project_root: Path,
) -> dict[str, str]:
    payload = tomllib.loads(
        (project_root / "pyproject.toml").read_text(
            encoding="utf-8"
        )
    )

    return {
        str(name): str(target)
        for name, target in (
            payload.get("project", {})
            .get("scripts", {})
            .items()
        )
    }


def validate_target(
    name: str,
    target: str,
) -> dict[str, Any]:
    module_name, separator, function_name = (
        target.partition(":")
    )

    if not separator:
        return {
            "name": name,
            "target": target,
            "ok": False,
            "error": "Entry point has no function target",
        }

    try:
        module = importlib.import_module(module_name)
        function = getattr(module, function_name)
    except Exception as error:
        return {
            "name": name,
            "target": target,
            "ok": False,
            "error": redact(str(error)),
        }

    return {
        "name": name,
        "target": target,
        "ok": callable(function),
        "error": (
            ""
            if callable(function)
            else "Target is not callable"
        ),
    }


def run_help(
    project_root: Path,
    name: str,
    target: str,
) -> dict[str, Any]:
    module_name, _, function_name = target.partition(
        ":"
    )
    source = (
        "import importlib,sys;"
        f"module=importlib.import_module({module_name!r});"
        f"function=getattr(module,{function_name!r});"
        f"sys.argv=[{name!r},'--help'];"
        "function()"
    )
    environment = clean_environment()
    existing_path = environment.get(
        "PYTHONPATH",
        "",
    )
    environment["PYTHONPATH"] = os.pathsep.join(
        part
        for part in (
            str(project_root / "src"),
            existing_path,
        )
        if part
    )

    completed = subprocess.run(
        [sys.executable, "-c", source],
        cwd=project_root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
        check=False,
    )

    return {
        "name": name,
        "return_code": completed.returncode,
        "ok": completed.returncode == 0,
        "error": (
            ""
            if completed.returncode == 0
            else redact(
                (completed.stdout or "")[-2000:]
            )
        ),
    }


def run_installed_help(
    name: str,
) -> dict[str, Any]:
    executable = shutil.which(name)

    if not executable:
        return {
            "name": name,
            "ok": False,
            "return_code": None,
            "error": "Installed command was not found",
        }

    completed = subprocess.run(
        [executable, "--help"],
        env=clean_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
        check=False,
    )

    return {
        "name": name,
        "ok": completed.returncode == 0,
        "return_code": completed.returncode,
        "error": (
            ""
            if completed.returncode == 0
            else redact(
                (completed.stdout or "")[-2000:]
            )
        ),
    }


def validate_entrypoints(
    project_root: Path,
    *,
    require_installed: bool = False,
) -> dict[str, Any]:
    scripts = load_scripts(project_root)
    targets = [
        validate_target(name, target)
        for name, target in sorted(
            scripts.items()
        )
    ]
    module_help = [
        run_help(project_root, name, target)
        for name, target in sorted(
            scripts.items()
        )
    ]
    installed_help = (
        [
            run_installed_help(name)
            for name in sorted(scripts)
        ]
        if require_installed
        else []
    )
    ok = (
        bool(scripts)
        and all(item["ok"] for item in targets)
        and all(
            item["ok"] for item in module_help
        )
        and all(
            item["ok"] for item in installed_help
        )
    )

    return {
        "ok": ok,
        "script_count": len(scripts),
        "targets": targets,
        "module_help": module_help,
        "installed_help": installed_help,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate Wintermute package entry points "
            "without contacting external services."
        )
    )
    parser.add_argument(
        "--project-root",
        default=str(
            Path(__file__).resolve().parents[1]
        ),
    )
    parser.add_argument(
        "--require-installed",
        action="store_true",
    )
    parser.add_argument(
        "--report",
        default=".validation-results/entrypoints.json",
    )
    args = parser.parse_args()

    project_root = Path(
        args.project_root
    ).resolve()
    result = validate_entrypoints(
        project_root,
        require_installed=args.require_installed,
    )
    report = project_root / args.report
    report.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    report.write_text(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        f"Validated {result['script_count']} "
        f"entry point(s): "
        f"{'PASS' if result['ok'] else 'FAIL'}"
    )
    print(f"Report: {report}")

    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
