from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def output_root() -> Path:
    return Path(os.getenv("HARNESS_OUTPUT_DIR", ".harness")).expanduser()


def jira_output_path(*parts: str) -> str:
    return str(output_root().joinpath("jira", *parts))


def datadog_output_path(*parts: str) -> str:
    return str(output_root().joinpath("datadog", *parts))


def package_path(*parts: str) -> str:
    return str(Path(__file__).resolve().parent.joinpath(*parts))


def ensure_parent_dir(path: str | os.PathLike[str] | None) -> None:
    if path in (None, "", "-"):
        return

    parent = Path(path).expanduser().parent
    parent.mkdir(parents=True, exist_ok=True)


def compact_path(value: Any) -> str:
    return str(Path(str(value)).expanduser())
