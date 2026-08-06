from __future__ import annotations

import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_general_blackduck_pull_entrypoint() -> None:
    payload = tomllib.loads(
        (ROOT / "pyproject.toml").read_text(
            encoding="utf-8"
        )
    )
    scripts = payload["project"]["scripts"]

    assert scripts["blackduck-wintermute-pull"] == (
        "wintermute.blackduck.cli:main"
    )
