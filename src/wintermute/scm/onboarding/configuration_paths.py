from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path


CONFIG_ENVIRONMENT_VARIABLE = "WINTERMUTE_ONBOARD_CONFIG"
LOCAL_CONFIGURATION_NAME = "wintermute-onboard.local.json"
EXAMPLE_CONFIGURATION_NAME = "wintermute-onboard.example.json"


def configuration_directory() -> Path:
    return Path(__file__).resolve().parent / "config"


def default_configuration_path(
    *,
    environment: Mapping[str, str] | None = None,
    directory: Path | None = None,
) -> str | None:
    selected_environment = os.environ if environment is None else environment
    configured = str(
        selected_environment.get(CONFIG_ENVIRONMENT_VARIABLE, "") or ""
    ).strip()

    if configured:
        # Do not silently fall back if an explicitly configured path is missing.
        return str(Path(configured).expanduser())

    root = configuration_directory() if directory is None else directory
    local = root / LOCAL_CONFIGURATION_NAME
    if local.is_file():
        return str(local.resolve())

    return None


def missing_configuration_message() -> str:
    return (
        "No onboarding configuration selected. Supply --config PATH, set "
        f"{CONFIG_ENVIRONMENT_VARIABLE}, or create "
        f"{configuration_directory() / LOCAL_CONFIGURATION_NAME}. "
        "Installed-package users should keep private configuration outside "
        "site-packages and select it with --config or the environment variable."
    )
