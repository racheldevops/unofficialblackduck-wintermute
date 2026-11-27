from __future__ import annotations

import os
from collections.abc import Mapping


def gitlab_action_token(
    environment: Mapping[str, str] | None = None,
) -> str:
    """Prefer an explicit action token; otherwise reuse the configured token."""
    selected = os.environ if environment is None else environment

    for name in ("GITLAB_ACTION_TOKEN", "GITLAB_TOKEN"):
        raw = selected.get(name, "")
        if not isinstance(raw, str):
            raise ValueError(f"{name} must be a string")
        if "\r" in raw or "\n" in raw:
            raise ValueError(f"{name} contains invalid characters")

        token = raw.strip()
        if token:
            return token

    raise RuntimeError("GITLAB_ACTION_TOKEN or GITLAB_TOKEN must be set")
