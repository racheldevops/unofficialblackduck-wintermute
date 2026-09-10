from __future__ import annotations

from collections.abc import Sequence

from wintermute.scm.onboarding.setup import main as setup_main


def configure_gitlab_token() -> None:
    """Compatibility hook; credentials must now be supplied explicitly."""
    return None


def main(argv: Sequence[str] | None = None) -> int:
    return setup_main(list(argv) if argv is not None else None)


__all__ = ["configure_gitlab_token", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
