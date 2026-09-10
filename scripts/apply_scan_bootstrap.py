#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

from wintermute.scm.onboarding.bootstrap import (
    load_verified_bootstrap_plan,
)


CONFIRMATION = (
    "CREATE CENTRAL SCAN REPOSITORY"
)
PLAN_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$"
)


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def output_root() -> Path:
    configured = os.getenv(
        "WINTERMUTE_OUTPUT_DIR",
        "",
    ).strip()
    root = project_root()

    if not configured:
        return root / ".wintermute"

    selected = Path(configured).expanduser()

    return (
        selected
        if selected.is_absolute()
        else root / selected
    )


def required_value(
    argument: str,
    environment_name: str,
) -> str:
    selected = (
        argument
        or os.getenv(
            environment_name,
            "",
        )
    ).strip()

    if not selected:
        raise RuntimeError(
            f"{environment_name} must be set"
        )

    return selected


def run(
    args: argparse.Namespace,
) -> int:
    plan_id = required_value(
        args.plan_id,
        "WINTERMUTE_BOOTSTRAP_PLAN_ID",
    )
    expected_digest = required_value(
        args.expected_plan_digest,
        "WINTERMUTE_BOOTSTRAP_PLAN_DIGEST",
    )
    confirmation = required_value(
        args.confirmation,
        "WINTERMUTE_BOOTSTRAP_APPLY_CONFIRM",
    )

    if (
        PLAN_ID_PATTERN.fullmatch(plan_id)
        is None
    ):
        raise RuntimeError(
            "Bootstrap plan ID is invalid"
        )

    if confirmation != CONFIRMATION:
        raise RuntimeError(
            "Apply confirmation must exactly equal: "
            f"{CONFIRMATION}"
        )

    plan_directory = (
        output_root()
        / "scm"
        / "onboarding"
        / "bootstrap-plans"
        / plan_id
    )
    loaded = load_verified_bootstrap_plan(
        plan_directory
    )

    if loaded.digest != expected_digest:
        raise RuntimeError(
            "WINTERMUTE_BOOTSTRAP_PLAN_DIGEST "
            "does not match the verified plan"
        )

    providers = {
        str(repository["provider"])
        for repository
        in loaded.plan["repositories"]
    }

    if (
        "gitlab" in providers
        and not os.getenv(
            "GITLAB_ACTION_TOKEN",
            "",
        ).strip()
    ):
        raise RuntimeError(
            "GITLAB_ACTION_TOKEN must be set"
        )

    if (
        "github" in providers
        and not os.getenv(
            "GITHUB_ACTION_TOKEN",
            "",
        ).strip()
    ):
        raise RuntimeError(
            "GITHUB_ACTION_TOKEN must be set"
        )

    command = [
        sys.executable,
        "-m",
        (
            "wintermute.scm.onboarding."
            "bootstrap_cli"
        ),
        "execute",
        "--plan",
        str(plan_directory),
        "--apply",
        "--confirm-apply",
        "--expected-plan-digest",
        expected_digest,
        "--max-writes",
        str(args.max_writes),
    ]

    if args.insecure:
        command.append("--insecure")
    elif args.ca_bundle:
        command.extend(
            [
                "--ca-bundle",
                args.ca_bundle,
            ]
        )

    completed = subprocess.run(
        command,
        cwd=project_root(),
        env=dict(os.environ),
        stdin=subprocess.DEVNULL,
        check=False,
    )

    return completed.returncode


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Apply one explicitly selected and "
            "verified central bootstrap plan."
        )
    )
    parser.add_argument(
        "--plan-id",
        default="",
    )
    parser.add_argument(
        "--expected-plan-digest",
        default="",
    )
    parser.add_argument(
        "--confirmation",
        default="",
    )
    parser.add_argument(
        "--max-writes",
        type=int,
        default=4,
    )
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument(
        "--insecure",
        action="store_true",
    )
    tls.add_argument(
        "--ca-bundle",
    )
    args = parser.parse_args()

    if args.max_writes < 1:
        parser.error(
            "--max-writes must be positive"
        )

    return args


def main() -> int:
    try:
        return run(parse_args())
    except KeyboardInterrupt:
        return 130
    except (
        OSError,
        RuntimeError,
        ValueError,
    ) as error:
        print(
            f"ERROR: {error}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
