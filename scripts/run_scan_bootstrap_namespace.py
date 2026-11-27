#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def output_root() -> Path:
    root = project_root()
    configured = os.getenv(
        "WINTERMUTE_OUTPUT_DIR",
        "",
    ).strip()

    if not configured:
        return root / ".wintermute"

    selected = Path(configured).expanduser()

    return (
        selected
        if selected.is_absolute()
        else root / selected
    )


def latest_ready(
    root: Path,
) -> Path:
    candidates = sorted(
        (
            path
            for path in root.iterdir()
            if (
                path.is_dir()
                and (path / "READY").is_file()
            )
        ),
        key=lambda path: path.name,
        reverse=True,
    )

    if not candidates:
        raise RuntimeError(
            f"No ready artifacts under {root}"
        )

    return candidates[0].resolve()


def run_command(
    command: list[str],
) -> int:
    completed = subprocess.run(
        command,
        cwd=project_root(),
        env=dict(os.environ),
        stdin=subprocess.DEVNULL,
        check=False,
    )

    if completed.returncode != 0:
        raise RuntimeError(
            "Command exited with code "
            f"{completed.returncode}"
        )

    return completed.returncode


def namespace() -> tuple[str, str]:
    selected = os.getenv(
        "GITLAB_NAMESPACE",
        "",
    ).strip("/")
    namespace_type = os.getenv(
        "GITLAB_NAMESPACE_TYPE",
        "",
    ).strip().casefold()

    if not selected:
        selected = os.getenv(
            "GITLAB_GROUP",
            "",
        ).strip("/")
        namespace_type = (
            namespace_type or "group"
        )

    if not selected:
        raise RuntimeError(
            "GITLAB_NAMESPACE or GITLAB_GROUP "
            "must be set"
        )

    if namespace_type not in {
        "group",
        "user",
    }:
        raise RuntimeError(
            "GITLAB_NAMESPACE_TYPE must be "
            "group or user"
        )

    return selected, namespace_type


def project_name(
    selected_namespace: str,
) -> str:
    full_path = os.getenv(
        "GITLAB_CENTRAL_PROJECT",
        (
            f"{selected_namespace}/"
            "wintermute-security-scans"
        ),
    ).strip("/")

    prefix = f"{selected_namespace}/"

    if not full_path.startswith(prefix):
        raise RuntimeError(
            "GITLAB_CENTRAL_PROJECT must "
            "belong to GITLAB_NAMESPACE"
        )

    name = full_path.rsplit("/", 1)[1]

    if not name:
        raise RuntimeError(
            "GITLAB_CENTRAL_PROJECT is invalid"
        )

    return name


def plan(
    args: argparse.Namespace,
) -> int:
    bundle = latest_ready(
        output_root()
        / "scm"
        / "onboarding"
        / "central-bundles"
    )
    selected_namespace, namespace_type = (
        namespace()
    )
    command = [
        sys.executable,
        "-m",
        (
            "wintermute.scm.onboarding."
            "bootstrap_cli"
        ),
        "plan",
        "--bundle",
        str(bundle),
        "--gitlab-namespace",
        selected_namespace,
        "--gitlab-namespace-type",
        namespace_type,
        "--gitlab-project",
        project_name(
            selected_namespace
        ),
        "--gitlab-default-branch",
        os.getenv(
            "GITLAB_CENTRAL_REF",
            "main",
        ),
    ]

    return run_command(command)


def dry_run(
    args: argparse.Namespace,
) -> int:
    bootstrap_plan = latest_ready(
        output_root()
        / "scm"
        / "onboarding"
        / "bootstrap-plans"
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
        str(bootstrap_plan),
        "--dry-run",
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

    return run_command(command)


def all_dry_run(
    args: argparse.Namespace,
) -> int:
    plan(args)
    return dry_run(args)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    for name in (
        "plan",
        "dry-run",
        "all-dry-run",
    ):
        selected = commands.add_parser(name)
        tls = (
            selected
            .add_mutually_exclusive_group()
        )
        tls.add_argument(
            "--insecure",
            action="store_true",
        )
        tls.add_argument(
            "--ca-bundle",
        )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        if args.command == "plan":
            return plan(args)

        if args.command == "dry-run":
            return dry_run(args)

        return all_dry_run(args)

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
