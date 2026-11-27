from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from wintermute.file_lock import (
    FileLock,
    LockUnavailableError,
)
from wintermute.paths import output_root
from wintermute.scm.onboarding.bootstrap import (
    BootstrapArtifactError,
    load_verified_central_bundle,
)
from wintermute.scm.onboarding.central_upgrade import (
    CONFIRMATION,
    CentralUpgradeError,
    GitLabCentralUpgradeClient,
    build_upgrade_plan,
    execute_upgrade_plan,
    load_verified_upgrade_plan,
    write_upgrade_plan,
)
from wintermute.scm.providers.detection import (
    gitlab_rest_url,
)


def default_plan_root() -> Path:
    return (
        output_root()
        / "scm"
        / "onboarding"
        / "central-upgrade-plans"
    )


def default_result_root() -> Path:
    return (
        output_root()
        / "scm"
        / "onboarding"
        / "central-upgrade-results"
    )


def gitlab_base_url() -> str:
    return gitlab_rest_url(
        os.getenv(
            "GITLAB_REST_URL",
            "",
        )
        or os.getenv(
            "GITLAB_URL",
            "",
        )
        or os.getenv(
            "SCM_URL",
            "",
        )
        or "https://gitlab.com"
    )


def client(
    args: argparse.Namespace,
    *,
    mode: str,
) -> GitLabCentralUpgradeClient:
    token_name = (
        "GITLAB_ACTION_TOKEN"
        if mode == "apply"
        else "GITLAB_TOKEN"
    )
    token = os.getenv(
        token_name,
        "",
    ).strip()

    if not token:
        raise RuntimeError(
            f"{token_name} must be set"
        )

    return GitLabCentralUpgradeClient(
        "gitlab",
        gitlab_base_url(),
        token,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        request_interval_seconds=(
            args.request_interval_seconds
        ),
        insecure=args.insecure,
        ca_bundle=args.ca_bundle,
    )


def plan_command(
    args: argparse.Namespace,
) -> int:
    bundle = load_verified_central_bundle(
        args.bundle
    )
    read_client = client(
        args,
        mode="dry-run",
    )
    plan, desired, rollback = (
        build_upgrade_plan(
            read_client,
            bundle,
            project=args.project,
            branch=args.branch,
            expected_new_bundle_digest=(
                args.expected_new_bundle_digest
            ),
            expected_current_bundle_digest=(
                args.expected_current_bundle_digest
            ),
        )
    )
    directory = write_upgrade_plan(
        args.output_root,
        plan,
        desired,
        rollback,
    )
    loaded = load_verified_upgrade_plan(
        directory
    )

    print(
        json.dumps(
            {
                "phase": "plan",
                "status": "succeeded",
                "plan_id": plan["plan_id"],
                "plan_digest": loaded.digest,
                "plan_directory": str(
                    directory
                ),
                "project": plan["project"],
                "project_id": (
                    plan["project_id"]
                ),
                "branch": plan["branch"],
                "previous_source_bundle_id": (
                    plan[
                        "previous_source_bundle_id"
                    ]
                ),
                "previous_source_bundle_digest": (
                    plan[
                        "previous_source_bundle_digest"
                    ]
                ),
                "source_bundle_id": (
                    plan["source_bundle_id"]
                ),
                "source_bundle_digest": (
                    plan[
                        "source_bundle_digest"
                    ]
                ),
                "changed_file_count": (
                    plan[
                        "changed_file_count"
                    ]
                ),
                "actions": [
                    {
                        "action": (
                            value["action"]
                        ),
                        "path": value["path"],
                        "expected_current_sha256": (
                            value[
                                "expected_current_sha256"
                            ]
                        ),
                        "desired_sha256": (
                            value[
                                "desired_sha256"
                            ]
                        ),
                    }
                    for value in plan["actions"]
                ],
                "estimated_writes": (
                    plan["estimated_writes"]
                ),
                "requests": (
                    read_client.requests
                ),
                "remote_writes": 0,
                "mutation_allowed": (
                    plan["mutation_allowed"]
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )

    return 0


def execute_command(
    args: argparse.Namespace,
) -> int:
    loaded = load_verified_upgrade_plan(
        args.plan
    )
    selected_client = client(
        args,
        mode=args.mode,
    )
    code, result, path = (
        execute_upgrade_plan(
            loaded,
            selected_client,
            mode=args.mode,
            result_root=args.result_root,
            maximum_writes=(
                args.max_writes
            ),
            confirm_apply=(
                args.confirm_apply
            ),
            expected_plan_digest=(
                args.expected_plan_digest
            ),
        )
    )

    print(
        json.dumps(
            {
                "phase": "execute",
                "plan_id": result["plan_id"],
                "plan_digest": (
                    result["plan_digest"]
                ),
                "project": result["project"],
                "project_id": (
                    result["project_id"]
                ),
                "branch": result["branch"],
                "mode": result["mode"],
                "status": result["status"],
                "outcome": result["outcome"],
                "previous_source_bundle_digest": (
                    result[
                        "previous_source_bundle_digest"
                    ]
                ),
                "source_bundle_digest": (
                    result[
                        "source_bundle_digest"
                    ]
                ),
                "changed_file_count": (
                    result[
                        "changed_file_count"
                    ]
                ),
                "estimated_writes": (
                    result[
                        "estimated_writes"
                    ]
                ),
                "writes": result["writes"],
                "commit_id": (
                    result["commit_id"]
                ),
                "requests": (
                    result["requests"]
                ),
                "result_directory": str(path),
                "rollback_receipt": str(
                    path / "rollback.json"
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )

    return code


def add_transport_arguments(
    parser: argparse.ArgumentParser,
) -> None:
    parser.add_argument(
        "--timeout",
        type=float,
        default=30,
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=1,
    )
    parser.add_argument(
        "--request-interval-seconds",
        type=float,
        default=0.5,
    )
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument(
        "--insecure",
        action="store_true",
    )
    tls.add_argument(
        "--ca-bundle",
    )


def validate_transport(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
) -> None:
    if args.timeout <= 0:
        parser.error(
            "--timeout must be positive"
        )

    if args.retries < 0:
        parser.error(
            "--retries cannot be negative"
        )

    if args.retry_delay < 0:
        parser.error(
            "--retry-delay cannot be negative"
        )

    if args.request_interval_seconds < 0:
        parser.error(
            "--request-interval-seconds "
            "cannot be negative"
        )


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Plan, verify, and explicitly execute "
            "managed upgrades of a central GitLab "
            "scan repository."
        )
    )
    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    plan = commands.add_parser("plan")
    plan.add_argument(
        "--bundle",
        required=True,
    )
    plan.add_argument(
        "--expected-new-bundle-digest",
        required=True,
    )
    plan.add_argument(
        "--expected-current-bundle-digest",
        default="",
    )
    plan.add_argument(
        "--project",
        required=True,
    )
    plan.add_argument(
        "--branch",
        default="main",
    )
    plan.add_argument(
        "--output-root",
        default=str(
            default_plan_root()
        ),
    )
    plan.add_argument(
        "--lock",
        default=str(
            output_root()
            / "scm"
            / "onboarding"
            / "central-upgrade-plan.lock"
        ),
    )
    add_transport_arguments(plan)

    execute = commands.add_parser(
        "execute"
    )
    execute.add_argument(
        "--plan",
        required=True,
    )
    mode = (
        execute.add_mutually_exclusive_group()
    )
    mode.add_argument(
        "--dry-run",
        dest="mode",
        action="store_const",
        const="dry-run",
    )
    mode.add_argument(
        "--apply",
        dest="mode",
        action="store_const",
        const="apply",
    )
    execute.set_defaults(
        mode="dry-run"
    )
    execute.add_argument(
        "--confirm-apply",
        action="store_true",
    )
    execute.add_argument(
        "--confirmation",
        default="",
        help=(
            "Apply must exactly equal "
            f"{CONFIRMATION}"
        ),
    )
    execute.add_argument(
        "--expected-plan-digest",
        default="",
    )
    execute.add_argument(
        "--max-writes",
        type=int,
        default=1,
    )
    execute.add_argument(
        "--result-root",
        default=str(
            default_result_root()
        ),
    )
    execute.add_argument(
        "--lock",
        default=str(
            output_root()
            / "scm"
            / "onboarding"
            / "central-upgrade-execute.lock"
        ),
    )
    add_transport_arguments(execute)

    args = parser.parse_args(argv)
    validate_transport(
        parser,
        args,
    )

    if (
        args.command == "execute"
        and args.max_writes < 0
    ):
        parser.error(
            "--max-writes cannot be negative"
        )

    if (
        args.command == "execute"
        and args.mode == "apply"
    ):
        if not args.confirm_apply:
            parser.error(
                "--apply requires --confirm-apply"
            )

        if args.confirmation != CONFIRMATION:
            parser.error(
                "--apply requires the exact "
                f"confirmation: {CONFIRMATION}"
            )

        if not args.expected_plan_digest:
            parser.error(
                "--apply requires "
                "--expected-plan-digest"
            )

    return args


def main(
    argv: list[str] | None = None,
) -> int:
    tokens = [
        os.getenv("GITLAB_TOKEN", ""),
        os.getenv(
            "GITLAB_ACTION_TOKEN",
            "",
        ),
    ]

    try:
        args = parse_args(argv)

        with FileLock(
            args.lock,
            stale_seconds=7200,
            wait_seconds=0,
        ):
            if args.command == "plan":
                return plan_command(args)

            return execute_command(args)

    except KeyboardInterrupt:
        return 130
    except (
        BootstrapArtifactError,
        CentralUpgradeError,
        LockUnavailableError,
        OSError,
        RuntimeError,
        ValueError,
    ) as error:
        message = str(error)

        for token in tokens:
            if token:
                message = message.replace(
                    token,
                    "[REDACTED]",
                )

        print(
            f"ERROR: {message}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
