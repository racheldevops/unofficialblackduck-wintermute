#!/usr/bin/env python3
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
from wintermute.scm.onboarding.policy_pilot import (
    GitLabPolicyClient,
    PolicyConfiguration,
    PolicyPilotError,
    build_policy_plan,
    execute_policy_plan,
    load_verified_policy_plan,
    write_policy_plan,
)
from wintermute.scm.providers.detection import (
    gitlab_rest_url,
)


def environment_value(
    name: str,
    default: str = "",
) -> str:
    return str(
        os.getenv(name, default)
        or default
    ).strip()


def required_environment(
    name: str,
    default: str = "",
) -> str:
    value = environment_value(
        name,
        default,
    )

    if not value:
        raise RuntimeError(
            f"{name} must be set"
        )

    return value


def configuration(
    state: str,
) -> PolicyConfiguration:
    namespace = environment_value(
        "GITLAB_POLICY_NAMESPACE"
    ) or required_environment(
        "GITLAB_NAMESPACE"
    )
    policy_project = environment_value(
        "GITLAB_POLICY_PROJECT",
        (
            f"{namespace}/"
            "wintermute-security-policies"
        ),
    )
    pilot_project = required_environment(
        "GITLAB_POLICY_PILOT_PROJECT"
    )
    link_scope = environment_value(
        "GITLAB_POLICY_LINK_SCOPE",
        "project",
    ).casefold()
    target_project = environment_value(
        "GITLAB_POLICY_TARGET_PROJECT",
        pilot_project,
    )
    target_group = environment_value(
        "GITLAB_POLICY_TARGET_GROUP",
        environment_value(
            "GITLAB_GROUP"
        ),
    )

    return PolicyConfiguration(
        link_scope=link_scope,
        target_project=target_project,
        target_group=target_group,
        policy_project=policy_project,
        policy_namespace_type=(
            environment_value(
                "GITLAB_POLICY_NAMESPACE_TYPE",
                environment_value(
                    "GITLAB_NAMESPACE_TYPE",
                    "user",
                ),
            )
        ),
        central_project=required_environment(
            "GITLAB_CENTRAL_PROJECT"
        ),
        pilot_project=pilot_project,
        policy_file=environment_value(
            "GITLAB_POLICY_FILE",
            (
                ".gitlab/security-policies/"
                "policy.yml"
            ),
        ),
        ownership_file=environment_value(
            "GITLAB_POLICY_OWNERSHIP_FILE",
            "wintermute-managed.json",
        ),
        template_file=environment_value(
            "GITLAB_TEMPLATE_FILE",
            (
                "templates/"
                "wintermute-security.yml"
            ),
        ),
        template_ref=environment_value(
            "GITLAB_CENTRAL_REF",
            "main",
        ),
        policy_name=environment_value(
            "GITLAB_POLICY_NAME",
            (
                "Wintermute Black Duck "
                "SCA Pilot"
            ),
        ),
        default_branch=environment_value(
            "GITLAB_POLICY_DEFAULT_BRANCH",
            "main",
        ),
        state=state,
    )


def gitlab_api_url() -> str:
    selected = environment_value(
        "GITLAB_REST_URL"
    ) or required_environment(
        "GITLAB_URL"
    )

    return gitlab_rest_url(selected)


def client(
    token_name: str,
    args: argparse.Namespace,
) -> GitLabPolicyClient:
    return GitLabPolicyClient(
        "gitlab",
        gitlab_api_url(),
        required_environment(token_name),
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        request_interval_seconds=(
            args.request_interval_seconds
        ),
        insecure=args.insecure,
        ca_bundle=args.ca_bundle,
    )


def print_result(
    phase: str,
    result: dict,
    path: Path,
) -> None:
    print(
        json.dumps(
            {
                "phase": phase,
                "plan_id": (
                    result["plan_id"]
                ),
                "plan_digest": (
                    result["plan_digest"]
                ),
                "state": result["state"],
                "mode": result["mode"],
                "status": result["status"],
                "outcome": result["outcome"],
                "estimated_writes": (
                    result[
                        "estimated_writes"
                    ]
                ),
                "writes": result["writes"],
                "result_path": str(path),
            },
            indent=2,
            sort_keys=True,
        )
    )


def run(
    args: argparse.Namespace,
) -> int:
    selected_configuration = (
        configuration(args.state)
    )

    with FileLock(
        args.lock,
        stale_seconds=7200,
        wait_seconds=0,
    ):
        read_client = client(
            "GITLAB_TOKEN",
            args,
        )
        plan, files = build_policy_plan(
            read_client,
            selected_configuration,
        )
        plan_path = write_policy_plan(
            args.plan_root,
            plan,
            files,
        )
        loaded = load_verified_policy_plan(
            plan_path
        )

        print(
            json.dumps(
                {
                    "phase": "plan",
                    "plan_id": (
                        loaded.plan["plan_id"]
                    ),
                    "plan_digest": (
                        loaded.digest
                    ),
                    "link_scope": (
                        loaded.plan[
                            "configuration"
                        ]["link_scope"]
                    ),
                    "link_target": (
                        loaded.plan[
                            "configuration"
                        ][
                            "target_project"
                            if loaded.plan[
                                "configuration"
                            ]["link_scope"]
                            == "project"
                            else "target_group"
                        ]
                    ),
                    "state": (
                        loaded.plan["state"]
                    ),
                    "status": (
                        loaded.plan["status"]
                    ),
                    "reason": (
                        loaded.plan["reason"]
                    ),
                    "estimated_writes": (
                        loaded.plan[
                            "estimated_writes"
                        ]
                    ),
                    "plan_directory": (
                        str(plan_path)
                    ),
                },
                indent=2,
                sort_keys=True,
            )
        )

        (
            dry_code,
            dry_result,
            dry_path,
        ) = execute_policy_plan(
            loaded,
            read_client,
            mode="dry-run",
            maximum_writes=(
                args.max_writes
            ),
            result_root=(
                args.result_root
            ),
        )
        print_result(
            "dry-run",
            dry_result,
            dry_path,
        )

        if dry_code != 0:
            return dry_code

        if not args.apply:
            return 0

        action_client = client(
            "GITLAB_ACTION_TOKEN",
            args,
        )
        (
            apply_code,
            apply_result,
            apply_path,
        ) = execute_policy_plan(
            loaded,
            action_client,
            mode="apply",
            action_client=action_client,
            confirm_apply=True,
            maximum_writes=(
                args.max_writes
            ),
            result_root=(
                args.result_root
            ),
        )
        print_result(
            "apply",
            apply_result,
            apply_path,
        )

        return apply_code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create, verify, dry-run, and "
            "optionally apply a GitLab "
            "security-policy pilot."
        )
    )
    parser.add_argument(
        "--state",
        choices=[
            "disabled",
            "pilot",
        ],
        required=True,
    )
    parser.add_argument(
        "--apply",
        action="store_true",
    )
    parser.add_argument(
        "--confirm-apply",
        action="store_true",
    )
    parser.add_argument(
        "--max-writes",
        type=int,
        default=3,
    )
    parser.add_argument(
        "--plan-root",
        type=Path,
        default=(
            output_root()
            / "scm"
            / "onboarding"
            / "policy-plans"
        ),
    )
    parser.add_argument(
        "--result-root",
        type=Path,
        default=(
            output_root()
            / "scm"
            / "onboarding"
            / "policy-results"
        ),
    )
    parser.add_argument(
        "--lock",
        type=Path,
        default=(
            output_root()
            / "scm"
            / "onboarding"
            / "policy-job.lock"
        ),
    )
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
    args = parser.parse_args()

    if args.apply and not args.confirm_apply:
        parser.error(
            "--apply requires --confirm-apply"
        )

    if args.max_writes < 1:
        parser.error(
            "--max-writes must be positive"
        )

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

    if (
        args.request_interval_seconds
        < 0
    ):
        parser.error(
            "--request-interval-seconds "
            "cannot be negative"
        )

    return args


def main() -> int:
    tokens = [
        environment_value(
            "GITLAB_TOKEN"
        ),
        environment_value(
            "GITLAB_ACTION_TOKEN"
        ),
    ]

    try:
        return run(parse_args())
    except KeyboardInterrupt:
        return 130
    except (
        LockUnavailableError,
        OSError,
        PolicyPilotError,
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
