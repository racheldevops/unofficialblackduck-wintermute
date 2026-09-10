#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

from wintermute.file_lock import (
    FileLock,
    LockUnavailableError,
)
from wintermute.paths import output_root
from wintermute.scm.onboarding.bootstrap import (
    GitHubBootstrapTarget,
    GitLabBootstrapTarget,
    build_bootstrap_plan,
    load_verified_bootstrap_plan,
    load_verified_central_bundle,
    write_bootstrap_plan,
)
from wintermute.scm.onboarding.bootstrap_cli import (
    execute_command,
)
from wintermute.scm.onboarding.job_token_access import (
    GitLabJobTokenAccessClient,
    JobTokenAccessError,
    build_access_plan,
    execute_access_plan,
    load_verified_access_plan,
    write_access_plan,
)
from wintermute.scm.providers.detection import (
    gitlab_rest_url,
)


def latest_ready(root: Path) -> Path:
    if not root.is_dir():
        raise RuntimeError(
            f"Artifact directory does not exist: {root}"
        )

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
            f"No ready artifacts exist under {root}"
        )

    return candidates[0].resolve()


def selected_bundle(
    value: str,
) -> Path:
    if value:
        return Path(value).expanduser().resolve()

    return latest_ready(
        output_root()
        / "scm"
        / "onboarding"
        / "central-bundles"
    )


def github_target(
    bundle_path: Path,
) -> GitHubBootstrapTarget | None:
    workflow = (
        bundle_path
        / ".github"
        / "workflows"
        / "wintermute-security.yml"
    )

    if not workflow.is_file():
        return None

    organization = os.getenv(
        "GITHUB_ORG",
        "",
    ).strip()

    if not organization:
        raise RuntimeError(
            "GITHUB_ORG must be set"
        )

    full_name = os.getenv(
        "GITHUB_CENTRAL_REPOSITORY",
        (
            f"{organization}/"
            "wintermute-security-scans"
        ),
    ).strip()

    if (
        full_name.count("/") != 1
        or full_name.split("/", 1)[0]
        .casefold()
        != organization.casefold()
    ):
        raise RuntimeError(
            "GITHUB_CENTRAL_REPOSITORY must "
            "belong to GITHUB_ORG"
        )

    return GitHubBootstrapTarget(
        organization=organization,
        repository=full_name.split(
            "/",
            1,
        )[1],
        default_branch=os.getenv(
            "GITHUB_CENTRAL_REF",
            "main",
        ).strip(),
    )


def gitlab_target(
    bundle_path: Path,
) -> GitLabBootstrapTarget | None:
    template = (
        bundle_path
        / "templates"
        / "wintermute-security.yml"
    )

    if not template.is_file():
        return None

    namespace = os.getenv(
        "GITLAB_NAMESPACE",
        "",
    ).strip("/")

    if not namespace:
        namespace = os.getenv(
            "GITLAB_GROUP",
            "",
        ).strip("/")

    if not namespace:
        raise RuntimeError(
            "GITLAB_NAMESPACE or GITLAB_GROUP "
            "must be set"
        )

    namespace_type = os.getenv(
        "GITLAB_NAMESPACE_TYPE",
        "group",
    ).strip().casefold()

    if namespace_type not in {
        "group",
        "user",
    }:
        raise RuntimeError(
            "GITLAB_NAMESPACE_TYPE must be "
            "group or user"
        )

    full_name = os.getenv(
        "GITLAB_CENTRAL_PROJECT",
        (
            f"{namespace}/"
            "wintermute-security-scans"
        ),
    ).strip("/")

    if not full_name.startswith(
        f"{namespace}/"
    ):
        raise RuntimeError(
            "GITLAB_CENTRAL_PROJECT must "
            "belong to GITLAB_NAMESPACE"
        )

    return GitLabBootstrapTarget(
        namespace=namespace,
        namespace_type=namespace_type,
        project=full_name.rsplit(
            "/",
            1,
        )[1],
        default_branch=os.getenv(
            "GITLAB_CENTRAL_REF",
            "main",
        ).strip(),
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


def consumer_group() -> str:
    selected = (
        os.getenv(
            "GITLAB_CONSUMER_GROUP",
            "",
        ).strip("/")
        or os.getenv(
            "GITLAB_GROUP",
            "",
        ).strip("/")
    )

    if not selected:
        raise RuntimeError(
            "GITLAB_CONSUMER_GROUP or "
            "GITLAB_GROUP must be set"
        )

    return selected


def inferred_image_project() -> str:
    explicit = os.getenv(
        "GITLAB_SCAN_IMAGE_PROJECT",
        "",
    ).strip("/")

    if explicit:
        return explicit

    image = os.getenv(
        "WINTERMUTE_SCAN_IMAGE",
        "",
    ).strip()

    if not image:
        raise RuntimeError(
            "GITLAB_SCAN_IMAGE_PROJECT or "
            "WINTERMUTE_SCAN_IMAGE must be set"
        )

    reference = image.split("@", 1)[0]
    parsed = urlsplit(
        (
            reference
            if "://" in reference
            else f"https://{reference}"
        )
    )
    parts = [
        part
        for part
        in parsed.path.strip("/").split("/")
        if part
    ]

    if len(parts) < 3:
        raise RuntimeError(
            "Could not infer the GitLab image "
            "project; set "
            "GITLAB_SCAN_IMAGE_PROJECT"
        )

    return "/".join(parts[:-1])


def access_client(
    args: argparse.Namespace,
    *,
    mode: str,
) -> GitLabJobTokenAccessClient:
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

    return GitLabJobTokenAccessClient(
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


def execution_arguments(
    args: argparse.Namespace,
    *,
    plan_path: Path,
    mode: str,
    plan_digest: str,
) -> argparse.Namespace:
    return argparse.Namespace(
        plan=str(plan_path),
        mode=mode,
        confirm_apply=(
            mode == "apply"
        ),
        expected_plan_digest=(
            plan_digest
            if mode == "apply"
            else ""
        ),
        max_writes=args.max_writes,
        result_root=args.result_root,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        request_interval_seconds=(
            args.request_interval_seconds
        ),
        insecure=args.insecure,
        ca_bundle=args.ca_bundle,
    )


def print_access_result(
    *,
    phase: str,
    result: dict,
    path: Path,
) -> None:
    before = result["before"]
    consumer_groups = before.get(
        "consumer_groups",
        [],
    )

    if not consumer_groups:
        legacy_group = before.get(
            "consumer_group",
            "",
        )
        consumer_groups = (
            [legacy_group]
            if legacy_group
            else []
        )

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
                "mode": result["mode"],
                "status": result["status"],
                "outcome": result["outcome"],
                "consumer_groups": (
                    consumer_groups
                ),
                "projects": [
                    value["project"]
                    for value
                    in before["projects"]
                ],
                "estimated_writes": (
                    result[
                        "estimated_writes"
                    ]
                ),
                "writes": result["writes"],
                "requests": (
                    result["requests"]
                ),
                "result_path": str(path),
            },
            indent=2,
            sort_keys=True,
        )
    )


def run(
    args: argparse.Namespace,
) -> int:
    bundle_path = selected_bundle(
        args.bundle
    )
    bundle = load_verified_central_bundle(
        bundle_path
    )
    github = github_target(bundle_path)
    gitlab = gitlab_target(bundle_path)

    with FileLock(
        args.lock,
        stale_seconds=7200,
        wait_seconds=0,
    ):
        plan, files = build_bootstrap_plan(
            bundle,
            github=github,
            gitlab=gitlab,
        )
        plan_path = write_bootstrap_plan(
            args.plan_root,
            plan,
            files,
        )
        verified = (
            load_verified_bootstrap_plan(
                plan_path
            )
        )

        print(
            json.dumps(
                {
                    "phase": "plan",
                    "plan_id": (
                        verified.plan[
                            "plan_id"
                        ]
                    ),
                    "plan_digest": (
                        verified.digest
                    ),
                    "plan_directory": (
                        str(plan_path)
                    ),
                    "repository_count": (
                        verified.plan[
                            "repository_count"
                        ]
                    ),
                    "status": "succeeded",
                },
                indent=2,
                sort_keys=True,
            )
        )

        access_loaded = None

        if gitlab is not None:
            central_project = next(
                repository[
                    "name_with_owner"
                ]
                for repository
                in verified.plan[
                    "repositories"
                ]
                if repository["provider"]
                == "gitlab"
            )
            access_plan = build_access_plan(
                bootstrap_plan_id=(
                    verified.plan[
                        "plan_id"
                    ]
                ),
                bootstrap_plan_digest=(
                    verified.digest
                ),
                central_project=(
                    central_project
                ),
                image_project=(
                    inferred_image_project()
                ),
                consumer_group=(
                    consumer_group()
                ),
            )
            access_path = write_access_plan(
                args.access_plan_root,
                access_plan,
            )
            access_loaded = (
                load_verified_access_plan(
                    access_path
                )
            )

            print(
                json.dumps(
                    {
                        "phase": (
                            "job-token-access-plan"
                        ),
                        "plan_id": (
                            access_loaded.plan[
                                "plan_id"
                            ]
                        ),
                        "plan_digest": (
                            access_loaded.digest
                        ),
                        "plan_directory": (
                            str(access_path)
                        ),
                        "consumer_groups": (
                            access_loaded.plan[
                                "consumer_groups"
                            ]
                        ),
                        "projects": [
                            value["project"]
                            for value
                            in access_loaded.plan[
                                "projects"
                            ]
                        ],
                        "status": "succeeded",
                    },
                    indent=2,
                    sort_keys=True,
                )
            )

        dry_run_result = execute_command(
            execution_arguments(
                args,
                plan_path=plan_path,
                mode="dry-run",
                plan_digest=(
                    verified.digest
                ),
            )
        )

        if dry_run_result != 0:
            return dry_run_result

        if access_loaded is not None:
            (
                access_dry_code,
                access_dry_result,
                access_dry_path,
            ) = execute_access_plan(
                access_loaded,
                access_client(
                    args,
                    mode="dry-run",
                ),
                mode="dry-run",
                maximum_writes=(
                    args.max_access_writes
                ),
                allow_pending_projects=True,
                result_root=(
                    args.access_result_root
                ),
            )
            print_access_result(
                phase=(
                    "job-token-access-dry-run"
                ),
                result=access_dry_result,
                path=access_dry_path,
            )

            if access_dry_code != 0:
                return access_dry_code

        if not args.apply:
            print(
                json.dumps(
                    {
                        "phase": "complete",
                        "mode": "dry-run",
                        "plan_id": (
                            verified.plan[
                                "plan_id"
                            ]
                        ),
                        "plan_digest": (
                            verified.digest
                        ),
                        "status": "succeeded",
                        "writes": 0,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0

        apply_result = execute_command(
            execution_arguments(
                args,
                plan_path=plan_path,
                mode="apply",
                plan_digest=(
                    verified.digest
                ),
            )
        )

        if apply_result != 0:
            return apply_result

        access_apply_result = 0

        if access_loaded is not None:
            (
                access_apply_result,
                access_result,
                access_result_path,
            ) = execute_access_plan(
                access_loaded,
                access_client(
                    args,
                    mode="apply",
                ),
                mode="apply",
                confirm_apply=True,
                expected_plan_digest=(
                    access_loaded.digest
                ),
                maximum_writes=(
                    args.max_access_writes
                ),
                allow_pending_projects=False,
                result_root=(
                    args.access_result_root
                ),
            )
            print_access_result(
                phase=(
                    "job-token-access-apply"
                ),
                result=access_result,
                path=access_result_path,
            )

        final_code = (
            access_apply_result
            if access_apply_result
            else apply_result
        )

        print(
            json.dumps(
                {
                    "phase": "complete",
                    "mode": "apply",
                    "plan_id": (
                        verified.plan[
                            "plan_id"
                        ]
                    ),
                    "plan_digest": (
                        verified.digest
                    ),
                    "status": (
                        "succeeded"
                        if final_code == 0
                        else "failed"
                    ),
                    "exit_code": final_code,
                },
                indent=2,
                sort_keys=True,
            )
        )

        return final_code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create, verify, dry-run, and "
            "optionally apply one central "
            "bootstrap and GitLab access plan."
        )
    )
    parser.add_argument(
        "--bundle",
        default="",
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
        default=4,
    )
    parser.add_argument(
        "--max-access-writes",
        type=int,
        default=4,
    )
    parser.add_argument(
        "--plan-root",
        default=str(
            output_root()
            / "scm"
            / "onboarding"
            / "bootstrap-plans"
        ),
    )
    parser.add_argument(
        "--result-root",
        default=str(
            output_root()
            / "scm"
            / "onboarding"
            / "bootstrap-results"
        ),
    )
    parser.add_argument(
        "--access-plan-root",
        default=str(
            output_root()
            / "scm"
            / "onboarding"
            / "job-token-access-plans"
        ),
    )
    parser.add_argument(
        "--access-result-root",
        default=str(
            output_root()
            / "scm"
            / "onboarding"
            / "job-token-access-results"
        ),
    )
    parser.add_argument(
        "--lock",
        default=str(
            output_root()
            / "scm"
            / "onboarding"
            / "bootstrap-job.lock"
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

    for name in (
        "max_writes",
        "max_access_writes",
    ):
        if getattr(args, name) < 1:
            parser.error(
                f"--{name.replace('_', '-')} "
                "must be positive"
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

    if args.request_interval_seconds < 0:
        parser.error(
            "--request-interval-seconds "
            "cannot be negative"
        )

    return args


def main() -> int:
    tokens = [
        os.getenv("GITLAB_TOKEN", ""),
        os.getenv(
            "GITLAB_ACTION_TOKEN",
            "",
        ),
    ]

    try:
        return run(parse_args())
    except KeyboardInterrupt:
        return 130
    except (
        JobTokenAccessError,
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
