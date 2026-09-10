from __future__ import annotations

import argparse
import json
import os
import sys

from wintermute.file_lock import (
    FileLock,
    LockUnavailableError,
)
from wintermute.paths import output_root
from wintermute.scm.onboarding.artifacts import (
    write_execution_result,
)
from wintermute.scm.onboarding.bootstrap import (
    BootstrapArtifactError,
    GitHubBootstrapTarget,
    GitLabBootstrapTarget,
    build_bootstrap_plan,
    load_verified_bootstrap_plan,
    load_verified_central_bundle,
    write_bootstrap_plan,
)
from wintermute.scm.onboarding.bootstrap_providers import (
    GitHubBootstrapAdapter,
    GitLabBootstrapAdapter,
)
from wintermute.scm.onboarding.http import (
    OnboardingHttpClient,
)
from wintermute.scm.providers.detection import (
    gitlab_rest_url,
)


def default_plan_root() -> str:
    return str(
        output_root()
        / "scm"
        / "onboarding"
        / "bootstrap-plans"
    )


def default_result_root() -> str:
    return str(
        output_root()
        / "scm"
        / "onboarding"
        / "bootstrap-results"
    )


def selected_gitlab_target(
    args: argparse.Namespace,
) -> GitLabBootstrapTarget | None:
    namespace = str(
        args.gitlab_namespace
        or args.gitlab_group
        or ""
    ).strip("/")

    if not namespace:
        return None

    namespace_type = (
        "group"
        if (
            args.gitlab_group
            and not args.gitlab_namespace
        )
        else args.gitlab_namespace_type
    )

    return GitLabBootstrapTarget(
        namespace=namespace,
        namespace_type=namespace_type,
        project=args.gitlab_project,
        default_branch=(
            args.gitlab_default_branch
        ),
    )


def plan_command(
    args: argparse.Namespace,
) -> int:
    bundle = load_verified_central_bundle(
        args.bundle
    )
    github = (
        GitHubBootstrapTarget(
            organization=(
                args.github_organization
            ),
            repository=(
                args.github_repository
            ),
            default_branch=(
                args.github_default_branch
            ),
        )
        if args.github_organization
        else None
    )
    gitlab = selected_gitlab_target(
        args
    )
    plan, files = build_bootstrap_plan(
        bundle,
        github=github,
        gitlab=gitlab,
    )
    directory = write_bootstrap_plan(
        args.output_root,
        plan,
        files,
    )

    print(
        json.dumps(
            {
                "plan_id": plan["plan_id"],
                "repository_count": (
                    plan["repository_count"]
                ),
                "repositories": [
                    {
                        "name_with_owner": (
                            value[
                                "name_with_owner"
                            ]
                        ),
                        "namespace_type": (
                            value[
                                "namespace_type"
                            ]
                        ),
                    }
                    for value
                    in plan["repositories"]
                ],
                "status": plan["status"],
                "mutation_allowed": (
                    plan["mutation_allowed"]
                ),
                "plan_directory": (
                    str(directory)
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )

    return 0


def token_for(
    provider: str,
    mode: str,
) -> str:
    if provider == "github":
        name = (
            "GITHUB_ACTION_TOKEN"
            if mode == "apply"
            else "GITHUB_TOKEN"
        )
    else:
        name = (
            "GITLAB_ACTION_TOKEN"
            if mode == "apply"
            else "GITLAB_TOKEN"
        )

    token = os.getenv(name, "").strip()

    if not token:
        raise RuntimeError(
            f"{name} must be set"
        )

    return token


def adapters_for(
    providers: list[str],
    args: argparse.Namespace,
):
    adapters = {}
    clients = {}

    for provider in providers:
        if provider == "github":
            base_url = os.getenv(
                "GITHUB_REST_URL",
                "https://api.github.com",
            )
            adapter_type = (
                GitHubBootstrapAdapter
            )
        else:
            base_url = gitlab_rest_url(
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
            adapter_type = (
                GitLabBootstrapAdapter
            )

        client = OnboardingHttpClient(
            provider,
            base_url,
            token_for(
                provider,
                args.mode,
            ),
            timeout=args.timeout,
            retries=args.retries,
            retry_delay=args.retry_delay,
            request_interval_seconds=(
                args.request_interval_seconds
            ),
            insecure=args.insecure,
            ca_bundle=args.ca_bundle,
        )
        clients[provider] = client
        adapters[provider] = (
            adapter_type(client)
        )

    return adapters, clients


def execute_command(
    args: argparse.Namespace,
) -> int:
    bundle = load_verified_bootstrap_plan(
        args.plan
    )
    providers = [
        value["provider"]
        for value
        in bundle.plan["repositories"]
    ]

    if args.mode == "apply":
        if not args.confirm_apply:
            raise ValueError(
                "Apply mode requires confirmation"
            )

        if (
            not args.expected_plan_digest
            or args.expected_plan_digest
            != bundle.digest
        ):
            raise ValueError(
                "Expected bootstrap plan digest "
                "does not match"
            )

    adapters, clients = adapters_for(
        providers,
        args,
    )
    probes = {
        provider: adapters[
            provider
        ].probe(bundle)
        for provider in providers
    }
    blocked = [
        provider
        for provider in providers
        if probes[provider].get(
            "status"
        )
        != "ready"
    ]
    estimated_writes = sum(
        int(
            probes[provider].get(
                "estimated_writes"
            )
            or 0
        )
        for provider in providers
        if provider not in blocked
    )
    writes = 0
    results = []

    if blocked:
        status = "blocked"
        outcome = "capability-blocked"

    elif estimated_writes > args.max_writes:
        status = "blocked"
        outcome = "budget-exhausted"

    elif args.mode == "dry-run":
        status = "ok"
        outcome = (
            "planned"
            if estimated_writes
            else "already-satisfied"
        )

    else:
        status = "ok"
        outcome = "applied"

        for provider in providers:
            provider_writes = adapters[
                provider
            ].apply(
                bundle,
                probes[provider][
                    "actions"
                ],
            )
            writes += provider_writes
            after = adapters[
                provider
            ].probe(bundle)
            verified = (
                after.get("status")
                == "ready"
                and after.get("actions")
                == []
            )
            results.append(
                {
                    "provider": provider,
                    "writes": (
                        provider_writes
                    ),
                    "verified": verified,
                    "after": after,
                }
            )

            if not verified:
                status = "failed"
                outcome = (
                    "verification-failed"
                )
                break

    result = {
        "schema_version": 1,
        "execution_id": (
            __import__("uuid")
            .uuid4().hex
        ),
        "plan_id": (
            bundle.plan["plan_id"]
        ),
        "plan_digest": bundle.digest,
        "mode": args.mode,
        "status": status,
        "outcome": outcome,
        "estimated_writes": (
            estimated_writes
        ),
        "writes": writes,
        "probes": probes,
        "results": results,
        "requests": {
            provider: clients[
                provider
            ].requests
            for provider in providers
        },
    }
    result_path = write_execution_result(
        args.result_root,
        result,
    )

    print(
        json.dumps(
            {
                "plan_id": result["plan_id"],
                "plan_digest": (
                    result["plan_digest"]
                ),
                "mode": result["mode"],
                "status": result["status"],
                "outcome": result["outcome"],
                "estimated_writes": (
                    estimated_writes
                ),
                "writes": writes,
                "requests": result[
                    "requests"
                ],
                "result_path": (
                    str(result_path)
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )

    return (
        0
        if status == "ok"
        else 1
    )


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Plan or execute initialize-only "
            "central SCM repository bootstrap."
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
        "--output-root",
        default=default_plan_root(),
    )
    plan.add_argument(
        "--github-organization",
        default="",
    )
    plan.add_argument(
        "--github-repository",
        default=(
            "wintermute-security-scans"
        ),
    )
    plan.add_argument(
        "--github-default-branch",
        default="main",
    )
    plan.add_argument(
        "--gitlab-namespace",
        default=os.getenv(
            "GITLAB_NAMESPACE",
            "",
        ),
    )
    plan.add_argument(
        "--gitlab-namespace-type",
        choices=["group", "user"],
        default=os.getenv(
            "GITLAB_NAMESPACE_TYPE",
            "group",
        ),
    )
    plan.add_argument(
        "--gitlab-group",
        default="",
        help=(
            "Compatibility alias for a group "
            "namespace"
        ),
    )
    plan.add_argument(
        "--gitlab-project",
        default=(
            "wintermute-security-scans"
        ),
    )
    plan.add_argument(
        "--gitlab-default-branch",
        default="main",
    )

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
    execute.set_defaults(mode="dry-run")
    execute.add_argument(
        "--confirm-apply",
        action="store_true",
    )
    execute.add_argument(
        "--expected-plan-digest",
        default="",
    )
    execute.add_argument(
        "--max-writes",
        type=int,
        default=10,
    )
    execute.add_argument(
        "--result-root",
        default=default_result_root(),
    )
    execute.add_argument(
        "--timeout",
        type=float,
        default=30,
    )
    execute.add_argument(
        "--retries",
        type=int,
        default=2,
    )
    execute.add_argument(
        "--retry-delay",
        type=float,
        default=1,
    )
    execute.add_argument(
        "--request-interval-seconds",
        type=float,
        default=0.5,
    )
    execute.add_argument(
        "--lock",
        default=str(
            output_root()
            / "scm"
            / "onboarding"
            / "bootstrap.lock"
        ),
    )
    tls = execute.add_mutually_exclusive_group()
    tls.add_argument(
        "--insecure",
        action="store_true",
    )
    tls.add_argument(
        "--ca-bundle",
    )

    return parser.parse_args(argv)


def main(
    argv: list[str] | None = None,
) -> int:
    tokens = [
        os.getenv(
            "GITHUB_ACTION_TOKEN",
            "",
        ),
        os.getenv(
            "GITLAB_ACTION_TOKEN",
            "",
        ),
        os.getenv("GITHUB_TOKEN", ""),
        os.getenv("GITLAB_TOKEN", ""),
    ]

    try:
        args = parse_args(argv)

        if args.command == "plan":
            return plan_command(args)

        with FileLock(
            args.lock,
            stale_seconds=7200,
            wait_seconds=0,
        ):
            return execute_command(args)

    except KeyboardInterrupt:
        return 130
    except (
        BootstrapArtifactError,
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
