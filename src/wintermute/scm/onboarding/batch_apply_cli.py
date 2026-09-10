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
from wintermute.scm.onboarding.batch_artifacts import (
    BatchOnboardingArtifactError,
    load_verified_batch_plan,
)
from wintermute.scm.onboarding.batch_executor import (
    BatchExecutionOptions,
    execute_batch_plan,
)
from wintermute.scm.onboarding.batch_providers import (
    GitHubBatchOnboardingAdapter,
    GitLabBatchOnboardingAdapter,
)
from wintermute.scm.onboarding.http import (
    OnboardingHttpClient,
)
from wintermute.scm.providers.detection import (
    gitlab_rest_url,
)


def default_result_root() -> str:
    return str(
        output_root()
        / "scm"
        / "onboarding"
        / "batch-results"
    )


def default_lock_path() -> str:
    return str(
        output_root()
        / "scm"
        / "onboarding"
        / "batch-executor.lock"
    )


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


def github_base_url() -> str:
    return os.getenv(
        "GITHUB_REST_URL",
        "https://api.github.com",
    ).strip()


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


def adapters_for(
    providers: list[str],
    args: argparse.Namespace,
):
    adapters = {}
    clients = {}

    for provider in providers:
        base_url = (
            github_base_url()
            if provider == "github"
            else gitlab_base_url()
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
            GitHubBatchOnboardingAdapter(
                client
            )
            if provider == "github"
            else GitLabBatchOnboardingAdapter(
                client
            )
        )

    return adapters, clients


def run(
    args: argparse.Namespace,
) -> int:
    bundle = load_verified_batch_plan(
        args.plan
    )
    providers = list(
        bundle.plan["providers"]
    )
    adapters, clients = adapters_for(
        providers,
        args,
    )

    with FileLock(
        args.lock,
        stale_seconds=(
            args.lock_stale_seconds
        ),
        wait_seconds=0,
    ):
        result = execute_batch_plan(
            bundle,
            adapters,
            BatchExecutionOptions(
                mode=args.mode,
                confirm_apply=(
                    args.confirm_apply
                ),
                expected_plan_digest=(
                    args.expected_plan_digest
                ),
                maximum_writes=(
                    args.max_writes
                ),
            ),
        )
        result["requests"] = {
            provider: client.requests
            for provider, client
            in clients.items()
        }
        result[
            "transport_writes"
        ] = {
            provider: client.writes
            for provider, client
            in clients.items()
        }
        path = write_execution_result(
            args.result_root,
            result,
        )

    print(
        json.dumps(
            {
                "execution_id": (
                    result["execution_id"]
                ),
                "plan_id": result["plan_id"],
                "plan_digest": (
                    result["plan_digest"]
                ),
                "mode": result["mode"],
                "status": result["status"],
                "outcome": result["outcome"],
                "estimated_writes": (
                    result[
                        "estimated_writes"
                    ]
                ),
                "writes": result["writes"],
                "requests": result[
                    "requests"
                ],
                "result_path": str(path),
            },
            indent=2,
            sort_keys=True,
        )
    )

    return (
        0
        if result["status"] == "ok"
        else 1
    )


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Probe or execute a reviewed "
            "central onboarding batch plan."
        )
    )
    parser.add_argument(
        "--plan",
        required=True,
    )
    mode = parser.add_mutually_exclusive_group()
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
    parser.set_defaults(mode="dry-run")
    parser.add_argument(
        "--confirm-apply",
        action="store_true",
    )
    parser.add_argument(
        "--expected-plan-digest",
        default="",
    )
    parser.add_argument(
        "--max-writes",
        type=int,
        default=100,
    )
    parser.add_argument(
        "--result-root",
        default=default_result_root(),
    )
    parser.add_argument(
        "--lock",
        default=default_lock_path(),
    )
    parser.add_argument(
        "--lock-stale-seconds",
        type=float,
        default=7200,
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
    args = parser.parse_args(argv)

    if args.max_writes < 0:
        parser.error(
            "--max-writes cannot be negative"
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

    return args


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
        return run(parse_args(argv))
    except KeyboardInterrupt:
        return 130
    except (
        BatchOnboardingArtifactError,
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
