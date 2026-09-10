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
from wintermute.scm.onboarding.artifacts import (
    OnboardingArtifactError,
    load_verified_plan,
    write_execution_result,
)
from wintermute.scm.onboarding.executor import (
    ExecutionOptions,
    execute_plan,
)
from wintermute.scm.onboarding.http import (
    OnboardingHttpClient,
)
from wintermute.scm.onboarding.providers import (
    GitHubOnboardingAdapter,
    GitLabOnboardingAdapter,
)
from wintermute.scm.providers.detection import (
    gitlab_rest_url,
)


def default_result_root() -> str:
    return str(
        output_root()
        / "scm"
        / "onboarding"
        / "results"
    )


def default_lock_path() -> str:
    return str(
        output_root()
        / "scm"
        / "onboarding"
        / "executor.lock"
    )


def client_and_adapter(
    provider: str,
    args: argparse.Namespace,
):
    if provider == "github":
        token = (
            os.getenv(
                "GITHUB_ACTION_TOKEN",
                "",
            )
            if args.mode == "apply"
            else os.getenv(
                "GITHUB_TOKEN",
                "",
            )
        ).strip()
        base_url = os.getenv(
            "GITHUB_REST_URL",
            "https://api.github.com",
        )
        adapter_type = (
            GitHubOnboardingAdapter
        )
    else:
        token = (
            os.getenv(
                "GITLAB_ACTION_TOKEN",
                "",
            )
            if args.mode == "apply"
            else os.getenv(
                "GITLAB_TOKEN",
                "",
            )
        ).strip()
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
            GitLabOnboardingAdapter
        )

    if not token:
        required = (
            f"{provider.upper()}_ACTION_TOKEN"
            if args.mode == "apply"
            else f"{provider.upper()}_TOKEN"
        )
        raise RuntimeError(
            f"{required} must be set"
        )

    client = OnboardingHttpClient(
        provider,
        base_url,
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

    return client, adapter_type(client)


def run(
    args: argparse.Namespace,
) -> int:
    bundle = load_verified_plan(
        args.plan
    )
    provider = str(
        bundle.plan["repository"][
            "provider"
        ]
    )
    client, adapter = client_and_adapter(
        provider,
        args,
    )

    with FileLock(
        args.lock,
        stale_seconds=(
            args.lock_stale_seconds
        ),
        wait_seconds=0,
    ):
        result = execute_plan(
            bundle,
            adapter,
            ExecutionOptions(
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
        result["requests"] = client.requests
        result["transport_writes"] = (
            client.writes
        )
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
                "provider": provider,
                "mode": result["mode"],
                "status": result["status"],
                "outcome": result["outcome"],
                "requests": result["requests"],
                "writes": result["writes"],
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
            "Probe or execute a reviewed central "
            "SCM onboarding plan."
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
        default=2,
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

    return args


def main(
    argv: list[str] | None = None,
) -> int:
    try:
        return run(parse_args(argv))
    except KeyboardInterrupt:
        return 130
    except (
        LockUnavailableError,
        OnboardingArtifactError,
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
