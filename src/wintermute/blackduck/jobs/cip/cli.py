from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from wintermute.blackduck.actions.lock import (
    FileLock,
    LockUnavailableError,
)
from wintermute.blackduck.actions.models import (
    normalize_base_url,
)
from wintermute.blackduck.client import (
    BlackDuckClient,
)
from wintermute.blackduck.jobs.cip.config import (
    load_cip_configuration,
)
from wintermute.blackduck.jobs.cip.planner import (
    create_cip_plan,
)
from wintermute.paths import output_root
from wintermute.scm.providers.gitlab.client import (
    DEFAULT_REST_BASE_URL,
)
from wintermute.scm.providers.gitlab.commits import (
    GitLabCommitClient,
)


def default_plan_root() -> str:
    return str(
        output_root()
        / "blackduck"
        / "actions"
        / "plans"
    )


def default_cache_root() -> str:
    return str(
        output_root()
        / "blackduck"
        / "jobs"
        / "cip"
        / "cache"
    )


def default_lock_path() -> str:
    return str(
        output_root()
        / "blackduck"
        / "jobs"
        / "cip"
        / "planning.lock"
    )


def validate_args(
    args: argparse.Namespace,
) -> None:
    for name in (
        "timeout",
        "page_limit",
        "target_page_size",
        "max_occurrences_per_target",
        "max_candidates_per_run",
        "progress_every",
    ):
        if int(getattr(args, name)) < 1:
            raise RuntimeError(
                f"--{name.replace('_', '-')} "
                "must be greater than zero"
            )

    if args.target_page_size > 500:
        raise RuntimeError(
            "--target-page-size cannot exceed 500"
        )

    if args.retries < 0:
        raise RuntimeError(
            "--retries cannot be negative"
        )

    if args.retry_delay < 0:
        raise RuntimeError(
            "--retry-delay cannot be negative"
        )

    if args.max_hours <= 0:
        raise RuntimeError(
            "--max-hours must be positive"
        )

    if args.request_interval_seconds < 0:
        raise RuntimeError(
            "--request-interval-seconds cannot "
            "be negative"
        )

    if (
        args.gitlab_request_interval_seconds
        < 0
    ):
        raise RuntimeError(
            "--gitlab-request-interval-seconds "
            "cannot be negative"
        )


def run(args: argparse.Namespace) -> int:
    validate_args(args)
    configuration = load_cip_configuration(
        args.config
    )

    if (
        args.bd_url
        and normalize_base_url(args.bd_url)
        != configuration.blackduck_base_url
    ):
        raise RuntimeError(
            "BLACKDUCK_URL does not match the "
            "runtime configuration"
        )

    deadline = (
        time.monotonic()
        + args.max_hours * 3600
    )
    cache_root = Path(
        args.cache_root
    ).expanduser()
    client = BlackDuckClient(
        base_url=(
            configuration.blackduck_base_url
        ),
        api_token=args.api_token,
        insecure=args.insecure,
        ca_bundle=args.ca_bundle,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        page_limit=args.page_limit,
        debug=args.debug,
        api_cache=None,
        request_interval_seconds=(
            args.request_interval_seconds
        ),
    )
    client.cache_raw_gets = False
    client.cache_paged_results = False
    gitlab = GitLabCommitClient(
        token=args.gitlab_token,
        base_url=args.gitlab_rest_url,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        request_interval_seconds=(
            args.gitlab_request_interval_seconds
        ),
        insecure=args.insecure,
        ca_bundle=args.ca_bundle,
        deadline=deadline,
    )

    with FileLock(
        args.lock,
        stale_seconds=(
            args.lock_stale_seconds
        ),
        wait_seconds=0,
    ):
        client.authenticate()
        result = create_cip_plan(
            client,
            configuration,
            gitlab,
            plan_root=args.plan_root,
            assessment_cache_path=(
                cache_root
                / "assessments.json"
            ),
            target_cursor_cache_path=(
                cache_root
                / "target-cursors.json"
            ),
            alias_cache_path=(
                cache_root
                / "vulnerability-aliases.json"
            ),
            target_page_size=(
                args.target_page_size
            ),
            max_occurrences_per_target=(
                args
                .max_occurrences_per_target
            ),
            max_candidates_per_run=(
                args.max_candidates_per_run
            ),
            progress_every=(
                args.progress_every
            ),
            refresh_target_cursors=(
                args.refresh_target_cursors
            ),
        )

    gitlab_stats = gitlab.stats()
    print(
        json.dumps(
            {
                **result.as_dict(),
                "gitlab_requests": (
                    gitlab_stats.requests
                ),
                "gitlab_retries": (
                    gitlab_stats.retries
                ),
                "gitlab_rate_remaining": (
                    gitlab_stats.rate_remaining
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )

    return (
        1
        if result.failure_count
        else 0
    )


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create a bounded Black Duck action "
            "plan from Linux CIP evidence."
        )
    )
    parser.add_argument(
        "--config",
        default=os.getenv(
            "CIP_REMEDIATION_CONFIG"
        ),
    )
    parser.add_argument(
        "--plan-root",
        default=default_plan_root(),
    )
    parser.add_argument(
        "--cache-root",
        default=default_cache_root(),
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
        "--target-page-size",
        type=int,
        default=25,
    )
    parser.add_argument(
        "--max-occurrences-per-target",
        type=int,
        default=25,
    )
    parser.add_argument(
        "--max-candidates-per-run",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=5,
    )
    parser.add_argument(
        "--refresh-target-cursors",
        action="store_true",
    )
    parser.add_argument(
        "--bd-url",
        default=os.getenv("BLACKDUCK_URL"),
    )
    parser.add_argument(
        "--api-token",
        default=os.getenv(
            "BLACKDUCK_API_TOKEN"
        ),
        required=(
            os.getenv(
                "BLACKDUCK_API_TOKEN"
            )
            is None
        ),
    )
    parser.add_argument(
        "--gitlab-token",
        default=os.getenv(
            "GITLAB_TOKEN",
            "",
        ),
    )
    parser.add_argument(
        "--gitlab-rest-url",
        default=os.getenv(
            "GITLAB_REST_URL",
            DEFAULT_REST_BASE_URL,
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
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
        "--page-limit",
        type=int,
        default=500,
    )
    parser.add_argument(
        "--request-interval-seconds",
        type=float,
        default=0.5,
    )
    parser.add_argument(
        "--gitlab-request-interval-seconds",
        type=float,
        default=0.2,
    )
    parser.add_argument(
        "--max-hours",
        type=float,
        default=1,
    )
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument(
        "--insecure",
        action="store_true",
    )
    tls.add_argument("--ca-bundle")
    parser.add_argument(
        "--debug",
        action="store_true",
    )

    return parser.parse_args(argv)


def main() -> int:
    token = os.getenv(
        "GITLAB_TOKEN",
        "",
    )

    try:
        return run(parse_args())
    except KeyboardInterrupt:
        return 130
    except (
        LockUnavailableError,
        OSError,
        RuntimeError,
        ValueError,
    ) as error:
        message = str(error)

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
