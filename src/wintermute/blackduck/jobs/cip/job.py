from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path

from wintermute.blackduck.actions.artifacts import (
    load_verified_action_plan,
)
from wintermute.blackduck.actions.budget import (
    BudgetedRequestController,
    RequestBudgetExceeded,
)
from wintermute.blackduck.actions.executor import (
    ActionExecutor,
    ExecutionPolicy,
)
from wintermute.blackduck.actions.http import (
    BlackDuckActionHttpClient,
)
from wintermute.blackduck.actions.lock import (
    FileLock,
    LockUnavailableError,
)
from wintermute.blackduck.actions.registry import (
    ActionRegistry,
)
from wintermute.blackduck.actions.remediation import (
    VulnerabilityRemediationHandler,
)
from wintermute.blackduck.actions.results import (
    write_execution_result,
)
from wintermute.blackduck.client import (
    BlackDuckClient,
)
from wintermute.blackduck.jobs.cip.config import (
    CipConfiguration,
    load_cip_configuration,
)
from wintermute.blackduck.jobs.cip.planner import (
    CipPlanningResult,
    create_cip_plan,
)
from wintermute.paths import output_root
from wintermute.scm.providers.gitlab.client import (
    DEFAULT_REST_BASE_URL,
)
from wintermute.scm.providers.gitlab.commits import (
    BudgetedGitLabCommitClient,
)


def job_root() -> Path:
    return (
        output_root()
        / "blackduck"
        / "jobs"
        / "cip"
    )


def default_plan_root() -> str:
    return str(
        output_root()
        / "blackduck"
        / "actions"
        / "plans"
    )


def default_result_root() -> str:
    return str(
        output_root()
        / "blackduck"
        / "actions"
        / "results"
    )


def default_cache_root() -> str:
    return str(
        job_root() / "cache"
    )


def default_lock_path() -> str:
    return str(
        job_root() / "job.lock"
    )


def validate_args(
    args: argparse.Namespace,
) -> None:
    if args.mode == "apply":
        if not args.confirm_apply:
            raise RuntimeError(
                "Apply mode requires "
                "--confirm-apply"
            )

        if not args.action_api_token:
            raise RuntimeError(
                "BLACKDUCK_ACTION_API_TOKEN "
                "is required for apply mode"
            )

        if args.max_writes < 1:
            raise RuntimeError(
                "--max-writes must be positive "
                "in apply mode"
            )

    for name in (
        "timeout",
        "page_limit",
        "target_page_size",
        "max_occurrences_per_target",
        "max_candidates_per_run",
        "max_actions",
        "max_reads",
        "max_blackduck_requests",
        "max_gitlab_requests",
        "progress_every",
    ):
        if int(getattr(args, name)) < 1:
            raise RuntimeError(
                f"--{name.replace('_', '-')} "
                "must be greater than zero"
            )

    if args.max_writes < 0:
        raise RuntimeError(
            "--max-writes cannot be negative"
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


def candidate_limit(
    args: argparse.Namespace,
    configuration: CipConfiguration,
) -> int:
    selected = min(
        args.max_candidates_per_run,
        configuration.limits.maximum_actions,
        args.max_actions,
    )

    if args.mode == "apply":
        selected = min(
            selected,
            args.max_writes,
        )

    return max(1, selected)


def create_blackduck_client(
    *,
    base_url: str,
    api_token: str,
    args: argparse.Namespace,
    request_control=None,
    retries: int | None = None,
) -> BlackDuckClient:
    client = BlackDuckClient(
        base_url=base_url,
        api_token=api_token,
        insecure=args.insecure,
        ca_bundle=args.ca_bundle,
        timeout=args.timeout,
        retries=(
            args.retries
            if retries is None
            else retries
        ),
        retry_delay=args.retry_delay,
        page_limit=args.page_limit,
        debug=args.debug,
        api_cache=None,
        request_interval_seconds=(
            args.request_interval_seconds
        ),
        request_control=request_control,
    )
    client.cache_raw_gets = False
    client.cache_paged_results = False
    return client


def execute_plan(
    planning: CipPlanningResult,
    read_client: BlackDuckClient,
    configuration: CipConfiguration,
    args: argparse.Namespace,
) -> tuple[dict, str]:
    plan = load_verified_action_plan(
        planning.path
    )
    registry = ActionRegistry()

    if args.mode == "apply":
        write_client = create_blackduck_client(
            base_url=(
                configuration.blackduck_base_url
            ),
            api_token=args.action_api_token,
            args=args,
            request_control=(
                read_client.request_control
            ),
            retries=0,
        )
        write_client.authenticate()
        write_transport = (
            BlackDuckActionHttpClient(
                write_client
            )
        )
    else:
        write_transport = (
            BlackDuckActionHttpClient(
                read_client
            )
        )

    registry.register(
        VulnerabilityRemediationHandler(
            read_client.clone_for_uncached_reads(),
            write_transport,
            preserve_existing_decisions=(
                configuration
                .preserve_existing_decisions
            ),
            allowed_statuses=(
                configuration.desired_status,
            ),
        )
    )
    result = ActionExecutor(
        registry
    ).execute(
        plan,
        ExecutionPolicy(
            mode=args.mode,
            confirm_apply=(
                args.confirm_apply
            ),
            expected_plan_digest=(
                plan.digest
            ),
            expected_blackduck_base_url=(
                configuration
                .blackduck_base_url
            ),
            allowed_producers=(
                "cip-remediation",
            ),
            allowed_action_kinds=(
                "vulnerability-remediation.set",
            ),
            maximum_actions=args.max_actions,
            maximum_blackduck_reads=(
                args.max_reads
            ),
            maximum_blackduck_writes=(
                args.max_writes
            ),
            stop_on_failure=True,
        ),
    )
    result_path = write_execution_result(
        args.result_root,
        result,
    )

    return result.as_dict(), str(result_path)


def run(args: argparse.Namespace) -> int:
    validate_args(args)
    configuration = load_cip_configuration(
        args.config
    )
    deadline = (
        time.monotonic()
        + args.max_hours * 3600
    )
    cache_root = Path(
        args.cache_root
    ).expanduser()
    client = create_blackduck_client(
        base_url=(
            configuration.blackduck_base_url
        ),
        api_token=args.api_token,
        args=args,
    )
    client.request_control = (
        BudgetedRequestController(
            client.request_control,
            args.max_blackduck_requests,
        )
    )
    gitlab = BudgetedGitLabCommitClient(
        token=args.gitlab_token,
        base_url=args.gitlab_rest_url,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        request_interval_seconds=(
            args
            .gitlab_request_interval_seconds
        ),
        insecure=args.insecure,
        ca_bundle=args.ca_bundle,
        deadline=deadline,
        maximum_requests=(
            args.max_gitlab_requests
        ),
    )
    run_id = (
        time.strftime(
            "%Y%m%dT%H%M%SZ",
            time.gmtime(),
        )
        + "-"
        + uuid.uuid4().hex[:8]
    )

    with FileLock(
        args.lock,
        stale_seconds=(
            args.lock_stale_seconds
        ),
        wait_seconds=0,
    ):
        client.authenticate()
        planning = create_cip_plan(
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
                candidate_limit(
                    args,
                    configuration,
                )
            ),
            progress_every=(
                args.progress_every
            ),
            refresh_target_cursors=(
                args.refresh_target_cursors
            ),
        )

        execution = None
        result_path = ""

        if args.mode != "plan":
            execution, result_path = (
                execute_plan(
                    planning,
                    client,
                    configuration,
                    args,
                )
            )

    blackduck_requests = (
        client.request_control.request_count
    )
    gitlab_stats = gitlab.stats()
    status = "ok"

    if planning.failure_count:
        status = "partial"

    if (
        execution is not None
        and execution["status"] != "ok"
    ):
        status = "partial"

    summary = {
        "run_id": run_id,
        "mode": args.mode,
        "status": status,
        "plan": planning.as_dict(),
        "execution": execution,
        "result_path": result_path,
        "blackduck_requests": (
            blackduck_requests
        ),
        "gitlab_requests": (
            gitlab_stats.requests
        ),
        "gitlab_retries": (
            gitlab_stats.retries
        ),
    }
    print(
        json.dumps(
            summary,
            indent=2,
            sort_keys=True,
        )
    )

    return 0 if status == "ok" else 1


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Plan and execute bounded Linux CIP "
            "remediation actions."
        )
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--plan-only",
        dest="mode",
        action="store_const",
        const="plan",
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
    parser.set_defaults(mode="dry-run")
    parser.add_argument(
        "--confirm-apply",
        action="store_true",
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
        "--result-root",
        default=default_result_root(),
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
        default=100,
    )
    parser.add_argument(
        "--max-candidates-per-run",
        type=int,
        default=25,
    )
    parser.add_argument(
        "--max-actions",
        type=int,
        default=100,
    )
    parser.add_argument(
        "--max-reads",
        type=int,
        default=500,
    )
    parser.add_argument(
        "--max-writes",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--max-blackduck-requests",
        type=int,
        default=500,
    )
    parser.add_argument(
        "--max-gitlab-requests",
        type=int,
        default=500,
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--refresh-target-cursors",
        action="store_true",
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
        "--action-api-token",
        default=os.getenv(
            "BLACKDUCK_ACTION_API_TOKEN",
            "",
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
    tokens = [
        os.getenv(
            "BLACKDUCK_ACTION_API_TOKEN",
            "",
        ),
        os.getenv("GITLAB_TOKEN", ""),
    ]

    try:
        return run(parse_args())
    except KeyboardInterrupt:
        return 130
    except (
        LockUnavailableError,
        RequestBudgetExceeded,
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
