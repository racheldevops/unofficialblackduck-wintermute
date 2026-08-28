from __future__ import annotations

import argparse
import json
import os
import sys

from wintermute.blackduck.actions.artifacts import (
    ActionArtifactError,
    load_verified_action_plan,
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
from wintermute.paths import output_root


def default_result_root() -> str:
    return str(
        output_root()
        / "blackduck"
        / "actions"
        / "results"
    )


def default_lock_path() -> str:
    return str(
        output_root()
        / "blackduck"
        / "actions"
        / "executor.lock"
    )


def validate_args(
    args: argparse.Namespace,
) -> None:
    if args.timeout <= 0:
        raise RuntimeError(
            "--timeout must be greater than zero"
        )

    if args.retries < 0:
        raise RuntimeError(
            "--retries cannot be negative"
        )

    if args.retry_delay < 0:
        raise RuntimeError(
            "--retry-delay cannot be negative"
        )

    if args.request_interval_seconds < 0:
        raise RuntimeError(
            "--request-interval-seconds cannot "
            "be negative"
        )

    for name in (
        "max_actions",
        "max_reads",
        "max_writes",
    ):
        if int(getattr(args, name)) < 0:
            raise RuntimeError(
                f"--{name.replace('_', '-')} "
                "cannot be negative"
            )


def run(args: argparse.Namespace) -> int:
    validate_args(args)
    plan = load_verified_action_plan(
        args.plan
    )
    client = BlackDuckClient(
        base_url=args.bd_url,
        api_token=args.api_token,
        insecure=args.insecure,
        ca_bundle=args.ca_bundle,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        page_limit=100,
        debug=args.debug,
        api_cache=None,
        request_interval_seconds=(
            args.request_interval_seconds
        ),
    )
    client.cache_raw_gets = False
    client.cache_paged_results = False
    client.authenticate()
    read_client = (
        client.clone_for_uncached_reads()
    )
    write_client = (
        BlackDuckActionHttpClient(client)
    )
    registry = ActionRegistry()
    registry.register(
        VulnerabilityRemediationHandler(
            read_client,
            write_client,
            preserve_existing_decisions=True,
            allowed_statuses=tuple(
                args.allow_remediation_status
                or ["PATCHED"]
            ),
        )
    )
    policy = ExecutionPolicy(
        mode=args.mode,
        confirm_apply=args.confirm_apply,
        expected_plan_digest=(
            args.expected_plan_digest or ""
        ),
        expected_blackduck_base_url=(
            args.bd_url
        ),
        allowed_producers=tuple(
            args.allow_producer or ()
        ),
        allowed_action_kinds=tuple(
            args.allow_action_kind or ()
        ),
        maximum_actions=args.max_actions,
        maximum_blackduck_reads=(
            args.max_reads
        ),
        maximum_blackduck_writes=(
            args.max_writes
        ),
        stop_on_failure=(
            not args.continue_on_failure
        ),
    )

    with FileLock(
        args.lock,
        stale_seconds=args.lock_stale_seconds,
        wait_seconds=args.lock_wait_seconds,
    ):
        result = ActionExecutor(
            registry
        ).execute(
            plan,
            policy,
        )
        result_path = write_execution_result(
            args.result_root,
            result,
        )

    print(
        json.dumps(
            {
                "execution_id": (
                    result.execution_id
                ),
                "plan_id": result.plan_id,
                "plan_digest": (
                    result.plan_digest
                ),
                "mode": result.mode,
                "status": result.status,
                "reads": result.reads,
                "writes": result.writes,
                "counts": result.counts,
                "result_path": str(result_path),
            },
            indent=2,
            sort_keys=True,
        )
    )

    return (
        0
        if result.status == "ok"
        else 1
    )


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate, preview, or apply a "
            "Black Duck action plan."
        )
    )
    parser.add_argument(
        "--plan",
        default=os.getenv(
            "WINTERMUTE_ACTION_PLAN"
        ),
        required=(
            os.getenv(
                "WINTERMUTE_ACTION_PLAN"
            )
            is None
        ),
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
        "--allow-producer",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--allow-action-kind",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--allow-remediation-status",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--max-actions",
        type=int,
        default=10,
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
        "--continue-on-failure",
        action="store_true",
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
        "--lock-wait-seconds",
        type=float,
        default=0,
    )
    parser.add_argument(
        "--bd-url",
        default=os.getenv("BLACKDUCK_URL"),
        required=(
            os.getenv("BLACKDUCK_URL")
            is None
        ),
    )
    parser.add_argument(
        "--api-token",
        default=(
            os.getenv(
                "BLACKDUCK_ACTION_API_TOKEN"
            )
            or os.getenv(
                "BLACKDUCK_API_TOKEN"
            )
        ),
        required=not bool(
            os.getenv(
                "BLACKDUCK_ACTION_API_TOKEN"
            )
            or os.getenv(
                "BLACKDUCK_API_TOKEN"
            )
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
        default=1,
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=2,
    )
    parser.add_argument(
        "--request-interval-seconds",
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
    try:
        return run(parse_args())
    except KeyboardInterrupt:
        return 130
    except (
        ActionArtifactError,
        LockUnavailableError,
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
