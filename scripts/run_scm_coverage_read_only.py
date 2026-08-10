#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from wintermute.paths import output_root
from wintermute.scm.cli import (
    main as inventory_main,
)
from wintermute.scm.coverage.cli import (
    main as coverage_main,
)


Operation = Callable[
    [list[str] | None],
    int,
]

REQUIRED_ENVIRONMENT = (
    "GITHUB_TOKEN",
    "BLACKDUCK_URL",
    "BLACKDUCK_API_TOKEN",
)


def create_run_id() -> str:
    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")

    return (
        f"scm-read-only-{timestamp}-"
        f"{uuid.uuid4().hex[:8]}"
    )


def validate_environment(
    organization: str,
) -> None:
    missing = [
        name
        for name in REQUIRED_ENVIRONMENT
        if not os.getenv(name, "").strip()
    ]

    if not organization:
        missing.append("GITHUB_ORG")

    if missing:
        raise RuntimeError(
            "Missing required environment variable(s): "
            + ", ".join(sorted(set(missing)))
        )


def tls_arguments(
    args: argparse.Namespace,
) -> list[str]:
    if args.insecure:
        return ["--insecure"]

    if args.ca_bundle:
        return [
            "--ca-bundle",
            args.ca_bundle,
        ]

    return []


def run(
    args: argparse.Namespace,
    *,
    inventory_operation: Operation = (
        inventory_main
    ),
    coverage_operation: Operation = (
        coverage_main
    ),
) -> int:
    organization = str(
        args.organization
        or os.getenv("GITHUB_ORG")
        or ""
    ).strip()
    validate_environment(
        organization
    )

    run_id = (
        args.snapshot_id
        or create_run_id()
    )
    root = Path(
        args.output_root
    ).expanduser().resolve()
    inventory_root = (
        root
        / "scm"
        / "inventory"
        / "snapshots"
    )
    coverage_root = (
        root
        / "scm"
        / "coverage"
        / "snapshots"
    )
    inventory_snapshot = (
        inventory_root / run_id
    )
    coverage_snapshot = (
        coverage_root / run_id
    )

    for path in (
        inventory_snapshot,
        coverage_snapshot,
    ):
        if path.exists():
            raise RuntimeError(
                f"Refusing to replace existing "
                f"snapshot: {path}"
            )

    shared_tls = tls_arguments(args)
    inventory_arguments = [
        "--organization",
        organization,
        "--snapshot-root",
        str(inventory_root),
        "--snapshot-id",
        run_id,
        "--page-size",
        str(args.page_size),
        "--evidence-workers",
        str(args.evidence_workers),
        "--timeout",
        str(args.timeout),
        "--retries",
        str(args.retries),
        "--retry-delay",
        str(args.retry_delay),
        "--max-hours",
        str(args.max_hours),
        *shared_tls,
    ]

    if args.skip_provider_evidence:
        inventory_arguments.append(
            "--skip-provider-evidence"
        )

    print(
        json.dumps(
            {
                "operation": (
                    "scm-read-only-validation"
                ),
                "phase": "inventory",
                "run_id": run_id,
                "inventory_snapshot": str(
                    inventory_snapshot
                ),
                "coverage_snapshot": str(
                    coverage_snapshot
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )
    inventory_result = (
        inventory_operation(
            inventory_arguments
        )
    )

    if inventory_result not in {0, 1}:
        return inventory_result

    coverage_arguments = [
        "--scm-snapshot",
        str(inventory_snapshot),
        "--coverage-root",
        str(coverage_root),
        "--snapshot-id",
        run_id,
        "--workers",
        str(args.workers),
        "--scan-evidence-workers",
        str(
            args.scan_evidence_workers
        ),
        "--freshness-sla-days",
        str(args.freshness_sla_days),
        "--retain-snapshots",
        str(args.retain_snapshots),
        "--timeout",
        str(args.timeout),
        "--retries",
        str(args.retries),
        "--retry-delay",
        str(args.retry_delay),
        "--page-limit",
        str(args.page_limit),
        *shared_tls,
    ]

    if args.skip_direct_scan_evidence:
        coverage_arguments.append(
            "--skip-direct-scan-evidence"
        )

    if args.scan_evidence:
        coverage_arguments.extend(
            [
                "--scan-evidence",
                args.scan_evidence,
            ]
        )

    coverage_result = (
        coverage_operation(
            coverage_arguments
        )
    )
    result = (
        2
        if coverage_result not in {0, 1}
        else 1
        if (
            inventory_result == 1
            or coverage_result == 1
        )
        else 0
    )

    print(
        json.dumps(
            {
                "operation": (
                    "scm-read-only-validation"
                ),
                "phase": "complete",
                "run_id": run_id,
                "inventory_exit_code": (
                    inventory_result
                ),
                "coverage_exit_code": (
                    coverage_result
                ),
                "exit_code": result,
                "inventory_snapshot": str(
                    inventory_snapshot
                ),
                "coverage_snapshot": str(
                    coverage_snapshot
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )

    return result


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run GitHub SCM inventory followed by "
            "Black Duck coverage reconciliation. "
            "All provider operations are read-only."
        )
    )
    parser.add_argument(
        "--organization",
    )
    parser.add_argument(
        "--output-root",
        default=str(output_root()),
    )
    parser.add_argument(
        "--snapshot-id",
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=100,
    )
    parser.add_argument(
        "--page-limit",
        type=int,
        default=500,
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
    )
    parser.add_argument(
        "--evidence-workers",
        type=int,
        default=4,
    )
    parser.add_argument(
        "--scan-evidence-workers",
        type=int,
        default=4,
    )
    parser.add_argument(
        "--freshness-sla-days",
        type=int,
        default=30,
    )
    parser.add_argument(
        "--retain-snapshots",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--scan-evidence",
    )
    parser.add_argument(
        "--skip-provider-evidence",
        action="store_true",
    )
    parser.add_argument(
        "--skip-direct-scan-evidence",
        action="store_true",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=1.0,
    )
    parser.add_argument(
        "--max-hours",
        type=float,
        default=2.0,
    )
    tls = parser.add_mutually_exclusive_group()
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
    try:
        return run(
            parse_args(argv)
        )
    except KeyboardInterrupt:
        print(
            "Interrupted.",
            file=sys.stderr,
        )
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
