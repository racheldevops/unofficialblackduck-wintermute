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
from wintermute.scm.providers.detection import (
    gitlab_group_from_url,
    provider_from_url,
)
from wintermute.scm.providers.github.client import (
    DEFAULT_GRAPHQL_ENDPOINT,
)
from wintermute.scm.providers.github.rest import (
    DEFAULT_REST_BASE_URL as DEFAULT_GITHUB_REST_URL,
)
from wintermute.scm.providers.gitlab.client import (
    DEFAULT_REST_BASE_URL as DEFAULT_GITLAB_REST_URL,
)


Operation = Callable[
    [list[str] | None],
    int,
]

REQUIRED_ENVIRONMENT = (
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


def selected_provider(
    scm_url: str,
    gitlab_group: str,
    gitlab_rest_url: str,
) -> str:
    if str(scm_url or "").strip():
        return provider_from_url(scm_url)

    if (
        str(gitlab_group or "").strip()
        or str(gitlab_rest_url or "").strip()
    ):
        return "gitlab"

    return "github"


def selected_gitlab_group(
    scm_url: str,
    gitlab_group: str,
) -> str:
    return (
        str(gitlab_group or "").strip()
        or gitlab_group_from_url(scm_url)
    )


def validate_environment(
    organization: str,
    *,
    scm_url: str = "",
    gitlab_group: str = "",
    gitlab_rest_url: str = "",
) -> str:
    provider = selected_provider(
        scm_url,
        gitlab_group,
        gitlab_rest_url,
    )
    missing = [
        name
        for name in REQUIRED_ENVIRONMENT
        if not os.getenv(name, "").strip()
    ]

    if provider == "gitlab":
        if not os.getenv(
            "GITLAB_TOKEN",
            "",
        ).strip():
            missing.append("GITLAB_TOKEN")

        if not selected_gitlab_group(
            scm_url,
            gitlab_group,
        ):
            missing.append("GITLAB_GROUP")
    else:
        if not os.getenv(
            "GITHUB_TOKEN",
            "",
        ).strip():
            missing.append("GITHUB_TOKEN")

        if not str(
            organization or ""
        ).strip():
            missing.append("GITHUB_ORG")

    if missing:
        raise RuntimeError(
            "Missing required environment "
            "variable(s): "
            + ", ".join(
                sorted(set(missing))
            )
        )

    return provider


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
    scm_url = str(
        args.scm_url
        or os.getenv("SCM_URL")
        or ""
    ).strip()
    organization = str(
        args.organization
        or os.getenv("GITHUB_ORG")
        or ""
    ).strip()
    gitlab_group = str(
        args.group
        or os.getenv("GITLAB_GROUP")
        or ""
    ).strip()
    gitlab_rest_url = str(
        args.gitlab_rest_url
        or os.getenv("GITLAB_REST_URL")
        or ""
    ).strip()
    provider = validate_environment(
        organization,
        scm_url=scm_url,
        gitlab_group=gitlab_group,
        gitlab_rest_url=gitlab_rest_url,
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
                "Refusing to replace existing "
                f"snapshot: {path}"
            )

    shared_tls = tls_arguments(args)
    inventory_arguments = [
        "--snapshot-root",
        str(inventory_root),
        "--snapshot-id",
        run_id,
        "--page-size",
        str(args.page_size),
        "--workers",
        str(args.workers),
        "--evidence-workers",
        str(args.evidence_workers),
        "--pipeline-limit",
        str(args.pipeline_limit),
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

    if provider == "gitlab":
        group = selected_gitlab_group(
            scm_url,
            gitlab_group,
        )
        selected_url = (
            scm_url
            or gitlab_rest_url
            or DEFAULT_GITLAB_REST_URL
        )
        inventory_arguments.extend(
            [
                "--scm-url",
                selected_url,
                "--group",
                group,
            ]
        )

        if gitlab_rest_url:
            inventory_arguments.extend(
                [
                    "--gitlab-rest-url",
                    gitlab_rest_url,
                ]
            )
    else:
        inventory_arguments.extend(
            [
                "--organization",
                organization,
                "--graphql-endpoint",
                args.graphql_endpoint,
                "--rest-base-url",
                args.rest_base_url,
            ]
        )

        if scm_url:
            inventory_arguments.extend(
                [
                    "--scm-url",
                    scm_url,
                ]
            )

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
                "provider": provider,
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

    if args.max_projects is not None:
        coverage_arguments.extend(
            [
                "--max-projects",
                str(args.max_projects),
            ]
        )

    if args.max_versions is not None:
        coverage_arguments.extend(
            [
                "--max-versions",
                str(args.max_versions),
            ]
        )

    if args.collect_direct_scan_evidence:
        coverage_arguments.append(
            "--collect-direct-scan-evidence"
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
    observed_result = (
        2
        if coverage_result not in {0, 1}
        else 1
        if (
            inventory_result == 1
            or coverage_result == 1
        )
        else 0
    )
    result = (
        0
        if (
            args.allow_partial
            and observed_result == 1
        )
        else observed_result
    )

    print(
        json.dumps(
            {
                "operation": (
                    "scm-read-only-validation"
                ),
                "phase": "complete",
                "provider": provider,
                "run_id": run_id,
                "inventory_exit_code": (
                    inventory_result
                ),
                "coverage_exit_code": (
                    coverage_result
                ),
                "exit_code": result,
                "observed_exit_code": (
                    observed_result
                ),
                "partial_accepted": (
                    args.allow_partial
                    and observed_result == 1
                ),
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
            "Run SCM inventory followed by "
            "Black Duck coverage reconciliation."
        )
    )
    parser.add_argument(
        "--scm-url",
        default=os.getenv(
            "SCM_URL",
            "",
        ),
    )
    parser.add_argument(
        "--organization",
    )
    parser.add_argument(
        "--group",
    )
    parser.add_argument(
        "--graphql-endpoint",
        default=os.getenv(
            "GITHUB_GRAPHQL_URL",
            DEFAULT_GRAPHQL_ENDPOINT,
        ),
    )
    parser.add_argument(
        "--rest-base-url",
        default=os.getenv(
            "GITHUB_REST_URL",
            DEFAULT_GITHUB_REST_URL,
        ),
    )
    parser.add_argument(
        "--gitlab-rest-url",
        default=os.getenv(
            "GITLAB_REST_URL",
            "",
        ),
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
        "--pipeline-limit",
        type=int,
        default=20,
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
        "--max-projects",
        type=int,
    )
    parser.add_argument(
        "--max-versions",
        type=int,
    )
    parser.add_argument(
        "--scan-evidence",
    )
    parser.add_argument(
        "--skip-provider-evidence",
        action="store_true",
    )
    parser.add_argument(
        "--collect-direct-scan-evidence",
        action="store_true",
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
        "--max-hours",
        type=float,
        default=2,
    )
    parser.add_argument(
        "--allow-partial",
        action="store_true",
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
