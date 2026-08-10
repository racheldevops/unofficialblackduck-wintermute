from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from wintermute.blackduck.client import (
    BlackDuckClient,
)
from wintermute.blackduck.inventory import (
    InventoryFilter,
)
from wintermute.paths import output_root
from wintermute.scm.coverage.models import (
    MappingMetadataFields,
)
from wintermute.scm.coverage.pipeline import (
    execute_coverage,
    load_explicit_mappings,
)
from wintermute.scm.coverage.snapshot import (
    CoverageSnapshotError,
    mark_coverage_complete,
    prune_coverage_snapshots,
    write_coverage_snapshot,
)


def default_coverage_root() -> str:
    return str(
        output_root()
        / "scm"
        / "coverage"
        / "snapshots"
    )


def validate_args(
    args: argparse.Namespace,
) -> None:
    if not Path(
        args.scm_snapshot
    ).is_dir():
        raise RuntimeError(
            "SCM inventory snapshot does not exist"
        )

    if args.workers < 1:
        raise RuntimeError(
            "--workers must be greater than zero"
        )

    if not 1 <= args.scan_evidence_workers <= 8:
        raise RuntimeError(
            "--scan-evidence-workers must be "
            "between 1 and 8"
        )

    if args.freshness_sla_days < 1:
        raise RuntimeError(
            "--freshness-sla-days must be positive"
        )

    if args.retain_snapshots < 1:
        raise RuntimeError(
            "--retain-snapshots must be positive"
        )

    if args.timeout < 1:
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

    if args.page_limit < 1:
        raise RuntimeError(
            "--page-limit must be greater than zero"
        )


def run(
    args: argparse.Namespace,
) -> int:
    validate_args(args)
    client = BlackDuckClient(
        base_url=args.bd_url,
        api_token=args.api_token,
        insecure=args.insecure,
        ca_bundle=args.ca_bundle,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        page_limit=args.page_limit,
    )
    client.authenticate()
    execution = execute_coverage(
        client,
        args.scm_snapshot,
        inventory_filter=InventoryFilter(
            project_name=(
                args.project_name or ""
            ),
            project_name_contains=(
                args.project_name_contains
                or ""
            ),
            version_name=(
                args.version_name or ""
            ),
            phase=args.phase or "",
            max_projects=args.max_projects,
            max_versions=args.max_versions,
        ),
        workers=args.workers,
        metadata_fields=(
            MappingMetadataFields(
                provider=(
                    args.provider_field
                ),
                provider_instance=(
                    args.provider_instance_field
                ),
                repository_id=(
                    args.repository_id_field
                ),
                canonical_url=(
                    args.repository_url_field
                ),
            )
        ),
        explicit_mappings=(
            load_explicit_mappings(
                args.explicit_mappings
            )
        ),
        scan_evidence_path=(
            args.scan_evidence
        ),
        collect_direct_scan_evidence=(
            not args.skip_direct_scan_evidence
        ),
        scan_evidence_workers=(
            args.scan_evidence_workers
        ),
        freshness_sla_days=(
            args.freshness_sla_days
        ),
    )
    directory = write_coverage_snapshot(
        args.coverage_root,
        execution,
        snapshot_id=args.snapshot_id,
    )
    mark_coverage_complete(directory)
    pruned = prune_coverage_snapshots(
        args.coverage_root,
        retain_count=(
            args.retain_snapshots
        ),
        protected_ids={
            directory.name
        },
        require_complete=True,
    )
    metrics = __import__(
        "wintermute.scm.coverage.reporting",
        fromlist=["coverage_report_payload"],
    ).coverage_report_payload(
        execution.report
    )["metrics"]
    failure_count = (
        execution.report.provider_failure_count
        + execution.report.blackduck_failure_count
    )

    print(
        json.dumps(
            {
                "snapshot_id": directory.name,
                "snapshot_directory": str(
                    directory
                ),
                "repository_count": (
                    execution.report
                    .repository_count
                ),
                "eligible_repository_count": (
                    execution.report
                    .eligible_repository_count
                ),
                "authoritative_mapping_count": (
                    execution.mappings
                    .authoritative_count
                ),
                "mapping_recommendation_count": (
                    execution.mappings
                    .recommendation_count
                ),
                "mapping_conflict_count": (
                    execution.mappings
                    .conflict_count
                ),
                "metrics": metrics,
                "failure_count": failure_count,
                "pruned_snapshot_ids": list(
                    pruned
                ),
                "status": (
                    "partial"
                    if failure_count
                    else "succeeded"
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )

    return (
        1
        if failure_count
        else 0
    )


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Reconcile an immutable SCM inventory "
            "with Black Duck registration and scan evidence."
        )
    )
    parser.add_argument(
        "--scm-snapshot",
        required=True,
    )
    parser.add_argument(
        "--coverage-root",
        default=default_coverage_root(),
    )
    parser.add_argument("--snapshot-id")
    parser.add_argument(
        "--explicit-mappings",
    )
    parser.add_argument(
        "--scan-evidence",
    )
    parser.add_argument(
        "--scan-evidence-workers",
        type=int,
        default=4,
        help=(
            "Concurrent read-only Black Duck scan "
            "evidence requests. Range: 1-8."
        ),
    )
    parser.add_argument(
        "--skip-direct-scan-evidence",
        action="store_true",
        help=(
            "Do not query code-location and scan-summary "
            "evidence. Scan state remains unknown unless "
            "--scan-evidence is supplied."
        ),
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
        "--provider-field",
        default="scm_provider",
    )
    parser.add_argument(
        "--provider-instance-field",
        default="scm_provider_instance",
    )
    parser.add_argument(
        "--repository-id-field",
        default="scm_repository_id",
    )
    parser.add_argument(
        "--repository-url-field",
        default="scm_repository_url",
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
    parser.add_argument("--project-name")
    parser.add_argument(
        "--project-name-contains"
    )
    parser.add_argument("--version-name")
    parser.add_argument("--phase")
    parser.add_argument(
        "--max-projects",
        type=int,
    )
    parser.add_argument(
        "--max-versions",
        type=int,
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
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
        default=2.0,
    )
    parser.add_argument(
        "--page-limit",
        type=int,
        default=500,
    )
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument(
        "--insecure",
        action="store_true",
    )
    tls.add_argument("--ca-bundle")

    return parser.parse_args(argv)


def main(
    argv: list[str] | None = None,
) -> int:
    try:
        return run(
            parse_args(argv)
        )
    except KeyboardInterrupt:
        return 130
    except (
        CoverageSnapshotError,
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
