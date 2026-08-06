from __future__ import annotations

import argparse
import csv
import os
import sys
from pathlib import Path
from typing import Any

from wintermute.blackduck.cohort import load_cohort
from wintermute.blackduck.criteria import (
    datadog_high_risk_criteria,
)
from wintermute.blackduck.filtering import filter_findings
from wintermute.blackduck.projections import (
    datadog_finding_rows,
)
from wintermute.datadog import findings_to_datadog as publisher
from wintermute.paths import ensure_parent_dir, output_root


def destination_root() -> Path:
    return output_root() / "destinations" / "datadog"


def write_findings(
    path: Path,
    rows: list[dict[str, str]],
) -> None:
    ensure_parent_dir(path)
    fieldnames = list(
        dict.fromkeys(
            publisher.REQUIRED_FIELDS
            + sorted(
                {
                    key
                    for row in rows
                    for key in row
                }
            )
        )
    )

    with path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as output_file:
        writer = csv.DictWriter(
            output_file,
            fieldnames=fieldnames,
        )
        writer.writeheader()

        for row in rows:
            writer.writerow(
                {
                    field: row.get(field, "")
                    for field in fieldnames
                }
            )


def run(args: argparse.Namespace) -> int:
    cohort = load_cohort(
        args.cohort,
        verify_checksums=not args.skip_checksum_validation,
    )
    cohort_failure_count = (
        len(cohort.scope_failures)
        + len(cohort.collection_failures)
    )

    if cohort_failure_count and args.strict:
        raise RuntimeError(
            f"Cohort contains {cohort_failure_count} "
            "collection failure(s)"
        )

    findings = filter_findings(
        cohort.findings,
        datadog_high_risk_criteria(
            threshold=args.threshold,
            score_field=args.score_field,
            require_exploit_available=(
                args.require_exploit_available
            ),
            require_reachable=(
                args.require_reachable
            ),
            reachability_mode=(
                args.reachability_mode
            ),
            policy_name=args.policy_name or "",
            policy_rule_id=(
                args.policy_rule_id or ""
            ),
        ),
    )
    rows = datadog_finding_rows(
        findings,
        group_by=args.group_by,
    )
    run_directory = (
        destination_root()
        / "runs"
        / cohort.cohort_id
    )
    run_directory.mkdir(
        parents=True,
        exist_ok=True,
    )
    findings_path = (
        run_directory / "policy-findings.csv"
    )
    results_path = (
        run_directory
        / "datadog-publish-results.csv"
    )
    plan_path = (
        run_directory
        / "datadog-publish-plan.json"
    )
    write_findings(findings_path, rows)

    publish_args = argparse.Namespace(
        findings=str(findings_path),
        destination="events",
        event_mode=args.event_mode,
        site=args.site,
        insecure=args.insecure,
        api_key_env=args.api_key_env,
        service=args.service,
        source=args.source,
        env=args.env,
        tags=args.tags,
        state=args.state,
        results_out=str(results_path),
        plan_out=str(plan_path),
        apply=args.apply,
        dry_run=args.dry_run or not args.apply,
        refresh_existing=args.refresh_existing,
        send_resolved=args.send_resolved,
        max_send=args.max_send,
        event_project_limit=(
            args.event_project_limit
        ),
        event_component_limit=(
            args.event_component_limit
        ),
        event_finding_limit=(
            args.event_finding_limit
        ),
        event_vulnerability_link_limit=(
            args.event_vulnerability_link_limit
        ),
        progress_every=args.progress_every,
        checkpoint_every=args.checkpoint_every,
        fail_fast=args.fail_fast,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        debug=args.debug,
    )

    result = publisher.process(publish_args)
    publisher.atomic_write_json(
        str(
            run_directory
            / "cohort-consumer-summary.json"
        ),
        {
            "cohort_id": cohort.cohort_id,
            "destination": "datadog",
            "dry_run": publish_args.dry_run,
            "filtered_finding_count": len(findings),
            "projected_row_count": len(rows),
            "cohort_failure_count": (
                cohort_failure_count
            ),
            "exit_code": result,
        },
    )

    return result


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Consume an immutable Wintermute cohort "
            "and publish its Datadog projection."
        )
    )
    parser.add_argument("--cohort", required=True)
    parser.add_argument(
        "--state",
        default=str(
            destination_root()
            / "state"
            / "datadog-findings-state.json"
        ),
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=8.9,
    )
    parser.add_argument(
        "--score-field",
        default="overallScore",
    )
    parser.set_defaults(
        require_exploit_available=True,
        send_resolved=True,
        strict=True,
    )
    parser.add_argument(
        "--require-exploit-available",
        dest="require_exploit_available",
        action="store_true",
    )
    parser.add_argument(
        "--no-require-exploit-available",
        dest="require_exploit_available",
        action="store_false",
    )
    parser.add_argument(
        "--require-reachable",
        action="store_true",
    )
    parser.add_argument(
        "--reachability-mode",
        choices=["none", "field", "ai"],
        default="none",
    )
    parser.add_argument("--policy-name")
    parser.add_argument("--policy-rule-id")
    parser.add_argument(
        "--group-by",
        choices=["project", "project-version"],
        default="project",
    )
    parser.add_argument(
        "--event-mode",
        choices=[
            "vulnerability",
            "project",
            "finding",
            "both",
        ],
        default="vulnerability",
    )
    parser.add_argument(
        "--site",
        default="datadoghq.com",
    )
    parser.add_argument(
        "--api-key-env",
        default="DATADOG_API_KEY",
    )
    parser.add_argument(
        "--service",
        default="blackduck",
    )
    parser.add_argument(
        "--source",
        default="blackduck",
    )
    parser.add_argument("--env", default="")
    parser.add_argument("--tags", default="")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument(
        "--dry-run",
        action="store_true",
    )
    parser.add_argument(
        "--strict",
        dest="strict",
        action="store_true",
    )
    parser.add_argument(
        "--allow-partial",
        dest="strict",
        action="store_false",
    )
    parser.add_argument(
        "--skip-checksum-validation",
        action="store_true",
    )
    parser.add_argument(
        "--refresh-existing",
        action="store_true",
    )
    parser.add_argument(
        "--send-resolved",
        dest="send_resolved",
        action="store_true",
    )
    parser.add_argument(
        "--no-send-resolved",
        dest="send_resolved",
        action="store_false",
    )
    parser.add_argument("--max-send", type=int)
    parser.add_argument(
        "--event-project-limit",
        type=int,
        default=25,
    )
    parser.add_argument(
        "--event-component-limit",
        type=int,
        default=8,
    )
    parser.add_argument(
        "--event-finding-limit",
        type=int,
        default=3,
    )
    parser.add_argument(
        "--event-vulnerability-link-limit",
        type=int,
        default=3,
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=25,
    )
    parser.add_argument(
        "--checkpoint-every",
        type=int,
        default=25,
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
    )
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=2.0,
    )
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
    except RuntimeError as error:
        print(
            f"ERROR: {error}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
