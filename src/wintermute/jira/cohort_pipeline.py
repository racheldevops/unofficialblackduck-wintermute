from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path
from typing import Any

from wintermute.blackduck.cohort import load_cohort
from wintermute.blackduck.criteria import (
    jira_parent_rollup_criteria,
)
from wintermute.blackduck.filtering import filter_findings
from wintermute.blackduck.projections import (
    jira_parent_rollup_rows,
)
from wintermute.jira import findings_hierarchy_plan as hierarchy
from wintermute.jira import findings_to_jira as publisher
from wintermute.paths import (
    ensure_parent_dir,
    output_root,
    package_path,
)


def destination_root() -> Path:
    return output_root() / "destinations" / "jira"


def write_rows(
    path: Path,
    rows: list[dict[str, Any]],
) -> None:
    ensure_parent_dir(path)
    fieldnames = (
        hierarchy.REQUIRED_FINDING_FIELDS
        + hierarchy.OPTIONAL_FINDING_FIELDS
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


def atomic_write_json(
    path: Path,
    payload: Any,
) -> None:
    ensure_parent_dir(path)
    temporary = path.with_name(
        f"{path.name}.tmp"
    )
    temporary.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            default=str,
        )
        + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


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
        jira_parent_rollup_criteria(
            threshold=args.threshold,
            score_field=args.score_field,
            entity_custom_field=(
                args.entity_custom_field
            ),
            require_entity=args.require_entity,
        ),
    )

    if args.only_vulnerability:
        findings = [
            finding
            for finding in findings
            if finding.vulnerability
            == args.only_vulnerability
        ]

        if not findings:
            raise RuntimeError(
                "No cohort findings matched "
                f"--only-vulnerability "
                f"{args.only_vulnerability!r}"
            )
    rows = jira_parent_rollup_rows(findings)

    if findings and not rows:
        raise RuntimeError(
            "Cohort has no parent lineage contexts for "
            "Jira parent-rollup projection"
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
    findings_path = run_directory / "findings.csv"
    plan_path = run_directory / "jira-hierarchy-plan.json"
    summary_path = run_directory / "jira-hierarchy-summary.csv"
    nodes_path = run_directory / "jira-hierarchy-nodes.csv"
    publish_results = run_directory / "jira-rollup-results.csv"
    publish_plan = run_directory / "jira-rollup-plan.json"
    write_rows(findings_path, rows)

    normalized_findings = [
        hierarchy.normalize_finding(row)
        for row in rows
    ]
    unique_findings = hierarchy.dedupe_findings(
        normalized_findings
    )
    mode = hierarchy.normalize_hierarchy_mode(
        args.hierarchy_mode
    )
    nodes = hierarchy.build_nodes(
        unique_findings,
        hash_length=args.hash_length,
        hierarchy_mode=mode,
    )
    plan_payload = {
        "schema_version": hierarchy.SCHEMA_VERSION,
        "hierarchy_mode": mode,
        "generated_at": hierarchy.now_iso(),
        "source_cohort_id": cohort.cohort_id,
        "source_cohort": str(cohort.directory),
        "source_counts": {
            "normalized_finding_count": len(
                cohort.findings
            ),
            "filtered_finding_count": len(findings),
            "projected_row_count": len(rows),
        },
        "node_counts": hierarchy.count_nodes(nodes),
        "nodes": nodes,
    }
    hierarchy.write_json_file(
        str(plan_path),
        plan_payload,
    )
    hierarchy.write_summary_csv(
        str(summary_path),
        nodes,
    )
    hierarchy.write_nodes_csv(
        str(nodes_path),
        nodes,
    )

    publish_args = argparse.Namespace(
        config=args.config,
        state=args.state,
        hierarchy_plan=str(plan_path),
        sync_existing_fields=(
            args.sync_existing_fields
        ),
        only_parent_project=None,
        only_parent_version=None,
        only_subproject=None,
        only_vulnerability=None,
        limit=None,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        debug=args.debug,
        dry_run=args.dry_run or not args.apply,
        apply=args.apply,
        refresh_existing=args.refresh_existing,
        jql_label_batch_size=(
            args.jql_label_batch_size
        ),
        description_format=(
            args.description_format
        ),
        max_create=args.max_create,
        plan_out=str(publish_plan),
        results_out=str(publish_results),
    )
    result = publisher.process_hierarchy_plan(
        publish_args
    )
    atomic_write_json(
        run_directory / "cohort-consumer-summary.json",
        {
            "cohort_id": cohort.cohort_id,
            "destination": "jira",
            "dry_run": publish_args.dry_run,
            "filtered_finding_count": len(findings),
            "projected_row_count": len(rows),
            "node_count": len(nodes),
            "cohort_failure_count": cohort_failure_count,
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
            "and publish its Jira projection."
        )
    )
    parser.add_argument("--cohort", required=True)
    parser.add_argument(
        "--config",
        default=package_path(
            "jira",
            "config",
            "jira-rollup-config.json",
        ),
    )
    parser.add_argument(
        "--state",
        default=str(
            destination_root()
            / "state"
            / "jira-rollup-state.json"
        ),
    )
    parser.add_argument(
        "--hierarchy-mode",
        default="vulnerability-remediation",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=7.0,
    )
    parser.add_argument(
        "--score-field",
        default="overallScore",
    )
    parser.add_argument(
        "--entity-custom-field",
        default="foo Entity",
    )
    parser.add_argument(
        "--require-entity",
        action="store_true",
    )
    parser.add_argument(
        "--only-vulnerability",
    )
    parser.add_argument(
        "--hash-length",
        type=int,
        default=24,
    )
    parser.add_argument("--apply", action="store_true")
    parser.add_argument(
        "--dry-run",
        action="store_true",
    )
    parser.set_defaults(strict=True)
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
        "--sync-existing-fields",
        action="store_true",
    )
    parser.add_argument("--max-create", type=int)
    parser.add_argument(
        "--description-format",
        choices=["wiki", "adf"],
        default="wiki",
    )
    parser.add_argument(
        "--jql-label-batch-size",
        type=int,
        default=50,
    )
    parser.add_argument("--timeout", type=int, default=60)
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
