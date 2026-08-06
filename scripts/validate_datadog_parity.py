#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
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


def load_rows(path: Path) -> list[dict[str, str]]:
    if path.suffix.lower() == ".json":
        payload = json.loads(
            path.read_text(encoding="utf-8")
        )

        if not isinstance(payload, list):
            raise RuntimeError(
                "Direct findings JSON must be an array"
            )

        return [
            {
                str(key): str(value or "")
                for key, value in row.items()
            }
            for row in payload
            if isinstance(row, dict)
        ]

    with path.open(
        newline="",
        encoding="utf-8",
    ) as input_file:
        reader = csv.DictReader(input_file)

        if not reader.fieldnames:
            raise RuntimeError(
                "Direct findings CSV has no header"
            )

        return [
            {
                str(key): str(value or "")
                for key, value in row.items()
            }
            for row in reader
        ]


def compare_rows(
    cohort_rows: list[dict[str, str]],
    direct_rows: list[dict[str, str]],
) -> dict[str, Any]:
    cohort_by_id = {
        row["finding_external_id"]: row
        for row in cohort_rows
        if row.get("finding_external_id")
    }
    direct_by_id = {
        row["finding_external_id"]: row
        for row in direct_rows
        if row.get("finding_external_id")
    }
    cohort_ids = set(cohort_by_id)
    direct_ids = set(direct_by_id)
    missing = sorted(
        direct_ids - cohort_ids
    )
    extra = sorted(
        cohort_ids - direct_ids
    )

    return {
        "ok": not missing and not extra,
        "cohort_count": len(cohort_by_id),
        "direct_count": len(direct_by_id),
        "missing_from_cohort": missing,
        "extra_in_cohort": extra,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compare cohort-projected Datadog findings "
            "with a direct pull output."
        )
    )
    parser.add_argument(
        "--cohort",
        required=True,
    )
    parser.add_argument(
        "--direct-findings",
        required=True,
    )
    parser.add_argument(
        "--report",
        default=(
            ".validation-results/"
            "datadog-parity.json"
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
        "--group-by",
        choices=["project", "project-version"],
        default="project",
    )
    args = parser.parse_args()

    cohort = load_cohort(args.cohort)
    filtered = filter_findings(
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
        ),
    )
    cohort_rows = datadog_finding_rows(
        filtered,
        group_by=args.group_by,
    )
    direct_rows = load_rows(
        Path(args.direct_findings)
    )
    report = compare_rows(
        cohort_rows,
        direct_rows,
    )
    report.update(
        {
            "cohort_id": cohort.cohort_id,
            "threshold": args.threshold,
            "score_field": args.score_field,
            "require_exploit_available": (
                args.require_exploit_available
            ),
            "require_reachable": (
                args.require_reachable
            ),
            "group_by": args.group_by,
        }
    )
    report_path = Path(args.report)
    report_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    report_path.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        f"Datadog parity: "
        f"{'PASS' if report['ok'] else 'FAIL'}"
    )
    print(
        f"Cohort={report['cohort_count']} "
        f"Direct={report['direct_count']}"
    )
    print(f"Report: {report_path}")

    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
