from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from wintermute.blackduck.cohort import (
    CohortError,
    load_cohort,
    mark_cohort_complete,
    prune_cohorts,
)


DESTINATION_MODES = {
    "disabled",
    "dry-run",
    "apply",
}

TERMINAL_TASK_STATUSES = {
    "succeeded",
    "failed",
    "error",
    "errored",
}


def destination_status(
    mode: str,
    task_status: str,
) -> str:
    if mode == "disabled":
        return "disabled"

    normalized = str(
        task_status or ""
    ).strip().lower()

    if normalized not in TERMINAL_TASK_STATUSES:
        raise RuntimeError(
            f"Enabled destination in mode {mode!r} "
            f"did not reach a terminal state: "
            f"{task_status!r}"
        )

    return (
        "error"
        if normalized == "errored"
        else normalized
    )


def run(args: argparse.Namespace) -> int:
    root = Path(args.cohort_root)
    cohort_directory = root / args.cohort_id
    cohort = load_cohort(cohort_directory)

    statuses = {
        "jira": destination_status(
            args.jira_mode,
            args.jira_status,
        ),
        "datadog": destination_status(
            args.datadog_mode,
            args.datadog_status,
        ),
    }

    mark_cohort_complete(
        cohort.directory,
        destination_statuses=statuses,
    )
    removed = prune_cohorts(
        root,
        retain_count=args.retain_cohorts,
        protected_ids={cohort.cohort_id},
        require_complete=True,
    )

    print(
        json.dumps(
            {
                "cohort_id": cohort.cohort_id,
                "status": "complete",
                "destination_statuses": statuses,
                "pruned_cohorts": list(removed),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Mark a cohort complete after destination "
            "processing and prune completed cohorts."
        )
    )
    parser.add_argument(
        "--cohort-root",
        required=True,
    )
    parser.add_argument(
        "--cohort-id",
        required=True,
    )
    parser.add_argument(
        "--retain-cohorts",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--jira-mode",
        choices=sorted(DESTINATION_MODES),
        default="dry-run",
    )
    parser.add_argument(
        "--datadog-mode",
        choices=sorted(DESTINATION_MODES),
        default="dry-run",
    )
    parser.add_argument(
        "--jira-status",
        required=True,
    )
    parser.add_argument(
        "--datadog-status",
        required=True,
    )

    return parser.parse_args(argv)


def main() -> int:
    try:
        return run(parse_args())
    except (
        CohortError,
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
