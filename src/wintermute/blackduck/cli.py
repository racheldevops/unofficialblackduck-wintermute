from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path
from typing import Any

from wintermute.blackduck.cache import (
    ApiResponseCache,
)
from wintermute.blackduck.client import (
    BlackDuckClient,
)
from wintermute.blackduck.criteria import (
    CollectionCriteria,
    ScoreOperator,
)
from wintermute.blackduck.inventory import (
    InventoryFilter,
)
from wintermute.blackduck.pull import (
    PullRequest,
    pull_scope,
)
from wintermute.blackduck.scopes import (
    CollectionScope,
    normalize_scope,
)
from wintermute.blackduck.serialization import (
    collection_failure_payload,
    normalized_finding_payload,
    scope_failure_payload,
)
from wintermute.paths import (
    ensure_parent_dir,
    output_root,
)


def blackduck_output_path(*parts: str) -> str:
    return str(
        output_root().joinpath(
            "blackduck",
            *parts,
        )
    )


def atomic_write_json(
    path: str,
    payload: Any,
) -> None:
    if not path:
        return

    ensure_parent_dir(path)
    temporary_path = f"{path}.tmp"

    with open(
        temporary_path,
        "w",
        encoding="utf-8",
    ) as output_file:
        json.dump(
            payload,
            output_file,
            indent=2,
            sort_keys=True,
            default=str,
        )

    os.replace(temporary_path, path)


def load_input_rows(
    path: str | None,
) -> list[dict[str, Any]]:
    if not path:
        return []

    input_path = Path(path)

    if not input_path.is_file():
        raise RuntimeError(
            f"Input file does not exist: {path}"
        )

    if input_path.suffix.lower() == ".json":
        try:
            payload = json.loads(
                input_path.read_text(
                    encoding="utf-8"
                )
            )
        except (
            OSError,
            json.JSONDecodeError,
        ) as error:
            raise RuntimeError(
                f"Failed reading input JSON "
                f"{path}: {error}"
            ) from error

        if not isinstance(payload, list):
            raise RuntimeError(
                f"{path} must contain a JSON array"
            )

        return [
            {
                str(key): value
                for key, value in row.items()
            }
            for row in payload
            if isinstance(row, dict)
        ]

    try:
        with input_path.open(
            newline="",
            encoding="utf-8",
        ) as input_file:
            reader = csv.DictReader(input_file)

            if not reader.fieldnames:
                raise RuntimeError(
                    f"{path} has no header row"
                )

            return [
                {
                    str(key): str(value or "")
                    for key, value in row.items()
                }
                for row in reader
            ]
    except OSError as error:
        raise RuntimeError(
            f"Failed reading input CSV "
            f"{path}: {error}"
        ) from error


def criteria_from_args(
    args: argparse.Namespace,
) -> CollectionCriteria:
    return CollectionCriteria(
        score_field=args.score_field,
        score_operator=ScoreOperator(
            args.score_operator
        ),
        threshold=args.threshold,
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
        skip_policy_rules=(
            args.skip_policy_rules
        ),
        include_policy_rule_details=(
            args.include_policy_rule_details
        ),
    )


def validate_args(
    args: argparse.Namespace,
) -> None:
    args.scope = normalize_scope(
        args.scope
    )

    if args.workers < 1:
        raise RuntimeError(
            "--workers must be greater than zero"
        )

    if args.component_workers < 1:
        raise RuntimeError(
            "--component-workers must be "
            "greater than zero"
        )

    if args.page_limit < 1:
        raise RuntimeError(
            "--page-limit must be greater than zero"
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

    if args.api_cache_max_entries < 1:
        raise RuntimeError(
            "--api-cache-max-entries must be "
            "greater than zero"
        )

    if args.api_cache_max_age_hours < -1:
        raise RuntimeError(
            "--api-cache-max-age-hours must "
            "be -1 or greater"
        )

    if (
        args.scope
        in {
            CollectionScope.CANDIDATE_PROJECTS,
            CollectionScope.EXPLICIT_PROJECT_VERSIONS,
        }
        and not args.input
    ):
        raise RuntimeError(
            f"--input is required for "
            f"--scope {args.scope.value}"
        )

    criteria_from_args(args)


def run(
    args: argparse.Namespace,
) -> int:
    validate_args(args)
    rows = load_input_rows(args.input)
    api_cache: ApiResponseCache | None = None

    if not args.no_api_cache:
        api_cache = ApiResponseCache(
            path=args.api_cache,
            base_url=args.bd_url,
            max_age_hours=(
                args.api_cache_max_age_hours
            ),
            max_entries=(
                args.api_cache_max_entries
            ),
            refresh=args.refresh_api_cache,
            debug=args.debug,
        )

    client = BlackDuckClient(
        base_url=args.bd_url,
        api_token=args.api_token,
        insecure=args.insecure,
        ca_bundle=args.ca_bundle,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        page_limit=args.page_limit,
        debug=args.debug,
        api_cache=api_cache,
    )

    try:
        client.authenticate()
        execution = pull_scope(
            client,
            PullRequest(
                scope=args.scope,
                criteria=criteria_from_args(args),
                workers=args.workers,
                component_workers=(
                    args.component_workers
                ),
                resolve_bom_names=(
                    args.resolve_bom_names
                ),
            ),
            rows=rows,
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
            debug=args.debug,
        )
    finally:
        if api_cache is not None:
            api_cache.save()

    finding_payloads = [
        normalized_finding_payload(
            finding
        )
        for finding in execution.collection.findings
    ]
    collection_failures = [
        collection_failure_payload(failure)
        for failure
        in execution.collection.failures
    ]
    scope_failures = [
        scope_failure_payload(failure)
        for failure in execution.scope_failures
    ]
    payload = {
        "schema_version": 1,
        "generated_at": (
            execution.manifest.generated_at
        ),
        "scope": (
            execution.request.scope.value
        ),
        "criteria": {
            "score_field": args.score_field,
            "score_operator": (
                args.score_operator
            ),
            "threshold": args.threshold,
            "require_exploit_available": (
                args.require_exploit_available
            ),
            "require_reachable": (
                args.require_reachable
            ),
            "reachability_mode": (
                args.reachability_mode
            ),
            "policy_name": (
                args.policy_name or ""
            ),
            "policy_rule_id": (
                args.policy_rule_id or ""
            ),
        },
        "target_count": (
            execution.target_count
        ),
        "finding_count": (
            execution.finding_count
        ),
        "failure_count": (
            execution.failure_count
        ),
        "findings": finding_payloads,
        "collection_failures": (
            collection_failures
        ),
        "scope_failures": scope_failures,
    }

    atomic_write_json(args.out, payload)

    if args.manifest_out:
        atomic_write_json(
            args.manifest_out,
            execution.manifest.as_dict(),
        )

    if args.failures_out:
        atomic_write_json(
            args.failures_out,
            {
                "scope_failures": (
                    scope_failures
                ),
                "collection_failures": (
                    collection_failures
                ),
            },
        )

    print()
    print("Black Duck collection summary")
    print("=============================")
    print(
        f"Scope:              "
        f"{execution.request.scope.value}"
    )
    print(
        f"Targets:            "
        f"{execution.target_count}"
    )
    print(
        f"Findings:           "
        f"{execution.finding_count}"
    )
    print(
        f"Failures:           "
        f"{execution.failure_count}"
    )
    print(f"Output:             {args.out}")

    if args.manifest_out:
        print(
            f"Manifest:           "
            f"{args.manifest_out}"
        )

    return (
        1
        if execution.failure_count
        else 0
    )


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Collect normalized Black Duck "
            "vulnerability findings for any "
            "Wintermute destination."
        )
    )
    parser.add_argument(
        "--scope",
        default=(
            CollectionScope
            .ALL_PROJECT_VERSIONS
            .value
        ),
        help=(
            "Collection scope: parent-rollup, "
            "candidate-projects, "
            "all-project-versions, or "
            "explicit-project-versions."
        ),
    )
    parser.add_argument(
        "--input",
        help=(
            "Optional CSV or JSON scope input. "
            "Required for candidate and explicit "
            "project-version scopes."
        ),
    )
    parser.add_argument(
        "--out",
        default=blackduck_output_path(
            "normalized-findings.json"
        ),
    )
    parser.add_argument(
        "--manifest-out",
        default=blackduck_output_path(
            "collection-manifest.json"
        ),
    )
    parser.add_argument(
        "--failures-out",
        default=blackduck_output_path(
            "collection-failures.json"
        ),
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
    parser.add_argument(
        "--score-field",
        default="overallScore",
    )
    parser.add_argument(
        "--score-operator",
        choices=["gt", "gte"],
        default="gte",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=7.0,
    )
    parser.add_argument(
        "--require-exploit-available",
        action="store_true",
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
        "--skip-policy-rules",
        action="store_true",
    )
    parser.add_argument(
        "--include-policy-rule-details",
        action="store_true",
    )
    parser.add_argument(
        "--resolve-bom-names",
        action="store_true",
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
        "--component-workers",
        type=int,
        default=1,
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
    parser.add_argument(
        "--api-cache",
        default=blackduck_output_path(
            "cache",
            "blackduck-api-cache.json",
        ),
    )
    parser.add_argument(
        "--no-api-cache",
        action="store_true",
    )
    parser.add_argument(
        "--refresh-api-cache",
        action="store_true",
    )
    parser.add_argument(
        "--api-cache-max-age-hours",
        type=float,
        default=20.0,
    )
    parser.add_argument(
        "--api-cache-max-entries",
        type=int,
        default=5000,
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
        print(
            "Interrupted.",
            file=sys.stderr,
        )
        return 130
    except (
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
