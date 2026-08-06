from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from wintermute.blackduck.cache import ApiResponseCache
from wintermute.blackduck.cli import load_input_rows
from wintermute.blackduck.client import BlackDuckClient
from wintermute.blackduck.cohort import (
    create_cohort_id,
    prune_cohorts,
    write_cohort,
)
from wintermute.blackduck.custom_fields import (
    ProjectCustomFieldResolver,
)
from wintermute.blackduck.filtering import (
    broad_collection_criteria,
)
from wintermute.blackduck.inventory import InventoryFilter
from wintermute.blackduck.pull import (
    PullRequest,
    pull_scope,
)
from wintermute.blackduck.scopes import (
    CollectionScope,
    normalize_scope,
)
from wintermute.paths import ensure_parent_dir, output_root


def default_cohort_root() -> str:
    return str(output_root() / "cohorts")


def default_cache_path() -> str:
    return str(
        output_root()
        / "blackduck"
        / "cache"
        / "cohort-source-api-cache.json"
    )


def default_summary_path() -> str:
    return str(
        output_root()
        / "blackduck"
        / "cohort-source-summary.json"
    )


def atomic_write_json(
    path: str,
    payload: Any,
) -> None:
    ensure_parent_dir(path)
    temporary = f"{path}.tmp"

    with open(
        temporary,
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

    os.replace(temporary, path)


def validate_args(args: argparse.Namespace) -> None:
    args.scope = normalize_scope(args.scope)

    for name in (
        "workers",
        "component_workers",
        "page_limit",
        "timeout",
        "api_cache_max_entries",
    ):
        if int(getattr(args, name)) < 1:
            raise RuntimeError(
                f"--{name.replace('_', '-')} must be "
                "greater than zero"
            )

    if args.retain_cohorts < 1:
        raise RuntimeError(
            "--retain-cohorts must be greater than zero"
        )

    if args.retries < 0:
        raise RuntimeError(
            "--retries cannot be negative"
        )

    if args.retry_delay < 0:
        raise RuntimeError(
            "--retry-delay cannot be negative"
        )

    if args.api_cache_max_age_hours < -1:
        raise RuntimeError(
            "--api-cache-max-age-hours must be "
            "-1 or greater"
        )

    if args.scope in {
        CollectionScope.CANDIDATE_PROJECTS,
        CollectionScope.EXPLICIT_PROJECT_VERSIONS,
    } and not args.input:
        raise RuntimeError(
            f"--input is required for "
            f"--scope {args.scope.value}"
        )


def run(args: argparse.Namespace) -> int:
    validate_args(args)
    rows = load_input_rows(args.input)
    cohort_id = args.cohort_id or create_cohort_id()
    api_cache: ApiResponseCache | None = None

    if not args.no_api_cache:
        api_cache = ApiResponseCache(
            path=args.api_cache,
            base_url=args.bd_url,
            max_age_hours=args.api_cache_max_age_hours,
            max_entries=args.api_cache_max_entries,
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
    entity_resolver = (
        ProjectCustomFieldResolver(
            args.entity_custom_field
        )
        if args.entity_custom_field
        else None
    )

    try:
        client.authenticate()
        execution = pull_scope(
            client,
            PullRequest(
                scope=args.scope,
                criteria=broad_collection_criteria(
                    score_field=args.score_field,
                    minimum_score=args.minimum_score,
                    include_policy_rule_details=(
                        args.include_policy_rule_details
                    ),
                    entity_custom_field=(
                        args.entity_custom_field
                    ),
                    require_entity=args.require_entity,
                ),
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
                project_name=args.project_name or "",
                project_name_contains=(
                    args.project_name_contains or ""
                ),
                version_name=args.version_name or "",
                phase=args.phase or "",
                max_projects=args.max_projects,
                max_versions=args.max_versions,
            ),
            entity_resolver=entity_resolver,
            debug=args.debug,
        )
    finally:
        if api_cache is not None:
            api_cache.save()

    summary = {
        "cohort_id": cohort_id,
        "scope": execution.request.scope.value,
        "target_count": execution.target_count,
        "finding_count": execution.finding_count,
        "failure_count": execution.failure_count,
        "strict": args.strict,
        "cohort_directory": "",
        "status": "failed",
    }

    if execution.failure_count and args.strict:
        summary["status"] = "rejected"
        atomic_write_json(
            args.summary_out,
            summary,
        )
        print(
            f"ERROR: strict cohort source rejected "
            f"{execution.failure_count} failure(s)",
            file=sys.stderr,
        )
        return 1

    cohort_directory = write_cohort(
        args.cohort_root,
        execution,
        cohort_id=cohort_id,
    )
    summary["cohort_directory"] = str(
        cohort_directory
    )
    pruned_cohorts = prune_cohorts(
        args.cohort_root,
        retain_count=args.retain_cohorts,
        protected_ids={cohort_id},
    )
    summary["pruned_cohorts"] = list(
        pruned_cohorts
    )
    summary["status"] = (
        "partial"
        if execution.failure_count
        else "succeeded"
    )
    atomic_write_json(
        args.summary_out,
        summary,
    )

    if args.cohort_id_out:
        ensure_parent_dir(args.cohort_id_out)
        Path(args.cohort_id_out).write_text(
            cohort_id + "\n",
            encoding="utf-8",
        )

    print()
    print("Cohort source summary")
    print("=====================")
    print(f"Cohort ID:       {cohort_id}")
    print(
        f"Scope:           "
        f"{execution.request.scope.value}"
    )
    print(
        f"Targets:         "
        f"{execution.target_count}"
    )
    print(
        f"Findings:        "
        f"{execution.finding_count}"
    )
    print(
        f"Failures:        "
        f"{execution.failure_count}"
    )
    print(f"Directory:       {cohort_directory}")

    return 0


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create an immutable Wintermute Black Duck "
            "cohort snapshot."
        )
    )
    parser.add_argument(
        "--scope",
        default=CollectionScope.PARENT_ROLLUP.value,
    )
    parser.add_argument("--input")
    parser.add_argument(
        "--cohort-root",
        default=default_cohort_root(),
    )
    parser.add_argument("--cohort-id")
    parser.add_argument(
        "--retain-cohorts",
        type=int,
        default=10,
    )
    parser.add_argument("--cohort-id-out")
    parser.add_argument(
        "--summary-out",
        default=default_summary_path(),
    )
    parser.add_argument(
        "--bd-url",
        default=os.getenv("BLACKDUCK_URL"),
        required=os.getenv("BLACKDUCK_URL") is None,
    )
    parser.add_argument(
        "--api-token",
        default=os.getenv("BLACKDUCK_API_TOKEN"),
        required=(
            os.getenv("BLACKDUCK_API_TOKEN")
            is None
        ),
    )
    parser.add_argument(
        "--score-field",
        default="overallScore",
    )
    parser.add_argument(
        "--minimum-score",
        type=float,
        default=0.0,
    )
    parser.set_defaults(
        include_policy_rule_details=True,
        resolve_bom_names=True,
        strict=True,
    )
    parser.add_argument(
        "--include-policy-rule-details",
        dest="include_policy_rule_details",
        action="store_true",
    )
    parser.add_argument(
        "--skip-policy-rule-details",
        dest="include_policy_rule_details",
        action="store_false",
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
        "--resolve-bom-names",
        dest="resolve_bom_names",
        action="store_true",
    )
    parser.add_argument(
        "--no-resolve-bom-names",
        dest="resolve_bom_names",
        action="store_false",
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
    parser.add_argument("--project-name")
    parser.add_argument("--project-name-contains")
    parser.add_argument("--version-name")
    parser.add_argument("--phase")
    parser.add_argument("--max-projects", type=int)
    parser.add_argument("--max-versions", type=int)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument(
        "--component-workers",
        type=int,
        default=2,
    )
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--retries", type=int, default=1)
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
        default=default_cache_path(),
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
