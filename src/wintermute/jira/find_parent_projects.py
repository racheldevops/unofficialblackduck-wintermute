#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

from wintermute.blackduck.inventory import (
    InventoryFilter,
    build_project_version_inventory,
    get_project_versions as shared_get_project_versions,
)
from wintermute.blackduck.lineage import (
    discover_lineage_contexts as shared_discover_lineage_contexts,
    extract_project_version_hrefs as shared_extract_project_version_hrefs,
    get_bom_components as shared_get_bom_components,
    lineage_context_to_row,
    project_href_from_version_href as shared_project_href_from_version_href,
    resolve_project_version,
)
from wintermute.blackduck.models import ProjectVersionRef
from wintermute.blackduck import discovery_cache as shared_discovery_cache
from wintermute.blackduck.client import BlackDuckClient as SharedBlackDuckClient
from wintermute.concurrency import (
    MAX_IO_WORKERS,
    bounded_worker_count,
    ordered_parallel_map,
)
from wintermute.paths import ensure_parent_dir, jira_output_path


PROJECT_VERSION_RE = re.compile(
    r"/api/projects/[0-9a-fA-F-]+/versions/[0-9a-fA-F-]+"
)

CACHE_SCHEMA_VERSION = 2

RELATION_FIELDNAMES = [
    "parent_project",
    "parent_version",
    "parent_phase",
    "parent_updated",
    "child_project",
    "child_version",
    "child_phase",
    "detection_method",
    "bom_component_name",
    "bom_component_version",
    "parent_version_href",
    "child_version_href",
    "cache_entry_status",
    "cache_reuse_reason",
    "parent_scanned_at",
    "parent_scan_error",
]


@dataclass(frozen=True)
class VersionInfo:
    project_name: str
    version_name: str
    project_href: str
    version_href: str
    phase: str = ""
    updated: str = ""
    created: str = ""

    def signature(self) -> str:
        payload = {
            "project_name": self.project_name,
            "version_name": self.version_name,
            "project_href": self.project_href,
            "version_href": self.version_href,
            "phase": self.phase,
            "updated": self.updated,
            "created": self.created,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class BlackDuckClient(SharedBlackDuckClient):
    cache_raw_gets = False
    cache_paged_results = False


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def canonical_href(href: str) -> str:
    parsed = urlparse(href)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))


def get_self_href(resource: dict[str, Any]) -> str | None:
    return resource.get("_meta", {}).get("href")


def get_link(resource: dict[str, Any], rel_names: tuple[str, ...]) -> str | None:
    wanted = {rel.lower() for rel in rel_names}

    for link in resource.get("_meta", {}).get("links", []):
        rel = str(link.get("rel", "")).lower()
        href = link.get("href")
        if rel in wanted and href:
            return href

    for link in resource.get("_meta", {}).get("links", []):
        rel = str(link.get("rel", "")).lower()
        href = link.get("href")
        if href and any(wanted_rel in rel for wanted_rel in wanted):
            return href

    return None


def iter_hrefs(value: Any) -> list[str]:
    hrefs: list[str] = []

    if isinstance(value, dict):
        for key, item in value.items():
            if key == "href" and isinstance(item, str):
                hrefs.append(item)
            else:
                hrefs.extend(iter_hrefs(item))
    elif isinstance(value, list):
        for item in value:
            hrefs.extend(iter_hrefs(item))

    return hrefs


def extract_project_version_hrefs(
        raw_href: str,
        base_url: str,
) -> list[str]:
    return shared_extract_project_version_hrefs(
        raw_href,
        base_url,
    )


def project_href_from_version_href(
        version_href: str,
) -> str | None:
    return (
        shared_project_href_from_version_href(
            version_href
        )
        or None
    )


def version_name(version: dict[str, Any]) -> str:
    return str(version.get("versionName") or version.get("name") or "")


def first_value_by_key(value: Any, keys: list[str]) -> Any:
    wanted = {key.lower() for key in keys}

    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in wanted and item not in (None, ""):
                return item

        for item in value.values():
            found = first_value_by_key(item, keys)
            if found not in (None, ""):
                return found

    elif isinstance(value, list):
        for item in value:
            found = first_value_by_key(item, keys)
            if found not in (None, ""):
                return found

    return None


def extract_updated_timestamp(version: dict[str, Any]) -> str:
    value = first_value_by_key(
        version,
        [
            "updatedAt",
            "updatedDate",
            "lastUpdated",
            "lastUpdatedDate",
            "modifiedAt",
            "modifiedDate",
            "updated",
        ],
    )
    return str(value or "")


def extract_created_timestamp(version: dict[str, Any]) -> str:
    value = first_value_by_key(
        version,
        [
            "createdAt",
            "createdDate",
            "created",
        ],
    )
    return str(value or "")


def get_project_versions(
        client: BlackDuckClient,
        project: dict[str, Any],
) -> list[dict[str, Any]]:
    return shared_get_project_versions(
        client,
        project,
    )


def build_version_inventory(
        client: BlackDuckClient,
        project_name_contains: str | None,
        max_projects: int | None,
        debug: bool,
        workers: int = 1,
) -> list[VersionInfo]:
    result = build_project_version_inventory(
        client,
        filters=InventoryFilter(
            project_name_contains=(
                project_name_contains or ""
            ),
            max_projects=max_projects,
        ),
        workers=workers,
        debug=debug,
    )

    for failure in result.failures:
        print(
            f"Warning: failed to read versions for project "
            f"{failure.project}: {failure.error}",
            file=sys.stderr,
        )

    return [
        VersionInfo(
            project_name=item.project_version.project,
            version_name=item.project_version.version,
            project_href=item.project_version.project_href,
            version_href=item.project_version.version_href,
            phase=item.project_version.phase,
            updated=item.project_version.updated,
            created=item.created,
        )
        for item in result.items
    ]


def build_indexes(
        inventory: list[VersionInfo],
) -> tuple[dict[str, VersionInfo], dict[tuple[str, str], list[VersionInfo]]]:
    by_href: dict[str, VersionInfo] = {}
    by_name: dict[tuple[str, str], list[VersionInfo]] = {}

    for info in inventory:
        by_href[info.version_href] = info
        by_name.setdefault((info.project_name, info.version_name), []).append(info)

    return by_href, by_name


def resolve_version_href(
        client: BlackDuckClient,
        version_href: str,
        versions_by_href: dict[str, VersionInfo],
) -> VersionInfo | None:
    version_href = canonical_href(version_href)
    existing = versions_by_href.get(version_href)

    if existing is not None:
        return existing

    shared_by_href = {
        href: ProjectVersionRef(
            instance_url=client.base_url,
            project=value.project_name,
            version=value.version_name,
            project_href=value.project_href,
            version_href=value.version_href,
            phase=value.phase,
            updated=value.updated,
        )
        for href, value in versions_by_href.items()
    }
    resolved = resolve_project_version(
        client,
        version_href,
        shared_by_href,
    )

    if resolved is None:
        return None

    return VersionInfo(
        project_name=resolved.project,
        version_name=resolved.version,
        project_href=resolved.project_href,
        version_href=resolved.version_href,
        phase=resolved.phase,
        updated=resolved.updated,
    )


def get_bom_components(
        client: BlackDuckClient,
        version_info: VersionInfo,
) -> list[dict[str, Any]]:
    return shared_get_bom_components(
        client,
        ProjectVersionRef(
            instance_url=client.base_url,
            project=version_info.project_name,
            version=version_info.version_name,
            project_href=version_info.project_href,
            version_href=version_info.version_href,
            phase=version_info.phase,
            updated=version_info.updated,
        ),
    )


def discover_subprojects_for_version(
        client: BlackDuckClient,
        parent: VersionInfo,
        versions_by_href: dict[str, VersionInfo],
        versions_by_name: dict[
            tuple[str, str],
            list[VersionInfo],
        ],
        resolve_bom_names: bool,
        debug: bool,
) -> list[dict[str, str]]:
    parent_ref = ProjectVersionRef(
        instance_url=client.base_url,
        project=parent.project_name,
        version=parent.version_name,
        project_href=parent.project_href,
        version_href=parent.version_href,
        phase=parent.phase,
        updated=parent.updated,
    )
    shared_by_href = {
        href: ProjectVersionRef(
            instance_url=client.base_url,
            project=value.project_name,
            version=value.version_name,
            project_href=value.project_href,
            version_href=value.version_href,
            phase=value.phase,
            updated=value.updated,
        )
        for href, value in versions_by_href.items()
    }
    shared_by_name = {
        key: [
            ProjectVersionRef(
                instance_url=client.base_url,
                project=value.project_name,
                version=value.version_name,
                project_href=value.project_href,
                version_href=value.version_href,
                phase=value.phase,
                updated=value.updated,
            )
            for value in values
        ]
        for key, values in versions_by_name.items()
    }

    contexts = shared_discover_lineage_contexts(
        client,
        parent_ref,
        shared_by_href,
        shared_by_name,
        resolve_bom_names=resolve_bom_names,
        debug=debug,
        bom_loader=lambda current_client, _: (
            get_bom_components(
                current_client,
                parent,
            )
        ),
    )

    return [
        lineage_context_to_row(context)
        for context in contexts
    ]


def relation_identity(relation: dict[str, str]) -> tuple[str, str]:
    return (
        relation.get("parent_version_href", ""),
        relation.get("child_version_href", ""),
    )


def dedupe_relations(relations: list[dict[str, str]]) -> list[dict[str, str]]:
    unique: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for relation in relations:
        key = relation_identity(relation)

        if key in seen:
            continue

        seen.add(key)
        unique.append(relation)

    return unique


def new_cache(
    base_url: str,
    resolve_bom_names: bool,
) -> dict[str, Any]:
    return shared_discovery_cache.new_cache(
        base_url,
        resolve_bom_names,
    )


def load_cache(
    path: str,
    base_url: str,
    resolve_bom_names: bool,
) -> dict[str, Any]:
    return shared_discovery_cache.load_cache(
        path,
        base_url,
        resolve_bom_names,
    )


def save_cache(
    path: str,
    cache: dict[str, Any],
) -> None:
    shared_discovery_cache.save_cache(
        path,
        cache,
    )

def cache_entry_for_version(
    cache: dict[str, Any],
    version_info: VersionInfo,
) -> dict[str, Any] | None:
    return (
        shared_discovery_cache
        .cache_entry_for_version(
            cache,
            version_info,
        )
    )


def cache_age_days(
    entry: dict[str, Any],
) -> float | None:
    return (
        shared_discovery_cache
        .cache_age_days(entry)
    )


def scan_reason_for_version(
    version_info: VersionInfo,
    entry: dict[str, Any] | None,
    refresh_all: bool,
    refresh_failed: bool,
    refresh_older_than_days: float,
    trust_cache_without_update_marker: bool,
) -> str | None:
    return (
        shared_discovery_cache
        .scan_reason_for_version(
            version_info,
            entry,
            refresh_all,
            refresh_failed,
            refresh_older_than_days,
            trust_cache_without_update_marker,
        )
    )


def relation_with_cache_metadata(
    relation: dict[str, str],
    entry: dict[str, Any],
) -> dict[str, str]:
    return (
        shared_discovery_cache
        .relation_with_cache_metadata(
            relation,
            entry,
        )
    )


def collect_relations_from_cache(
    cache: dict[str, Any],
    inventory: list[VersionInfo],
) -> list[dict[str, str]]:
    return (
        shared_discovery_cache
        .collect_relations_from_cache(
            cache,
            inventory,
        )
    )


def plan_scan(
    cache: dict[str, Any],
    inventory: list[VersionInfo],
    refresh_all: bool,
    refresh_failed: bool,
    refresh_older_than_days: float,
    trust_cache_without_update_marker: bool,
) -> tuple[
    list[tuple[VersionInfo, str]],
    int,
]:
    return shared_discovery_cache.plan_scan(
        cache,
        inventory,
        refresh_all,
        refresh_failed,
        refresh_older_than_days,
        trust_cache_without_update_marker,
    )


def scan_one_parent(
        client: BlackDuckClient,
        parent: VersionInfo,
        reason: str,
        versions_by_href: dict[str, VersionInfo],
        versions_by_name: dict[tuple[str, str], list[VersionInfo]],
        resolve_bom_names: bool,
        debug: bool,
) -> tuple[VersionInfo, str, list[dict[str, str]], str | None]:
    try:
        relations = discover_subprojects_for_version(
            client=client,
            parent=parent,
            versions_by_href=versions_by_href,
            versions_by_name=versions_by_name,
            resolve_bom_names=resolve_bom_names,
            debug=debug,
        )
        return parent, reason, relations, None
    except RuntimeError as error:
        return parent, reason, [], str(error)


def scan_versions(
        client: BlackDuckClient,
        scan_plan: list[tuple[VersionInfo, str]],
        versions_by_href: dict[str, VersionInfo],
        versions_by_name: dict[tuple[str, str], list[VersionInfo]],
        resolve_bom_names: bool,
        workers: int,
        debug: bool,
) -> list[
    tuple[
        VersionInfo,
        str,
        list[dict[str, str]],
        str | None,
    ]
]:
    if not scan_plan:
        return []

    worker_count = min(
        bounded_worker_count(
            workers,
            maximum=MAX_IO_WORKERS,
        ),
        len(scan_plan),
    )

    if worker_count == 1:
        results = []

        for index, (parent, reason) in enumerate(
            scan_plan,
            start=1,
        ):
            if debug:
                print(
                    f"[{index}/{len(scan_plan)}] Scanning "
                    f"{parent.project_name} / "
                    f"{parent.version_name} ({reason})",
                    file=sys.stderr,
                )

            results.append(
                scan_one_parent(
                    client=client,
                    parent=parent,
                    reason=reason,
                    versions_by_href=versions_by_href,
                    versions_by_name=versions_by_name,
                    resolve_bom_names=resolve_bom_names,
                    debug=debug,
                )
            )

        return results

    print(
        f"Scanning {len(scan_plan)} project version(s) "
        f"with {worker_count} worker(s).",
        file=sys.stderr,
    )

    worker_local = threading.local()

    def worker_client() -> BlackDuckClient:
        local_client = getattr(
            worker_local,
            "blackduck_client",
            None,
        )

        if local_client is None:
            local_client = client.clone_for_worker()
            worker_local.blackduck_client = local_client

        return local_client

    ordered_results: list[
        tuple[
            VersionInfo,
            str,
            list[dict[str, str]],
            str | None,
        ]
        | None
    ] = [None] * len(scan_plan)

    with ThreadPoolExecutor(
        max_workers=worker_count
    ) as executor:
        futures = {
            executor.submit(
                scan_one_parent,
                worker_client(),
                parent,
                reason,
                versions_by_href,
                versions_by_name,
                resolve_bom_names,
                debug,
            ): (index, parent, reason)
            for index, (parent, reason)
            in enumerate(scan_plan)
        }

        for completed, future in enumerate(
            as_completed(futures),
            start=1,
        ):
            index, parent, reason = futures[future]
            ordered_results[index] = future.result()

            if debug:
                print(
                    f"[{completed}/{len(scan_plan)}] Completed "
                    f"{parent.project_name} / "
                    f"{parent.version_name} ({reason})",
                    file=sys.stderr,
                )

    return [
        result
        for result in ordered_results
        if result is not None
    ]


def update_cache_with_scan_results(
    cache: dict[str, Any],
    results: list[
        tuple[
            VersionInfo,
            str,
            list[dict[str, str]],
            str | None,
        ]
    ],
) -> None:
    shared_discovery_cache.update_cache_with_scan_results(
        cache,
        results,
    )


def prune_cache_to_current_inventory(
    cache: dict[str, Any],
    inventory: list[VersionInfo],
) -> int:
    return (
        shared_discovery_cache
        .prune_cache_to_current_inventory(
            cache,
            inventory,
        )
    )


def write_csv(relations: list[dict[str, str]], output_path: str) -> None:
    ensure_parent_dir(output_path)

    if output_path == "-":
        output_file = sys.stdout
        close_after = False
    else:
        output_file = open(output_path, "w", newline="", encoding="utf-8")
        close_after = True

    try:
        writer = csv.DictWriter(
            output_file,
            fieldnames=RELATION_FIELDNAMES,
        )
        writer.writeheader()

        for relation in relations:
            row = {
                field: relation.get(field, "")
                for field in RELATION_FIELDNAMES
            }
            writer.writerow(row)
    finally:
        if close_after:
            output_file.close()

def write_changes_csv(
        old_relations: list[dict[str, str]],
        new_relations: list[dict[str, str]],
        output_path: str,
) -> None:
    ensure_parent_dir(output_path)

    old_by_key = {
        relation_identity(relation): relation
        for relation in old_relations
    }
    new_by_key = {
        relation_identity(relation): relation
        for relation in new_relations
    }

    old_keys = set(old_by_key)
    new_keys = set(new_by_key)
    rows: list[dict[str, str]] = []

    for key in sorted(new_keys - old_keys):
        row = dict(new_by_key[key])
        row["change_type"] = "added"
        rows.append(row)

    for key in sorted(old_keys - new_keys):
        row = dict(old_by_key[key])
        row["change_type"] = "removed"
        rows.append(row)

    fieldnames = ["change_type"] + RELATION_FIELDNAMES

    with open(output_path, "w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()

        for row in rows:
            writer.writerow(
                {
                    field: row.get(field, "")
                    for field in fieldnames
                }
            )

    print(
        f"Wrote relationship changes: {output_path} "
        f"({len(rows)} added/removed row(s))",
        file=sys.stderr,
    )

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Find Black Duck project versions whose BOM appears to contain "
            "other Black Duck project versions."
        )
    )

    parser.add_argument(
        "--bd-url",
        default=os.getenv("BLACKDUCK_URL"),
        required=os.getenv("BLACKDUCK_URL") is None,
        help="Black Duck base URL, or BLACKDUCK_URL env var.",
    )
    parser.add_argument(
        "--api-token",
        default=os.getenv("BLACKDUCK_API_TOKEN"),
        required=os.getenv("BLACKDUCK_API_TOKEN") is None,
        help="Black Duck API token, or BLACKDUCK_API_TOKEN env var.",
    )
    parser.add_argument(
        "--resolve-bom-names",
        action="store_true",
        help=(
            "Also treat BOM rows as possible project/version references when "
            "componentName/componentVersionName exactly match a Black Duck "
            "project/version."
        ),
    )
    parser.add_argument(
        "--project-name-contains",
        help="Only scan projects whose names contain this text.",
    )
    parser.add_argument(
        "--max-projects",
        type=int,
        help="Optional safety limit for testing.",
    )
    parser.add_argument(
        "--out",
        default=jira_output_path("parent_projects.csv"),
        help="Relationship CSV output path.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Write JSON instead of CSV.",
    )
    parser.add_argument(
        "--changes-out",
        default=jira_output_path("parent_project_changes.csv"),
        help="CSV path for added and removed relationship changes.",
    )
    parser.add_argument(
        "--cache",
        default=jira_output_path(
            "cache",
            "parent_projects_cache.json",
        ),
        help="Incremental project relationship cache path.",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable cache and scan all selected project versions.",
    )
    parser.add_argument(
        "--refresh-all",
        action="store_true",
        help="Ignore cached scan results and rescan all selected versions.",
    )
    parser.add_argument(
        "--refresh-older-than-days",
        type=float,
        default=7.0,
        help=(
            "Rescan cached entries older than this many days. "
            "Use -1 to disable age-based refresh."
        ),
    )
    parser.add_argument(
        "--no-refresh-failed",
        action="store_true",
        help="Do not automatically retry previously failed versions.",
    )
    parser.add_argument(
        "--trust-cache-without-update-marker",
        action="store_true",
        help=(
            "Reuse cached entries when Black Duck provides no updated "
            "timestamp."
        ),
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate validation.",
    )
    parser.add_argument(
        "--ca-bundle",
        help="PEM CA bundle used to validate the Black Duck certificate.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="HTTP timeout seconds.",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Retry count for transient failures.",
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=2.0,
        help="Base retry delay seconds.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Concurrent project-version BOM checks. Use 1-8.",
    )
    parser.add_argument(
        "--page-limit",
        type=int,
        default=500,
        help="Black Duck API page size. Default: 500.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print progress and debugging information.",
    )

    return parser.parse_args()

def main() -> int:
    args = parse_args()

    if args.page_limit <= 0:
        print("ERROR: --page-limit must be greater than zero", file=sys.stderr)
        return 2

    if args.workers <= 0:
        print("ERROR: --workers must be greater than zero", file=sys.stderr)
        return 2

    if args.workers > MAX_IO_WORKERS:
        print(
            f"Warning: --workers {args.workers} exceeds maximum "
            f"{MAX_IO_WORKERS}; clamping.",
            file=sys.stderr,
        )

    args.workers = bounded_worker_count(
        args.workers,
        maximum=MAX_IO_WORKERS,
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
    )
    client.authenticate()

    if args.debug:
        print("Building project/version inventory...", file=sys.stderr)

    inventory = build_version_inventory(
        client=client,
        project_name_contains=args.project_name_contains,
        max_projects=args.max_projects,
        debug=args.debug,
        workers=args.workers,
    )

    versions_by_href, versions_by_name = build_indexes(inventory)

    print(
        f"Indexed {len(inventory)} project versions.",
        file=sys.stderr,
    )

    if args.no_cache:
        cache = new_cache(args.bd_url, args.resolve_bom_names)
        old_relations: list[dict[str, str]] = []
        scan_plan = [
            (version_info, "no-cache")
            for version_info in inventory
        ]
        reused_count = 0
    else:
        cache = load_cache(
            path=args.cache,
            base_url=args.bd_url,
            resolve_bom_names=args.resolve_bom_names,
        )

        old_relations = collect_relations_from_cache(cache, inventory)

        pruned_count = prune_cache_to_current_inventory(
            cache,
            inventory,
        )

        if pruned_count:
            print(
                f"Pruned {pruned_count} cache entrie(s) for project "
                f"versions not present in the current inventory.",
                file=sys.stderr,
            )

        scan_plan, reused_count = plan_scan(
            cache=cache,
            inventory=inventory,
            refresh_all=args.refresh_all,
            refresh_failed=not args.no_refresh_failed,
            refresh_older_than_days=args.refresh_older_than_days,
            trust_cache_without_update_marker=(
                args.trust_cache_without_update_marker
            ),
        )

    print(
        f"Reusing {reused_count} cached project version scan(s); "
        f"scanning {len(scan_plan)} project version(s).",
        file=sys.stderr,
    )

    scan_results = scan_versions(
        client=client,
        scan_plan=scan_plan,
        versions_by_href=versions_by_href,
        versions_by_name=versions_by_name,
        resolve_bom_names=args.resolve_bom_names,
        workers=args.workers,
        debug=args.debug,
    )

    update_cache_with_scan_results(cache, scan_results)

    relations = collect_relations_from_cache(cache, inventory)
    relations = dedupe_relations(relations)

    parent_count = len(
        {
            (
                relation["parent_project"],
                relation["parent_version"],
            )
            for relation in relations
        }
    )

    if args.json:
        if args.out == "-":
            json.dump(relations, sys.stdout, indent=2)
            print()
        else:
            ensure_parent_dir(args.out)
            with open(args.out, "w", encoding="utf-8") as output_file:
                json.dump(relations, output_file, indent=2)
    else:
        write_csv(relations, args.out)

    if args.changes_out:
        write_changes_csv(
            old_relations=old_relations,
            new_relations=relations,
            output_path=args.changes_out,
        )

    if not args.no_cache:
        save_cache(args.cache, cache)

    print(
        f"Found {parent_count} parent project versions with "
        f"{len(relations)} subproject relationship(s).",
        file=sys.stderr,
    )

    if not relations and not args.resolve_bom_names:
        print(
            "No API-href relationships found. "
            "Try again with --resolve-bom-names.",
            file=sys.stderr,
        )

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
