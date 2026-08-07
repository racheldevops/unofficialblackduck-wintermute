from __future__ import annotations

import json
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wintermute.blackduck import discovery_cache
from wintermute.blackduck.inventory import (
    InventoryFilter,
    InventoryResult,
    build_project_version_inventory,
)
from wintermute.blackduck.lineage import (
    build_project_version_indexes,
    discover_lineage_contexts,
    lineage_context_to_row,
)
from wintermute.blackduck.models import (
    LineageContext,
    ProjectVersionRef,
)
from wintermute.blackduck.scopes import (
    targets_from_parent_relationships,
)
from wintermute.concurrency import (
    MAX_IO_WORKERS,
    bounded_worker_count,
    ordered_parallel_map,
)


@dataclass(frozen=True)
class LineageDiscoveryFailure:
    project: str
    project_version: str
    project_version_href: str
    stage: str
    error: str
    elapsed_seconds: float = 0.0


@dataclass(frozen=True)
class ParentScanResult:
    contexts: tuple[LineageContext, ...]
    failure: LineageDiscoveryFailure | None
    elapsed_seconds: float


@dataclass(frozen=True)
class DiscoveryVersion:
    project_version: ProjectVersionRef
    created: str = ""

    @property
    def project_name(self) -> str:
        return self.project_version.project

    @property
    def version_name(self) -> str:
        return self.project_version.version

    @property
    def project_href(self) -> str:
        return self.project_version.project_href

    @property
    def version_href(self) -> str:
        return self.project_version.version_href

    @property
    def phase(self) -> str:
        return self.project_version.phase

    @property
    def updated(self) -> str:
        return self.project_version.updated

    def signature(self) -> str:
        return json.dumps(
            {
                "project_name": self.project_name,
                "version_name": self.version_name,
                "project_href": self.project_href,
                "version_href": self.version_href,
                "phase": self.phase,
                "updated": self.updated,
                "created": self.created,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


@dataclass(frozen=True)
class LineageDiscoveryResult:
    contexts: tuple[LineageContext, ...]
    failures: tuple[LineageDiscoveryFailure, ...]
    inventory: InventoryResult
    reused_count: int = 0
    scanned_count: int = 0
    pruned_count: int = 0
    cache_path: str = ""

    @property
    def relationship_count(self) -> int:
        return len(self.contexts)

    @property
    def parent_project_version_count(self) -> int:
        return len(
            {
                context.parent.identity_key
                for context in self.contexts
            }
        )

    @property
    def relationship_rows(
        self,
    ) -> tuple[dict[str, str], ...]:
        return tuple(
            lineage_context_to_row(context)
            for context in self.contexts
        )


def contexts_from_rows(
    rows: list[dict[str, Any]],
    *,
    instance_url: str,
) -> tuple[LineageContext, ...]:
    targets = targets_from_parent_relationships(
        rows,
        instance_url=instance_url,
    )
    contexts = {
        context.external_id: context
        for target in targets
        for context in target.lineage_contexts
    }

    return tuple(
        sorted(
            contexts.values(),
            key=lambda context: (
                context.parent.identity_key,
                context.child.identity_key,
                context.detection_method,
            ),
        )
    )


def discover_parent_relationships(
    client: Any,
    *,
    inventory_filter: InventoryFilter | None = None,
    workers: int = 4,
    resolve_bom_names: bool = False,
    debug: bool = False,
    cache_path: str | Path | None = None,
    refresh_all: bool = False,
    refresh_failed: bool = True,
    refresh_older_than_days: float = 7.0,
    trust_cache_without_update_marker: bool = False,
) -> LineageDiscoveryResult:
    inventory = build_project_version_inventory(
        client,
        filters=inventory_filter or InventoryFilter(),
        workers=workers,
        debug=debug,
    )
    project_versions = [
        item.project_version
        for item in inventory.items
    ]
    cache_versions = [
        DiscoveryVersion(
            project_version=item.project_version,
            created=item.created,
        )
        for item in inventory.items
    ]
    versions_by_href, versions_by_name = (
        build_project_version_indexes(
            project_versions
        )
    )
    failures = [
        LineageDiscoveryFailure(
            project=failure.project,
            project_version="",
            project_version_href="",
            stage=failure.stage,
            error=failure.error,
        )
        for failure in inventory.failures
    ]
    normalized_cache_path = (
        str(Path(cache_path))
        if cache_path
        else ""
    )
    cache: dict[str, Any] | None = None
    reused_count = 0
    pruned_count = 0

    if normalized_cache_path:
        cache = discovery_cache.load_cache(
            normalized_cache_path,
            str(getattr(client, "base_url", "")),
            resolve_bom_names,
        )
        pruned_count = (
            discovery_cache
            .prune_cache_to_current_inventory(
                cache,
                cache_versions,
            )
        )
        scan_plan, reused_count = (
            discovery_cache.plan_scan(
                cache,
                cache_versions,
                refresh_all=refresh_all,
                refresh_failed=refresh_failed,
                refresh_older_than_days=(
                    refresh_older_than_days
                ),
                trust_cache_without_update_marker=(
                    trust_cache_without_update_marker
                ),
            )
        )
    else:
        scan_plan = [
            (version, "no-cache")
            for version in cache_versions
        ]

    print(
        f"Parent lineage cache: reusing "
        f"{reused_count} project version(s); "
        f"scanning {len(scan_plan)}.",
        file=sys.stderr,
    )

    if not scan_plan:
        rows = (
            discovery_cache.collect_relations_from_cache(
                cache or {},
                cache_versions,
            )
        )

        return LineageDiscoveryResult(
            contexts=contexts_from_rows(
                rows,
                instance_url=str(
                    getattr(client, "base_url", "")
                ),
            ),
            failures=tuple(failures),
            inventory=inventory,
            reused_count=reused_count,
            scanned_count=0,
            pruned_count=pruned_count,
            cache_path=normalized_cache_path,
        )

    worker_count = min(
        bounded_worker_count(
            workers,
            maximum=MAX_IO_WORKERS,
        ),
        len(scan_plan),
    )
    worker_local = threading.local()

    def worker_client() -> Any:
        if worker_count == 1:
            return client

        local_client = getattr(
            worker_local,
            "blackduck_client",
            None,
        )

        if local_client is None:
            local_client = client.clone_for_worker()
            worker_local.blackduck_client = local_client

        return local_client

    def scan_parent(
        item: tuple[DiscoveryVersion, str],
    ) -> ParentScanResult:
        version, _ = item
        parent = version.project_version
        started = time.monotonic()

        try:
            contexts = discover_lineage_contexts(
                worker_client(),
                parent,
                versions_by_href,
                versions_by_name,
                resolve_bom_names=resolve_bom_names,
                debug=debug,
            )

            return ParentScanResult(
                contexts=tuple(contexts),
                failure=None,
                elapsed_seconds=(
                    time.monotonic() - started
                ),
            )
        except Exception as error:
            elapsed = time.monotonic() - started

            return ParentScanResult(
                contexts=(),
                failure=LineageDiscoveryFailure(
                    project=parent.project,
                    project_version=parent.version,
                    project_version_href=(
                        parent.version_href
                    ),
                    stage="scan-parent-bom",
                    error=str(error),
                    elapsed_seconds=elapsed,
                ),
                elapsed_seconds=elapsed,
            )

    print(
        f"Discovering parent relationships across "
        f"{len(scan_plan)} selected project version(s) "
        f"with {worker_count} worker(s).",
        file=sys.stderr,
    )

    scan_results = ordered_parallel_map(
        scan_plan,
        scan_parent,
        workers=worker_count,
        maximum=MAX_IO_WORKERS,
    )

    if cache is not None:
        cache_results: list[
            tuple[
                DiscoveryVersion,
                str,
                list[dict[str, str]],
                str | None,
            ]
        ] = []

        for (
            version,
            reason,
        ), result in zip(
            scan_plan,
            scan_results,
            strict=True,
        ):
            error = (
                result.failure.error
                if result.failure is not None
                else None
            )
            cache_results.append(
                (
                    version,
                    reason,
                    [
                        lineage_context_to_row(context)
                        for context in result.contexts
                    ],
                    error,
                )
            )

            if result.failure is not None:
                failures.append(result.failure)

        discovery_cache.update_cache_with_scan_results(
            cache,
            cache_results,
        )
        discovery_cache.save_cache(
            normalized_cache_path,
            cache,
        )
        rows = (
            discovery_cache.collect_relations_from_cache(
                cache,
                cache_versions,
            )
        )
        contexts = contexts_from_rows(
            rows,
            instance_url=str(
                getattr(client, "base_url", "")
            ),
        )

        print(
            f"Wrote parent lineage cache: "
            f"{normalized_cache_path}",
            file=sys.stderr,
        )
    else:
        contexts_by_id: dict[
            str,
            LineageContext,
        ] = {}

        for result in scan_results:
            if result.failure is not None:
                failures.append(result.failure)
                continue

            for context in result.contexts:
                contexts_by_id.setdefault(
                    context.external_id,
                    context,
                )

        contexts = tuple(
            sorted(
                contexts_by_id.values(),
                key=lambda context: (
                    context.parent.identity_key,
                    context.child.identity_key,
                    context.detection_method,
                ),
            )
        )

    return LineageDiscoveryResult(
        contexts=contexts,
        failures=tuple(failures),
        inventory=inventory,
        reused_count=reused_count,
        scanned_count=len(scan_plan),
        pruned_count=pruned_count,
        cache_path=normalized_cache_path,
    )
