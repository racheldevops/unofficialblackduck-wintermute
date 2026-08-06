from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass
from typing import Any

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
from wintermute.blackduck.models import LineageContext
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
class LineageDiscoveryResult:
    contexts: tuple[LineageContext, ...]
    failures: tuple[LineageDiscoveryFailure, ...]
    inventory: InventoryResult

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
    def relationship_rows(self) -> tuple[dict[str, str], ...]:
        return tuple(
            lineage_context_to_row(context)
            for context in self.contexts
        )


def discover_parent_relationships(
    client: Any,
    *,
    inventory_filter: InventoryFilter | None = None,
    workers: int = 4,
    resolve_bom_names: bool = False,
    debug: bool = False,
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

    if not project_versions:
        return LineageDiscoveryResult(
            contexts=(),
            failures=tuple(failures),
            inventory=inventory,
        )

    worker_count = min(
        bounded_worker_count(
            workers,
            maximum=MAX_IO_WORKERS,
        ),
        len(project_versions),
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

    def scan_parent(parent: Any) -> ParentScanResult:
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
        f"{len(project_versions)} project version(s) "
        f"with {worker_count} worker(s).",
        file=sys.stderr,
    )

    scan_results = ordered_parallel_map(
        project_versions,
        scan_parent,
        workers=worker_count,
        maximum=MAX_IO_WORKERS,
    )
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
    )
