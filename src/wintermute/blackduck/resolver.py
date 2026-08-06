from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from wintermute.blackduck.discovery import (
    discover_parent_relationships,
)
from wintermute.blackduck.inventory import (
    InventoryFailure,
    InventoryFilter,
    build_project_version_inventory,
)
from wintermute.blackduck.models import CollectionTarget
from wintermute.blackduck.scopes import (
    CollectionScope,
    normalize_scope,
    targets_from_candidates,
    targets_from_parent_relationships,
)


@dataclass(frozen=True)
class ScopeResolutionFailure:
    project: str
    project_href: str
    stage: str
    error: str
    project_version: str = ""
    project_version_href: str = ""


@dataclass(frozen=True)
class ScopeResolutionResult:
    scope: CollectionScope
    targets: tuple[CollectionTarget, ...]
    failures: tuple[ScopeResolutionFailure, ...]
    source_row_count: int

    @property
    def target_count(self) -> int:
        return len(self.targets)


def inventory_failure(
    failure: InventoryFailure,
) -> ScopeResolutionFailure:
    return ScopeResolutionFailure(
        project=failure.project,
        project_href=failure.project_href,
        stage=failure.stage,
        error=failure.error,
    )


def resolve_collection_scope(
    client: Any,
    scope: str | CollectionScope,
    *,
    rows: Iterable[Mapping[str, Any]] = (),
    inventory_filter: InventoryFilter | None = None,
    workers: int = 4,
    resolve_bom_names: bool = False,
    debug: bool = False,
) -> ScopeResolutionResult:
    normalized_scope = normalize_scope(scope)
    source_rows = [
        dict(row)
        for row in rows
    ]

    if normalized_scope == CollectionScope.PARENT_ROLLUP:
        if source_rows:
            targets = targets_from_parent_relationships(
                source_rows,
                instance_url=str(
                    getattr(client, "base_url", "")
                ),
            )

            return ScopeResolutionResult(
                scope=normalized_scope,
                targets=tuple(targets),
                failures=(),
                source_row_count=len(source_rows),
            )

        discovery = discover_parent_relationships(
            client,
            inventory_filter=inventory_filter,
            workers=workers,
            resolve_bom_names=resolve_bom_names,
            debug=debug,
        )
        targets = targets_from_parent_relationships(
            discovery.relationship_rows,
            instance_url=str(
                getattr(client, "base_url", "")
            ),
        )
        failures = tuple(
            ScopeResolutionFailure(
                project=failure.project,
                project_href="",
                project_version=(
                    failure.project_version
                ),
                project_version_href=(
                    failure.project_version_href
                ),
                stage=failure.stage,
                error=failure.error,
            )
            for failure in discovery.failures
        )

        return ScopeResolutionResult(
            scope=normalized_scope,
            targets=tuple(targets),
            failures=failures,
            source_row_count=(
                discovery.relationship_count
            ),
        )

    if normalized_scope in {
        CollectionScope.CANDIDATE_PROJECTS,
        CollectionScope.EXPLICIT_PROJECT_VERSIONS,
    }:
        targets = targets_from_candidates(
            source_rows,
            instance_url=str(
                getattr(client, "base_url", "")
            ),
        )

        return ScopeResolutionResult(
            scope=normalized_scope,
            targets=tuple(targets),
            failures=(),
            source_row_count=len(source_rows),
        )

    inventory = build_project_version_inventory(
        client,
        filters=inventory_filter or InventoryFilter(),
        workers=workers,
        debug=debug,
    )
    targets = tuple(
        CollectionTarget(
            project_version=item.project_version,
        )
        for item in inventory.items
    )

    return ScopeResolutionResult(
        scope=normalized_scope,
        targets=targets,
        failures=tuple(
            inventory_failure(failure)
            for failure in inventory.failures
        ),
        source_row_count=(
            inventory.selected_project_count
        ),
    )
