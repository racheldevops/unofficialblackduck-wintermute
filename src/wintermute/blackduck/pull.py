from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from wintermute.blackduck.collector import (
    CollectionRunResult,
    EntityResolver,
    collect_targets,
)
from wintermute.blackduck.criteria import CollectionCriteria
from wintermute.blackduck.inventory import InventoryFilter
from wintermute.blackduck.manifest import (
    CollectionManifest,
    now_iso as manifest_now_iso,
)
from wintermute.blackduck.resolver import (
    ScopeResolutionFailure,
    resolve_collection_scope,
)
from wintermute.blackduck.scopes import (
    CollectionScope,
    normalize_scope,
)


@dataclass(frozen=True)
class PullRequest:
    scope: CollectionScope
    criteria: CollectionCriteria
    workers: int = 4
    component_workers: int = 1
    resolve_bom_names: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "scope",
            normalize_scope(self.scope),
        )

        if self.workers < 1:
            raise ValueError(
                "workers must be greater than zero"
            )

        if self.component_workers < 1:
            raise ValueError(
                "component_workers must be greater than zero"
            )
    lineage_cache_path: str = ""
    refresh_lineage_cache: bool = False
    refresh_failed_lineage: bool = True
    lineage_cache_max_age_days: float = 7.0
    trust_lineage_cache_without_update_marker: bool = False


@dataclass(frozen=True)
class PullExecution:
    request: PullRequest
    manifest: CollectionManifest
    collection: CollectionRunResult
    scope_failures: tuple[
        ScopeResolutionFailure,
        ...
    ] = ()

    @property
    def target_count(self) -> int:
        return self.manifest.target_count

    @property
    def finding_count(self) -> int:
        return len(self.collection.findings)

    @property
    def failure_count(self) -> int:
        return (
            len(self.collection.failures)
            + len(self.scope_failures)
        )
    scope_metrics: dict[str, Any] | None = None


def pull_scope(
    client: Any,
    request: PullRequest,
    *,
    rows: Iterable[Mapping[str, Any]] = (),
    inventory_filter: InventoryFilter | None = None,
    entity_resolver: EntityResolver | None = None,
    generated_at: str | None = None,
    debug: bool = False,
) -> PullExecution:
    resolution = resolve_collection_scope(
        client,
        request.scope,
        rows=rows,
        inventory_filter=inventory_filter,
        workers=request.workers,
        resolve_bom_names=(
            request.resolve_bom_names
        ),
        debug=debug,
        lineage_cache_path=(
            request.lineage_cache_path
        ),
        refresh_lineage_cache=(
            request.refresh_lineage_cache
        ),
        refresh_failed_lineage=(
            request.refresh_failed_lineage
        ),
        lineage_cache_max_age_days=(
            request.lineage_cache_max_age_days
        ),
        trust_lineage_cache_without_update_marker=(
            request.trust_lineage_cache_without_update_marker
        ),
    )
    manifest = CollectionManifest(
        scope=resolution.scope,
        targets=resolution.targets,
        generated_at=(
            generated_at or manifest_now_iso()
        ),
    )
    collection = collect_targets(
        client,
        manifest.targets,
        request.criteria,
        workers=request.workers,
        component_workers=(
            request.component_workers
        ),
        entity_resolver=entity_resolver,
    )

    return PullExecution(
        request=request,
        manifest=manifest,
        collection=collection,
        scope_failures=resolution.failures,
        scope_metrics=dict(resolution.scope_metrics or {}),
    )


def pull_rows(
    client: Any,
    rows: Iterable[Mapping[str, Any]],
    request: PullRequest,
    *,
    entity_resolver: EntityResolver | None = None,
    generated_at: str | None = None,
) -> PullExecution:
    return pull_scope(
        client,
        request,
        rows=rows,
        entity_resolver=entity_resolver,
        generated_at=generated_at,
    )
