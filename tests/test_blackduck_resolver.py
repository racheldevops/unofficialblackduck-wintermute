from __future__ import annotations

from typing import Any

from wintermute.blackduck.inventory import (
    InventoryFilter,
)
from wintermute.blackduck.resolver import (
    resolve_collection_scope,
)
from wintermute.blackduck.scopes import (
    CollectionScope,
)


class Client:
    base_url = "https://bd.example"

    def clone_for_worker(self) -> Client:
        return self

    def paged_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        del params, limit

        if path == "/api/projects":
            return [
                {
                    "name": "Service",
                    "_meta": {
                        "href": (
                            "https://bd.example/"
                            "api/projects/service"
                        ),
                        "links": [
                            {
                                "rel": "versions",
                                "href": (
                                    "https://bd.example/"
                                    "api/projects/service/"
                                    "versions"
                                ),
                            }
                        ],
                    },
                }
            ]

        if path.endswith("/versions"):
            return [
                {
                    "versionName": "1.0",
                    "phase": "RELEASED",
                    "_meta": {
                        "href": (
                            "https://bd.example/"
                            "api/projects/service/"
                            "versions/1"
                        )
                    },
                }
            ]

        return []


def test_resolves_parent_scope() -> None:
    result = resolve_collection_scope(
        Client(),
        CollectionScope.PARENT_ROLLUP,
        rows=[
            {
                "parent_project": "Product",
                "parent_version": "1",
                "parent_version_href": (
                    "https://bd.example/products/p/"
                    "versions/1"
                ),
                "child_project": "Service",
                "child_version": "1.0",
                "child_version_href": (
                    "https://bd.example/services/s/"
                    "versions/1"
                ),
            }
        ],
    )

    assert result.target_count == 1
    assert result.source_row_count == 1
    assert len(
        result.targets[0].lineage_contexts
    ) == 1


def test_resolves_candidate_and_explicit_scopes() -> None:
    row = {
        "project": "Service",
        "project_version": "1.0",
        "project_version_href": (
            "https://bd.example/services/s/"
            "versions/1"
        ),
    }

    candidate_result = resolve_collection_scope(
        Client(),
        CollectionScope.CANDIDATE_PROJECTS,
        rows=[row],
    )
    explicit_result = resolve_collection_scope(
        Client(),
        CollectionScope.EXPLICIT_PROJECT_VERSIONS,
        rows=[row],
    )

    assert candidate_result.target_count == 1
    assert explicit_result.target_count == 1
    assert (
        candidate_result.targets[0]
        .project_version.identity_key
        == explicit_result.targets[0]
        .project_version.identity_key
    )


def test_resolves_all_project_versions_from_inventory() -> None:
    result = resolve_collection_scope(
        Client(),
        CollectionScope.ALL_PROJECT_VERSIONS,
        inventory_filter=InventoryFilter(
            phase="RELEASED",
        ),
        workers=2,
    )

    assert result.target_count == 1
    assert result.source_row_count == 1
    assert result.failures == ()
    assert (
        result.targets[0].project_version.project
        == "Service"
    )


def test_automatic_parent_discovery_uses_uncached_clone(
    monkeypatch,
) -> None:
    from types import SimpleNamespace
    from wintermute.blackduck import resolver

    uncached_client = object()
    captured = {}

    class CacheAwareClient:
        base_url = "https://bd.example"

        def clone_for_uncached_reads(self):
            return uncached_client

    def fake_discovery(client, **kwargs):
        captured["client"] = client
        captured["kwargs"] = kwargs

        return SimpleNamespace(
            relationship_rows=(),
            relationship_count=0,
            parent_project_version_count=0,
            failures=(),
            inventory=SimpleNamespace(
                project_version_count=0,
            ),
            reused_count=0,
            scanned_count=0,
            pruned_count=0,
            cache_path="",
        )

    monkeypatch.setattr(
        resolver,
        "discover_parent_relationships",
        fake_discovery,
    )

    result = resolver.resolve_collection_scope(
        CacheAwareClient(),
        CollectionScope.PARENT_ROLLUP,
        rows=[],
        workers=4,
    )

    assert result.target_count == 0
    assert captured["client"] is uncached_client
    assert captured["kwargs"]["workers"] == 4
    assert result.scope_metrics == {
        "relationship_rows": 0,
        "parent_project_versions": 0,
        "inventory_project_versions": 0,
        "lineage_cache_reused": 0,
        "lineage_cache_scanned": 0,
        "lineage_cache_pruned": 0,
        "lineage_cache_path": "",
    }
