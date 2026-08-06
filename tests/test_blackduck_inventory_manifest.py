from __future__ import annotations

import threading
import time
from typing import Any

from wintermute.blackduck.inventory import (
    InventoryFilter,
    build_project_version_inventory,
)
from wintermute.blackduck.manifest import (
    build_collection_manifest,
    partition_targets,
    target_shard,
)
from wintermute.blackduck.scopes import CollectionScope


def projects() -> list[dict[str, Any]]:
    return [
        {
            "name": "Service A",
            "_meta": {
                "href": "https://bd.example/api/projects/a",
                "links": [
                    {
                        "rel": "versions",
                        "href": (
                            "https://bd.example/api/projects/a/"
                            "versions"
                        ),
                    }
                ],
            },
        },
        {
            "name": "Service B",
            "_meta": {
                "href": "https://bd.example/api/projects/b",
                "links": [
                    {
                        "rel": "versions",
                        "href": (
                            "https://bd.example/api/projects/b/"
                            "versions"
                        ),
                    }
                ],
            },
        },
    ]


class InventoryClient:
    base_url = "https://bd.example"

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.active = 0
        self.max_active = 0

    def clone_for_worker(self) -> InventoryClient:
        return self

    def paged_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        del params, limit

        if path == "/api/projects":
            return projects()

        with self.lock:
            self.active += 1
            self.max_active = max(
                self.max_active,
                self.active,
            )

        try:
            time.sleep(0.02)
            project_id = path.split("/")[-2]

            return [
                {
                    "versionName": "1.0",
                    "phase": "RELEASED",
                    "updatedAt": "2026-08-01T00:00:00Z",
                    "createdAt": "2026-01-01T00:00:00Z",
                    "_meta": {
                        "href": (
                            f"https://bd.example/api/projects/"
                            f"{project_id}/versions/1"
                        )
                    },
                },
                {
                    "versionName": "2.0",
                    "phase": "DEVELOPMENT",
                    "_meta": {
                        "href": (
                            f"https://bd.example/api/projects/"
                            f"{project_id}/versions/2"
                        )
                    },
                },
            ]
        finally:
            with self.lock:
                self.active -= 1


def test_shared_inventory_is_parallel_and_deterministic() -> None:
    client = InventoryClient()

    result = build_project_version_inventory(
        client,
        filters=InventoryFilter(),
        workers=2,
    )

    assert client.max_active > 1
    assert result.project_version_count == 4
    assert result.failures == ()
    assert [
        item.project_version.project
        for item in result.items
    ] == [
        "Service A",
        "Service A",
        "Service B",
        "Service B",
    ]


def test_shared_inventory_applies_filters_and_limits() -> None:
    result = build_project_version_inventory(
        InventoryClient(),
        filters=InventoryFilter(
            project_name="Service B",
            version_name="1.0",
            phase="RELEASED",
            max_versions=1,
        ),
        workers=2,
    )

    assert result.project_version_count == 1
    item = result.items[0]

    assert item.project_version.project == "Service B"
    assert item.project_version.version == "1.0"
    assert item.project_version.updated == (
        "2026-08-01T00:00:00Z"
    )
    assert item.created == "2026-01-01T00:00:00Z"


def test_parent_manifest_deduplicates_collection_targets() -> None:
    manifest = build_collection_manifest(
        CollectionScope.PARENT_ROLLUP,
        [
            {
                "parent_project": "Product A",
                "parent_version": "1",
                "parent_version_href": (
                    "https://bd.example/products/a/versions/1"
                ),
                "child_project": "Service",
                "child_version": "2",
                "child_version_href": (
                    "https://bd.example/services/s/versions/2"
                ),
            },
            {
                "parent_project": "Product B",
                "parent_version": "3",
                "parent_version_href": (
                    "https://bd.example/products/b/versions/3"
                ),
                "child_project": "Service",
                "child_version": "2",
                "child_version_href": (
                    "https://bd.example/services/s/versions/2"
                ),
            },
        ],
        instance_url="https://bd.example",
        generated_at="2026-08-06T00:00:00Z",
    )

    assert manifest.target_count == 1
    assert manifest.lineage_context_count == 2

    payload = manifest.as_dict()
    assert payload["scope"] == "parent-rollup"
    assert payload["target_count"] == 1
    assert len(
        payload["targets"][0]["lineage_contexts"]
    ) == 2


def test_manifest_sharding_is_stable_and_complete() -> None:
    manifest = build_collection_manifest(
        CollectionScope.CANDIDATE_PROJECTS,
        [
            {
                "project": f"Service {index}",
                "project_version": "1",
                "project_version_href": (
                    f"https://bd.example/services/{index}/"
                    "versions/1"
                ),
            }
            for index in range(20)
        ],
        instance_url="https://bd.example",
        generated_at="2026-08-06T00:00:00Z",
    )

    first = partition_targets(
        manifest.targets,
        shard_count=4,
    )
    second = partition_targets(
        reversed(manifest.targets),
        shard_count=4,
    )

    assert [
        [
            target.project_version.external_id
            for target in partition
        ]
        for partition in first
    ] == [
        [
            target.project_version.external_id
            for target in partition
        ]
        for partition in second
    ]
    assert sum(len(partition) for partition in first) == 20

    for shard_index, partition in enumerate(first):
        assert all(
            target_shard(target, 4) == shard_index
            for target in partition
        )


def test_lineage_rows_feed_parent_rollup_manifest() -> None:
    from wintermute.blackduck.lineage import (
        lineage_context_to_row,
    )
    from wintermute.blackduck.models import (
        LineageContext,
        ProjectVersionRef,
    )

    parent = ProjectVersionRef(
        instance_url="https://bd.example",
        project="Product",
        version="1",
        version_href=(
            "https://bd.example/products/p/versions/1"
        ),
    )
    child = ProjectVersionRef(
        instance_url="https://bd.example",
        project="Service",
        version="2",
        version_href=(
            "https://bd.example/services/s/versions/2"
        ),
    )
    row = lineage_context_to_row(
        LineageContext(
            parent=parent,
            child=child,
            detection_method="api-href",
        )
    )
    manifest = build_collection_manifest(
        CollectionScope.PARENT_ROLLUP,
        [row],
        instance_url="https://bd.example",
        generated_at="2026-08-06T00:00:00Z",
    )

    assert manifest.target_count == 1
    assert manifest.lineage_context_count == 1
    assert (
        manifest.targets[0].project_version.version_href
        == child.version_href
    )
