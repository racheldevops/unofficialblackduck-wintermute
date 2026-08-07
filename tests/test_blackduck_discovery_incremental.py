from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from wintermute.blackduck.discovery import (
    discover_parent_relationships,
)


PARENT_PROJECT = (
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
)
PARENT_VERSION = (
    "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
)
CHILD_PROJECT = (
    "cccccccc-cccc-cccc-cccc-cccccccccccc"
)
CHILD_VERSION = (
    "dddddddd-dddd-dddd-dddd-dddddddddddd"
)
PARENT_PROJECT_HREF = (
    f"https://bd.example/api/projects/{PARENT_PROJECT}"
)
PARENT_VERSION_HREF = (
    f"{PARENT_PROJECT_HREF}/versions/{PARENT_VERSION}"
)
CHILD_PROJECT_HREF = (
    f"https://bd.example/api/projects/{CHILD_PROJECT}"
)
CHILD_VERSION_HREF = (
    f"{CHILD_PROJECT_HREF}/versions/{CHILD_VERSION}"
)


class Client:
    base_url = "https://bd.example"

    def __init__(
        self,
        *,
        parent_updated: str = (
            "2026-08-01T00:00:00Z"
        ),
    ) -> None:
        self.parent_updated = parent_updated
        self.component_calls = 0

    def clone_for_worker(self):
        return self

    def paged_get(
        self,
        href: str,
        params: dict[str, Any] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        del params, limit

        if href == "/api/projects":
            return [
                {
                    "name": "Parent",
                    "_meta": {
                        "href": PARENT_PROJECT_HREF,
                        "links": [
                            {
                                "rel": "versions",
                                "href": (
                                    f"{PARENT_PROJECT_HREF}/versions"
                                ),
                            }
                        ],
                    },
                },
                {
                    "name": "Child",
                    "_meta": {
                        "href": CHILD_PROJECT_HREF,
                        "links": [
                            {
                                "rel": "versions",
                                "href": (
                                    f"{CHILD_PROJECT_HREF}/versions"
                                ),
                            }
                        ],
                    },
                },
            ]

        if href == f"{PARENT_PROJECT_HREF}/versions":
            return [
                {
                    "versionName": "1.0",
                    "phase": "RELEASED",
                    "updatedAt": self.parent_updated,
                    "_meta": {
                        "href": PARENT_VERSION_HREF,
                    },
                }
            ]

        if href == f"{CHILD_PROJECT_HREF}/versions":
            return [
                {
                    "versionName": "2.0",
                    "phase": "RELEASED",
                    "updatedAt": (
                        "2026-08-01T00:00:00Z"
                    ),
                    "_meta": {
                        "href": CHILD_VERSION_HREF,
                    },
                }
            ]

        if href == f"{PARENT_VERSION_HREF}/components":
            self.component_calls += 1
            return [
                {
                    "componentName": "Child",
                    "componentVersionName": "2.0",
                    "_meta": {
                        "links": [
                            {
                                "rel": "project-version",
                                "href": CHILD_VERSION_HREF,
                            }
                        ]
                    },
                }
            ]

        if href == f"{CHILD_VERSION_HREF}/components":
            self.component_calls += 1
            return []

        raise RuntimeError(
            f"Unexpected request: {href}"
        )


def test_second_discovery_run_reuses_all_cached_versions(
    tmp_path: Path,
) -> None:
    cache_path = tmp_path / "lineage-cache.json"
    first_client = Client()
    first = discover_parent_relationships(
        first_client,
        workers=2,
        resolve_bom_names=True,
        cache_path=cache_path,
        refresh_older_than_days=-1,
    )

    assert first.relationship_count == 1
    assert first.reused_count == 0
    assert first.scanned_count == 2
    assert first_client.component_calls == 2

    second_client = Client()
    second = discover_parent_relationships(
        second_client,
        workers=2,
        resolve_bom_names=True,
        cache_path=cache_path,
        refresh_older_than_days=-1,
    )

    assert second.relationship_count == 1
    assert second.reused_count == 2
    assert second.scanned_count == 0
    assert second_client.component_calls == 0


def test_changed_version_rescans_only_changed_parent(
    tmp_path: Path,
) -> None:
    cache_path = tmp_path / "lineage-cache.json"

    discover_parent_relationships(
        Client(),
        workers=2,
        resolve_bom_names=True,
        cache_path=cache_path,
        refresh_older_than_days=-1,
    )
    changed_client = Client(
        parent_updated=(
            "2026-08-02T00:00:00Z"
        )
    )
    result = discover_parent_relationships(
        changed_client,
        workers=2,
        resolve_bom_names=True,
        cache_path=cache_path,
        refresh_older_than_days=-1,
    )

    assert result.relationship_count == 1
    assert result.reused_count == 1
    assert result.scanned_count == 1
    assert changed_client.component_calls == 1

    payload = json.loads(
        cache_path.read_text(encoding="utf-8")
    )
    assert len(payload["entries"]) == 2
