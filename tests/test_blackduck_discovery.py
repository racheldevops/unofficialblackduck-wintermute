from __future__ import annotations

import threading
import time
from typing import Any

from wintermute.blackduck.discovery import (
    discover_parent_relationships,
)
from wintermute.blackduck.inventory import InventoryFilter
from wintermute.blackduck.pull import (
    PullRequest,
    pull_scope,
)
from wintermute.blackduck.criteria import (
    jira_parent_rollup_criteria,
)
from wintermute.blackduck.scopes import (
    CollectionScope,
)


PARENT_PROJECT_ID = (
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
)
PARENT_VERSION_ID = (
    "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
)
CHILD_PROJECT_ID = (
    "cccccccc-cccc-cccc-cccc-cccccccccccc"
)
CHILD_VERSION_ID = (
    "dddddddd-dddd-dddd-dddd-dddddddddddd"
)

PARENT_PROJECT_HREF = (
    f"https://bd.example/api/projects/{PARENT_PROJECT_ID}"
)
PARENT_VERSION_HREF = (
    f"{PARENT_PROJECT_HREF}/versions/{PARENT_VERSION_ID}"
)
CHILD_PROJECT_HREF = (
    f"https://bd.example/api/projects/{CHILD_PROJECT_ID}"
)
CHILD_VERSION_HREF = (
    f"{CHILD_PROJECT_HREF}/versions/{CHILD_VERSION_ID}"
)


class Client:
    base_url = "https://bd.example"

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.active = 0
        self.max_active = 0

    def clone_for_worker(self) -> Client:
        return self

    def get(self, href: str) -> dict[str, Any]:
        return {
            "versionName": "1",
            "_meta": {"href": href},
        }

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
                    "_meta": {
                        "href": PARENT_VERSION_HREF
                    },
                }
            ]

        if href == f"{CHILD_PROJECT_HREF}/versions":
            return [
                {
                    "versionName": "2.0",
                    "phase": "RELEASED",
                    "_meta": {
                        "href": CHILD_VERSION_HREF
                    },
                }
            ]

        if href == f"{PARENT_VERSION_HREF}/components":
            with self.lock:
                self.active += 1
                self.max_active = max(
                    self.max_active,
                    self.active,
                )

            try:
                time.sleep(0.02)

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
            finally:
                with self.lock:
                    self.active -= 1

        if href == f"{CHILD_VERSION_HREF}/components":
            return []

        if href.endswith(
            "/vulnerable-bom-components"
        ):
            return []

        return []


def test_shared_discovery_finds_parent_relationships() -> None:
    result = discover_parent_relationships(
        Client(),
        workers=2,
        resolve_bom_names=True,
    )

    assert result.relationship_count == 1
    assert (
        result.parent_project_version_count
        == 1
    )
    assert result.failures == ()

    row = result.relationship_rows[0]
    assert row["parent_project"] == "Parent"
    assert row["child_project"] == "Child"
    assert row["detection_method"] == "api-href"


def test_parent_scope_discovers_when_rows_are_empty() -> None:
    execution = pull_scope(
        Client(),
        PullRequest(
            scope=CollectionScope.PARENT_ROLLUP,
            criteria=jira_parent_rollup_criteria(),
            workers=2,
            resolve_bom_names=True,
        ),
        rows=[],
        inventory_filter=InventoryFilter(
            phase="RELEASED",
        ),
        generated_at="2026-08-06T00:00:00Z",
    )

    assert execution.target_count == 1
    assert (
        execution.manifest.lineage_context_count
        == 1
    )
    assert execution.failure_count == 0
