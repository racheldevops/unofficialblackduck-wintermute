from __future__ import annotations

from typing import Any

from wintermute.blackduck.criteria import (
    jira_parent_rollup_criteria,
)
from wintermute.blackduck.pull import (
    PullRequest,
    pull_rows,
)
from wintermute.blackduck.scopes import (
    CollectionScope,
)


class Client:
    base_url = "https://bd.example"

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
    ) -> list[dict[str, Any]]:
        if href.endswith(
            "/vulnerable-bom-components"
        ):
            return [
                {
                    "componentName": "openssl",
                    "componentVersionName": "3.0.1",
                    "_meta": {
                        "links": [
                            {
                                "rel": "vulnerabilities",
                                "href": (
                                    "https://bd.example/"
                                    "vulnerabilities"
                                ),
                            }
                        ]
                    },
                }
            ]

        if href.endswith("/vulnerabilities"):
            return [
                {
                    "vulnerabilityName": (
                        "CVE-2026-0001"
                    ),
                    "overallScore": 9.8,
                    "severity": "CRITICAL",
                }
            ]

        return []


def test_general_pull_runs_parent_scope() -> None:
    execution = pull_rows(
        Client(),
        [
            {
                "parent_project": "Product A",
                "parent_version": "1",
                "parent_version_href": (
                    "https://bd.example/products/a/"
                    "versions/1"
                ),
                "child_project": "Service",
                "child_version": "2",
                "child_version_href": (
                    "https://bd.example/services/s/"
                    "versions/2"
                ),
            },
            {
                "parent_project": "Product B",
                "parent_version": "1",
                "parent_version_href": (
                    "https://bd.example/products/b/"
                    "versions/1"
                ),
                "child_project": "Service",
                "child_version": "2",
                "child_version_href": (
                    "https://bd.example/services/s/"
                    "versions/2"
                ),
            },
        ],
        PullRequest(
            scope=CollectionScope.PARENT_ROLLUP,
            criteria=jira_parent_rollup_criteria(),
            workers=2,
        ),
        generated_at="2026-08-06T00:00:00Z",
    )

    assert execution.target_count == 1
    assert execution.finding_count == 1
    assert execution.failure_count == 0
    assert (
        execution.manifest.lineage_context_count
        == 2
    )
    assert len(
        execution.collection.findings[0]
        .lineage_contexts
    ) == 2


def test_general_pull_runs_candidate_scope() -> None:
    execution = pull_rows(
        Client(),
        [
            {
                "project": "Service",
                "project_version": "2",
                "project_version_href": (
                    "https://bd.example/services/s/"
                    "versions/2"
                ),
            }
        ],
        PullRequest(
            scope=(
                CollectionScope.CANDIDATE_PROJECTS
            ),
            criteria=jira_parent_rollup_criteria(),
            workers=1,
        ),
        generated_at="2026-08-06T00:00:00Z",
    )

    assert execution.target_count == 1
    assert execution.finding_count == 1
    assert (
        execution.manifest.lineage_context_count
        == 0
    )


def test_pull_request_accepts_scope_alias() -> None:
    request = PullRequest(
        scope="parent-rollup",
        criteria=jira_parent_rollup_criteria(),
        workers=1,
    )

    assert request.scope == (
        CollectionScope.PARENT_ROLLUP
    )


def test_general_pull_runs_all_project_versions_scope() -> None:
    from wintermute.blackduck.inventory import (
        InventoryFilter,
    )
    from wintermute.blackduck.pull import (
        pull_scope,
    )

    class InventoryClient(Client):
        def paged_get(
            self,
            href: str,
        ) -> list[dict[str, Any]]:
            if href == "/api/projects":
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

            if href.endswith(
                "/api/projects/service/versions"
            ):
                return [
                    {
                        "versionName": "2",
                        "phase": "RELEASED",
                        "_meta": {
                            "href": (
                                "https://bd.example/"
                                "services/s/versions/2"
                            )
                        },
                    }
                ]

            return super().paged_get(href)

    execution = pull_scope(
        InventoryClient(),
        PullRequest(
            scope=(
                CollectionScope.ALL_PROJECT_VERSIONS
            ),
            criteria=jira_parent_rollup_criteria(),
            workers=2,
        ),
        inventory_filter=InventoryFilter(
            phase="RELEASED",
        ),
        generated_at="2026-08-06T00:00:00Z",
    )

    assert execution.target_count == 1
    assert execution.finding_count == 1
    assert execution.failure_count == 0
