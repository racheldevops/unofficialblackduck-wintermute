from __future__ import annotations

import threading
import time
from typing import Any

from wintermute.blackduck.collector import (
    collect_target,
    collect_targets,
)
from wintermute.blackduck.criteria import (
    datadog_high_risk_criteria,
    jira_parent_rollup_criteria,
)
from wintermute.blackduck.models import (
    CollectionTarget,
    LineageContext,
    ProjectVersionRef,
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
        if "/api/components/" in href:
            return {"versionName": "3.0.1"}

        return {
            "versionName": "1.0",
            "_meta": {"href": href},
        }

    def paged_get(
        self,
        href: str,
    ) -> list[dict[str, Any]]:
        with self.lock:
            self.active += 1
            self.max_active = max(
                self.max_active,
                self.active,
            )

        try:
            time.sleep(0.01)

            if href.endswith(
                "/vulnerable-bom-components"
            ):
                return [
                    {
                        "componentName": "openssl",
                        "componentVersionName": "3.0.1",
                        "componentOriginId": "origin-a",
                        "_meta": {
                            "href": (
                                "https://bd.example/"
                                "bom-components/openssl"
                            ),
                            "links": [
                                {
                                    "rel": "vulnerabilities",
                                    "href": (
                                        "https://bd.example/"
                                        "vulnerabilities/openssl"
                                    ),
                                }
                            ],
                        },
                    }
                ]

            if href.endswith(
                "/vulnerabilities/openssl"
            ):
                return [
                    {
                        "vulnerabilityName": (
                            "CVE-2026-0001"
                        ),
                        "overallScore": 9.8,
                        "severity": "CRITICAL",
                        "cvssVector": "CVSS:3.1/AV:N",
                        "exploitAvailable": True,
                        "reachabilityStatus": "reachable",
                        "_meta": {
                            "href": (
                                "https://bd.example/"
                                "vulnerabilities/"
                                "CVE-2026-0001"
                            )
                        },
                    },
                    {
                        "vulnerabilityName": (
                            "CVE-2026-0002"
                        ),
                        "overallScore": 5.0,
                        "severity": "MEDIUM",
                        "exploitAvailable": False,
                    },
                ]

            return []
        finally:
            with self.lock:
                self.active -= 1


def target(
    suffix: str = "service",
) -> CollectionTarget:
    child = ProjectVersionRef(
        instance_url="https://bd.example",
        project=f"Service {suffix}",
        version="1.0",
        project_href=(
            f"https://bd.example/projects/{suffix}"
        ),
        version_href=(
            f"https://bd.example/projects/{suffix}/"
            "versions/1"
        ),
    )
    parent = ProjectVersionRef(
        instance_url="https://bd.example",
        project="Product",
        version="2.0",
        version_href=(
            "https://bd.example/products/product/"
            "versions/2"
        ),
    )

    return CollectionTarget(
        project_version=child,
        lineage_contexts=(
            LineageContext(
                parent=parent,
                child=child,
                detection_method="api-href",
            ),
        ),
    )


def test_collect_target_applies_jira_criteria() -> None:
    result = collect_target(
        Client(),
        target(),
        jira_parent_rollup_criteria(),
        entity_resolver=lambda client, item: (
            "Team A"
        ),
    )

    assert result.status == "ok"
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.vulnerability == (
        "CVE-2026-0001"
    )
    assert finding.score == 9.8
    assert finding.entity == "Team A"
    assert finding.exploit_available is True
    assert len(finding.lineage_contexts) == 1


def test_collect_target_applies_datadog_criteria() -> None:
    criteria = datadog_high_risk_criteria(
        threshold=8.9,
        require_exploit_available=True,
        require_reachable=True,
        reachability_mode="field",
    )
    result = collect_target(
        Client(),
        target(),
        criteria,
    )

    assert result.status == "ok"
    assert [
        finding.vulnerability
        for finding in result.findings
    ] == ["CVE-2026-0001"]


def test_collect_targets_preserves_target_order() -> None:
    client = Client()
    targets = [
        target("slow"),
        target("fast"),
    ]

    result = collect_targets(
        client,
        targets,
        jira_parent_rollup_criteria(),
        workers=2,
    )

    assert [
        item.target.project_version.project
        for item in result.target_results
    ] == [
        "Service slow",
        "Service fast",
    ]
    assert result.succeeded_target_count == 2
    assert result.failed_target_count == 0
    assert len(result.findings) == 2
    assert client.max_active > 1


def test_missing_target_href_is_failure() -> None:
    item = CollectionTarget(
        project_version=ProjectVersionRef(
            instance_url="https://bd.example",
            project="Missing",
            version="1",
        )
    )
    result = collect_target(
        Client(),
        item,
        jira_parent_rollup_criteria(),
    )

    assert result.status == "failed"
    assert result.failures[0].stage == (
        "validate-target"
    )


def test_duplicate_component_vulnerability_links_are_collected_once() -> None:
    class DuplicateClient(Client):
        def __init__(self) -> None:
            super().__init__()
            self.vulnerability_calls = 0

        def paged_get(
            self,
            href: str,
        ) -> list[dict[str, Any]]:
            if href.endswith(
                "/vulnerable-bom-components"
            ):
                component = {
                    "componentName": "openssl",
                    "componentVersionName": "3.0.1",
                    "_meta": {
                        "href": (
                            "https://bd.example/"
                            "bom-components/openssl"
                        ),
                        "links": [
                            {
                                "rel": "vulnerabilities",
                                "href": (
                                    "https://bd.example/"
                                    "vulnerabilities/openssl"
                                ),
                            }
                        ],
                    },
                }

                return [
                    dict(component),
                    dict(component),
                    dict(component),
                ]

            if href.endswith(
                "/vulnerabilities/openssl"
            ):
                self.vulnerability_calls += 1

            return super().paged_get(href)

    client = DuplicateClient()
    result = collect_target(
        client,
        target(),
        jira_parent_rollup_criteria(),
        component_workers=4,
    )

    assert result.status == "ok"
    assert len(result.findings) == 1
    assert client.vulnerability_calls == 1
