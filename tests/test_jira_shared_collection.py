from __future__ import annotations

import argparse
from typing import Any

import pytest

from wintermute.blackduck.criteria import (
    jira_parent_rollup_criteria,
)
from wintermute.jira.collection import (
    collect_parent_rollup,
)
from wintermute.jira import subp_vuln_rollup as rollup


CHILD_HREF = (
    "https://bd.example/api/projects/"
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/"
    "versions/"
    "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
)


class Client:
    base_url = "https://bd.example"
    timeout = 30
    retries = 1

    def __init__(self) -> None:
        self.vulnerable_component_calls = 0
        self.vulnerability_calls = 0

    def clone_for_worker(self) -> Client:
        return self

    def get(self, href: str) -> dict[str, Any]:
        return {
            "versionName": "1.0",
            "_meta": {"href": href},
        }

    def paged_get(
        self,
        href: str,
    ) -> list[dict[str, Any]]:
        if href.endswith(
            "/vulnerable-bom-components"
        ):
            self.vulnerable_component_calls += 1

            return [
                {
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
                                    "component-vulnerabilities"
                                ),
                            }
                        ],
                    },
                }
            ]

        if href.endswith(
            "/component-vulnerabilities"
        ):
            self.vulnerability_calls += 1

            return [
                {
                    "vulnerabilityName": (
                        "CVE-2026-0001"
                    ),
                    "overallScore": 9.8,
                    "severity": "CRITICAL",
                    "cvssVector": "CVSS:3.1/AV:N",
                    "_meta": {
                        "href": (
                            "https://bd.example/"
                            "vulnerabilities/"
                            "CVE-2026-0001"
                        )
                    },
                }
            ]

        return []


class FailingClient(Client):
    def paged_get(
        self,
        href: str,
    ) -> list[dict[str, Any]]:
        if href.endswith(
            "/vulnerable-bom-components"
        ):
            raise RuntimeError(
                "temporary Black Duck failure"
            )

        return []


def relationships() -> list[dict[str, str]]:
    return [
        {
            "parent_project": "Product A",
            "parent_version": "1",
            "parent_version_href": (
                "https://bd.example/products/a/"
                "versions/1"
            ),
            "child_project": "Service",
            "child_version": "2",
            "child_version_href": CHILD_HREF,
            "detection_method": "api-href",
            "subproject_path": "Service/2",
        },
        {
            "parent_project": "Product B",
            "parent_version": "3",
            "parent_version_href": (
                "https://bd.example/products/b/"
                "versions/3"
            ),
            "child_project": "Service",
            "child_version": "2",
            "child_version_href": CHILD_HREF,
            "detection_method": (
                "bom-component-name-version"
            ),
            "subproject_path": (
                "Nested > Service/2"
            ),
        },
    ]


def test_shared_collection_pulls_child_once_and_expands_contexts() -> None:
    client = Client()
    result = collect_parent_rollup(
        client,
        relationships(),
        jira_parent_rollup_criteria(),
        workers=4,
    )

    assert result.target_count == 1
    assert result.finding_count == 1
    assert client.vulnerable_component_calls == 1
    assert client.vulnerability_calls == 1
    assert len(result.rows) == 2
    assert {
        row["parent_project"]
        for row in result.rows
    } == {"Product A", "Product B"}
    assert {
        row["rollup_key"]
        for row in result.rows
    } == {
        (
            "Product A|1|Service|2|openssl|"
            "3.0.1|CVE-2026-0001"
        ),
        (
            "Product B|3|Service|2|openssl|"
            "3.0.1|CVE-2026-0001"
        ),
    }
    assert {
        row["subproject_path"]
        for row in result.rows
    } == {
        "Service/2",
        "Nested > Service/2",
    }


def test_shared_failure_expands_to_every_parent_context() -> None:
    result = collect_parent_rollup(
        FailingClient(),
        relationships(),
        jira_parent_rollup_criteria(),
        workers=4,
    )

    assert result.rows == ()
    assert len(result.failures) == 2
    assert {
        failure.parent_project
        for failure in result.failures
    } == {"Product A", "Product B"}
    assert {
        failure.stage
        for failure in result.failures
    } == {"load-vulnerable-components"}


def test_pipeline_adapter_preserves_entity_and_failure_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = Client()
    monkeypatch.setattr(
        rollup,
        "read_project_custom_field",
        lambda **_: "Team A",
    )
    args = argparse.Namespace(
        threshold=7.0,
        score_field="overallScore",
        entity_custom_field="foo Entity",
        require_entity=False,
        workers=4,
    )
    subprojects = [
        {
            "parent_project": "Product A",
            "parent_version": "1",
            "parent_version_href": (
                "https://bd.example/products/a/"
                "versions/1"
            ),
            "project_name": "Service",
            "version_name": "2",
            "version_href": CHILD_HREF,
            "version": {
                "versionName": "2",
                "_meta": {"href": CHILD_HREF},
            },
            "source": "api-href",
            "path": "Service/2",
        }
    ]

    findings, failures = (
        rollup.collect_parent_rollup_findings(
            client,
            subprojects,
            args,
        )
    )

    assert failures == []
    assert len(findings) == 1
    assert findings[0]["entity"] == "Team A"
    assert findings[0]["parent_project"] == (
        "Product A"
    )
    assert findings[0]["rollup_key"] == (
        "Product A|1|Service|2|openssl|"
        "3.0.1|CVE-2026-0001"
    )
