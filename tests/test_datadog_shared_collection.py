from __future__ import annotations

import threading
import time
from typing import Any

from wintermute.datadog.collection import (
    candidate_external_id,
    candidate_key,
    collect_candidate_findings,
)
from wintermute.datadog.policy_vuln_pull import (
    PullSettings,
)


VERSION_HREF = (
    "https://bd.example/api/projects/service/"
    "versions/1"
)


def candidate() -> dict[str, str]:
    return {
        "project": "Service A",
        "project_version": "1.0",
        "project_href": (
            "https://bd.example/api/projects/service"
        ),
        "project_version_href": VERSION_HREF,
        "candidate_key": (
            f"Service A|1.0|{VERSION_HREF}"
        ),
        "candidate_external_id": (
            "candidate-a"
        ),
    }


def settings(
    **overrides: Any,
) -> PullSettings:
    values: dict[str, Any] = {
        "base_url": "https://bd.example",
        "api_token": "token",
        "bearer_token": "bearer",
        "insecure": False,
        "timeout": 30,
        "retries": 1,
        "retry_delay": 0.0,
        "page_limit": 100,
        "debug": False,
        "threshold": 8.9,
        "score_operator": "gt",
        "score_field": "overallScore",
        "require_exploit_available": True,
        "require_reachable": False,
        "reachability_mode": "field",
        "policy_name": "",
        "policy_rule_id": "",
        "group_by": "project",
        "skip_policy_rules": False,
        "include_policy_rule_details": False,
        "component_workers": 2,
    }
    values.update(overrides)

    return PullSettings(**values)


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
            return [
                {
                    "componentName": "openssl",
                    "componentVersionName": "3.0.1",
                    "componentOriginId": "origin-a",
                    "_meta": {
                        "href": (
                            "https://bd.example/bom/openssl"
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
                },
                {
                    "componentName": "zlib",
                    "componentVersionName": "1.3",
                    "componentOriginId": "origin-b",
                    "_meta": {
                        "href": (
                            "https://bd.example/bom/zlib"
                        ),
                        "links": [
                            {
                                "rel": "vulnerabilities",
                                "href": (
                                    "https://bd.example/"
                                    "vulnerabilities/zlib"
                                ),
                            }
                        ],
                    },
                },
            ]

        if "/vulnerabilities/" in href:
            with self.lock:
                self.active += 1
                self.max_active = max(
                    self.max_active,
                    self.active,
                )

            try:
                time.sleep(0.03)
                component = href.rsplit("/", 1)[-1]

                return [
                    {
                        "vulnerabilityName": (
                            f"CVE-2026-{component}"
                        ),
                        "overallScore": 9.8,
                        "severity": "CRITICAL",
                        "exploitAvailable": True,
                        "reachable": True,
                        "_meta": {
                            "href": (
                                "https://bd.example/"
                                f"cves/{component}"
                            )
                        },
                    }
                ]
            finally:
                with self.lock:
                    self.active -= 1

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


def test_shared_datadog_collection_preserves_schema_and_ids() -> None:
    client = Client()
    rows, failures = collect_candidate_findings(
        client,
        candidate(),
        settings(component_workers=2),
    )

    assert failures == []
    assert len(rows) == 2
    assert client.max_active > 1
    assert {
        row["component"]
        for row in rows
    } == {"openssl", "zlib"}
    assert all(
        row["candidate_key"]
        == candidate()["candidate_key"]
        for row in rows
    )
    assert all(
        row["candidate_external_id"]
        == "candidate-a"
        for row in rows
    )
    assert all(
        row["project_group_key"]
        == "Service A"
        for row in rows
    )
    assert all(
        row["exploit_available"] == "true"
        for row in rows
    )
    assert all(
        row["reachable"] == "true"
        for row in rows
    )


def test_shared_datadog_collection_applies_score_operator() -> None:
    rows, failures = collect_candidate_findings(
        Client(),
        candidate(),
        settings(
            threshold=9.8,
            score_operator="gt",
        ),
    )

    assert rows == []
    assert failures == []


def test_shared_datadog_collection_maps_failures() -> None:
    rows, failures = collect_candidate_findings(
        FailingClient(),
        candidate(),
        settings(),
    )

    assert rows == []
    assert len(failures) == 1
    assert failures[0] == {
        "project": "Service A",
        "project_version": "1.0",
        "project_version_href": VERSION_HREF,
        "candidate_external_id": "candidate-a",
        "stage": "load-vulnerable-components",
        "error": "temporary Black Duck failure",
    }


def test_candidate_identity_fallback_is_stable() -> None:
    row = {
        "project": "Service A",
        "project_version": "1.0",
        "project_version_href": (
            f"{VERSION_HREF}/"
        ),
    }

    assert candidate_key(row) == (
        f"Service A|1.0|{VERSION_HREF}"
    )
    assert candidate_external_id(row) == (
        candidate_external_id(dict(row))
    )
