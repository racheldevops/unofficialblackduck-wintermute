from __future__ import annotations

from typing import Any

from wintermute.blackduck.actions.probe import (
    inspect_target,
    redact_href,
)
from wintermute.blackduck.jobs.cip.config import (
    CipTarget,
)


BASE_URL = "https://blackduck.example.invalid"
PROJECT_VERSION = (
    f"{BASE_URL}/api/projects/"
    "11111111-1111-1111-1111-111111111111/"
    "versions/"
    "22222222-2222-2222-2222-222222222222"
)
COMPONENT_VERSION = (
    f"{BASE_URL}/api/components/"
    "33333333-3333-3333-3333-333333333333/"
    "versions/"
    "44444444-4444-4444-4444-444444444444"
)
BOM_COMPONENT = (
    f"{PROJECT_VERSION}/components/"
    "55555555-5555-5555-5555-555555555555"
)
VULNERABILITIES = (
    f"{BOM_COMPONENT}/vulnerabilities"
)
VULNERABILITY = (
    f"{VULNERABILITIES}/CVE-2026-0001"
)
REMEDIATION = (
    f"{VULNERABILITY}/remediation"
)


class Client:
    base_url = BASE_URL

    def get(
        self,
        url: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if url == PROJECT_VERSION:
            return {
                "versionName": "example",
                "_meta": {
                    "href": PROJECT_VERSION,
                    "links": [
                        {
                            "rel": (
                                "vulnerable-components"
                            ),
                            "href": (
                                f"{PROJECT_VERSION}/"
                                "vulnerable-bom-components"
                            ),
                        }
                    ],
                },
            }

        if url == (
            f"{PROJECT_VERSION}/"
            "vulnerable-bom-components"
        ):
            return {
                "totalCount": 1,
                "items": [
                    {
                        "componentVersionHref": (
                            COMPONENT_VERSION
                        ),
                        "_meta": {
                            "href": BOM_COMPONENT,
                            "links": [
                                {
                                    "rel": (
                                        "vulnerabilities"
                                    ),
                                    "href": (
                                        VULNERABILITIES
                                    ),
                                }
                            ],
                        },
                    }
                ],
            }

        if url == VULNERABILITIES:
            return {
                "totalCount": 1,
                "items": [
                    {
                        "vulnerabilityName": (
                            "CVE-2026-0001"
                        ),
                        "severity": "HIGH",
                        "_meta": {
                            "href": VULNERABILITY,
                            "links": [
                                {
                                    "rel": (
                                        "remediation"
                                    ),
                                    "href": REMEDIATION,
                                    "type": (
                                        "application/"
                                        "vnd.example+json"
                                    ),
                                }
                            ],
                        },
                    }
                ],
            }

        if url == REMEDIATION:
            return {
                "remediationStatus": "NEW",
                "comment": "private analyst text",
                "_meta": {
                    "href": REMEDIATION,
                    "links": [],
                },
            }

        raise RuntimeError(
            f"Unexpected GET: {url}, params={params}"
        )


def test_redact_href() -> None:
    assert redact_href(REMEDIATION) == (
        "<blackduck>/api/projects/{project}/"
        "versions/{version}/components/{component}/"
        "vulnerabilities/{vulnerability}/remediation"
    )


def test_probe_reports_shape_without_comment() -> None:
    result = inspect_target(
        Client(),
        CipTarget(
            project_version_href=(
                PROJECT_VERSION
            ),
            component_version_href=(
                COMPONENT_VERSION
            ),
            cip_tag="v6.1.173-cip56",
            cip_branch="linux-6.1.y-cip",
        ),
    )

    assert result["status"] == "succeeded"
    assert result["matching_occurrence_rows"] == 1

    item = next(
        occurrence
        for occurrence in result["occurrences"]
        if occurrence["remediation"] is not None
    )
    remediation = item["remediation"]

    assert item["cves"] == [
        "CVE-2026-0001"
    ]
    assert remediation["status"] == "NEW"
    assert remediation["comment_present"] is True
    assert remediation["comment_length"] == 20
    assert (
        "private analyst text"
        not in str(result)
    )
