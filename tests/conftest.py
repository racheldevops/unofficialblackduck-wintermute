from __future__ import annotations

from collections.abc import Callable

import pytest


@pytest.fixture
def sample_finding_factory() -> Callable[..., dict[str, str]]:
    def factory(**overrides: str) -> dict[str, str]:
        finding = {
            "parent_project": "Parent",
            "parent_version": "1.0",
            "parent_version_href": (
                "https://bd.example/api/projects/"
                "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/versions/"
                "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
            ),
            "subproject_path": "Child/2.0",
            "subproject": "Child",
            "subproject_version": "2.0",
            "subproject_version_href": (
                "https://bd.example/api/projects/"
                "cccccccc-cccc-cccc-cccc-cccccccccccc/versions/"
                "dddddddd-dddd-dddd-dddd-dddddddddddd"
            ),
            "relationship_detection_method": "api-href",
            "component": "library-a",
            "component_version": "1.2.3",
            "component_version_href": (
                "https://bd.example/api/components/component-a/"
                "versions/component-version-a"
            ),
            "vulnerability": "CVE-2026-0001",
            "score_field": "overallScore",
            "score": "9.8",
            "severity": "CRITICAL",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "entity": "Team A",
            "blackduck_url": "https://bd.example/vulnerabilities/CVE-2026-0001",
        }
        finding.update(overrides)

        if "rollup_key" not in overrides:
            finding["rollup_key"] = "|".join(
                [
                    finding["parent_project"],
                    finding["parent_version"],
                    finding["subproject"],
                    finding["subproject_version"],
                    finding["component"],
                    (
                        finding["component_version"]
                        or finding["component_version_href"]
                    ),
                    finding["vulnerability"],
                ]
            )

        return finding

    return factory
