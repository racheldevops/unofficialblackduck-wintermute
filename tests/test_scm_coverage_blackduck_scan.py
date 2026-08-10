from __future__ import annotations

from typing import Any

from wintermute.scm.coverage.blackduck_scan import (
    collect_blackduck_scan_evidence,
)
from wintermute.scm.coverage.models import (
    BlackDuckInventoryObservation,
    BlackDuckProjectObservation,
    BlackDuckVersionObservation,
)


PROJECT_HREF = (
    "https://bd.example/api/projects/project-a"
)
VERSION_HREF = (
    f"{PROJECT_HREF}/versions/version-a"
)
BOM_STATUS_HREF = (
    f"{VERSION_HREF}/bom-status"
)
CODE_LOCATIONS_HREF = (
    f"{VERSION_HREF}/codelocations"
)
CODE_LOCATION_HREF = (
    "https://bd.example/api/codelocations/location-a"
)
SCAN_SUMMARIES_HREF = (
    f"{CODE_LOCATION_HREF}/scan-summaries"
)


def inventory() -> BlackDuckInventoryObservation:
    return BlackDuckInventoryObservation(
        projects=(
            BlackDuckProjectObservation(
                instance_url=(
                    "https://bd.example"
                ),
                project_id="project-a",
                name="Service",
                href=PROJECT_HREF,
                versions=(
                    BlackDuckVersionObservation(
                        project_id="project-a",
                        version_id="version-a",
                        name="1.0",
                        href=VERSION_HREF,
                    ),
                ),
            ),
        )
    )


class Client:
    def __init__(
        self,
        *,
        fail_code_locations: bool = False,
        empty_code_locations: bool = False,
    ) -> None:
        self.fail_code_locations = (
            fail_code_locations
        )
        self.empty_code_locations = (
            empty_code_locations
        )

    def clone_for_worker(self) -> Client:
        return self

    def get(
        self,
        href: str,
    ) -> dict[str, Any]:
        if href == VERSION_HREF:
            return {
                "_meta": {
                    "href": VERSION_HREF,
                    "links": [
                        {
                            "rel": "bom-status",
                            "href": (
                                BOM_STATUS_HREF
                            ),
                        },
                        {
                            "rel": "code-locations",
                            "href": (
                                CODE_LOCATIONS_HREF
                            ),
                        },
                    ],
                }
            }

        if href == BOM_STATUS_HREF:
            return {
                "status": "UP_TO_DATE"
            }

        raise AssertionError(
            f"Unexpected GET {href}"
        )

    def paged_get(
        self,
        href: str,
    ) -> list[dict[str, Any]]:
        if href == CODE_LOCATIONS_HREF:
            if self.fail_code_locations:
                raise RuntimeError(
                    "code locations unavailable"
                )

            if self.empty_code_locations:
                return []

            return [
                {
                    "name": "service",
                    "_meta": {
                        "href": (
                            CODE_LOCATION_HREF
                        ),
                        "links": [
                            {
                                "rel": (
                                    "scan-summaries"
                                ),
                                "href": (
                                    SCAN_SUMMARIES_HREF
                                ),
                            }
                        ],
                    },
                }
            ]

        if href == SCAN_SUMMARIES_HREF:
            return [
                {
                    "id": "receipt-a",
                    "status": "COMPLETED",
                    "completedAt": (
                        "2026-08-15T00:00:00Z"
                    ),
                    "scannerType": "detect",
                }
            ]

        raise AssertionError(
            f"Unexpected paged GET {href}"
        )


def test_direct_scan_evidence_records_success() -> None:
    result = collect_blackduck_scan_evidence(
        Client(),
        inventory(),
        workers=2,
    )
    version = (
        result.projects[0].versions[0]
    )

    assert version.bom_exists is True
    assert version.code_location_count == 1
    assert (
        version.last_successful_scan_at
        == "2026-08-15T00:00:00Z"
    )
    assert version.receipt_id == "receipt-a"
    assert version.scanner_type == "detect"
    assert version.scan_source == (
        "blackduck-api"
    )
    assert version.scan_evidence_complete is True
    assert result.failures == ()


def test_zero_code_locations_is_complete_no_scan() -> None:
    result = collect_blackduck_scan_evidence(
        Client(
            empty_code_locations=True
        ),
        inventory(),
    )
    version = (
        result.projects[0].versions[0]
    )

    assert version.code_location_count == 0
    assert version.successful_scan_known is False
    assert version.scan_evidence_complete is True


def test_scan_evidence_failure_is_isolated() -> None:
    result = collect_blackduck_scan_evidence(
        Client(
            fail_code_locations=True
        ),
        inventory(),
    )
    version = (
        result.projects[0].versions[0]
    )

    assert version.scan_evidence_complete is False
    assert len(result.failures) == 1
    assert result.failures[0].stage == (
        "load-code-locations"
    )
