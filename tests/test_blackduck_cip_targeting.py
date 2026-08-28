from __future__ import annotations

from wintermute.blackduck.jobs.cip.config import (
    CipTarget,
)
from wintermute.blackduck.jobs.cip.targeting import (
    load_target_candidates,
)


BASE_URL = "https://blackduck.example.invalid"
PROJECT_VERSION = (
    f"{BASE_URL}/api/projects/p/versions/v"
)
COMPONENT_VERSION = (
    f"{BASE_URL}/api/components/c/versions/cv"
)
REMEDIATION = (
    f"{PROJECT_VERSION}/components/c/"
    "versions/cv/origins/o/"
    "vulnerabilities/v/remediation"
)
ORIGIN_VULNERABILITIES = (
    f"{BASE_URL}/api/components/c/"
    "versions/cv/origin/o/vulnerabilities"
)


class Cache:
    def __init__(self) -> None:
        self.values = {}

    def get(
        self,
        key: str,
        *,
        max_age_seconds: float = -1,
    ):
        del max_age_seconds
        return self.values.get(key)

    def set(
        self,
        key: str,
        value,
    ) -> None:
        self.values[key] = value


class Client:
    base_url = BASE_URL

    def __init__(self) -> None:
        self.alias_reads = 0

    def get(
        self,
        url: str,
        params=None,
    ):
        if url == PROJECT_VERSION:
            return {
                "versionName": "test",
                "_meta": {
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
                    ]
                },
            }

        if url == (
            f"{PROJECT_VERSION}/"
            "vulnerable-bom-components"
        ):
            offset = int(
                (params or {}).get(
                    "offset",
                    0,
                )
            )
            rows = [
                {
                    "componentName": "Linux Kernel",
                    "componentVersionName": (
                        "6.1.173"
                    ),
                    "componentVersionHref": (
                        COMPONENT_VERSION
                    ),
                    "vulnerability": {
                        "name": (
                            "BDSA-2026-27004"
                        )
                    },
                    "_meta": {
                        "href": REMEDIATION,
                        "links": [
                            {
                                "rel": "vulnerabilities",
                                "href": (
                                    ORIGIN_VULNERABILITIES
                                ),
                            }
                        ],
                    },
                },
                {
                    "componentName": "Other",
                    "componentVersionName": "1",
                    "componentVersionHref": (
                        f"{BASE_URL}/api/"
                        "components/other/versions/1"
                    ),
                },
            ]
            limit = int(
                (params or {}).get(
                    "limit",
                    25,
                )
            )

            return {
                "totalCount": len(rows),
                "items": rows[
                    offset:offset + limit
                ],
            }

        if url == (
            f"{BASE_URL}/api/vulnerabilities/"
            "BDSA-2026-27004"
        ):
            self.alias_reads += 1
            return {
                "name": "BDSA-2026-27004",
                "_meta": {
                    "href": url,
                    "links": [
                        {
                            "rel": (
                                "related-vulnerabilities"
                            ),
                            "href": (
                                f"{BASE_URL}/api/"
                                "vulnerabilities/"
                                "CVE-2026-68446"
                            ),
                        }
                    ],
                },
            }

        if url == ORIGIN_VULNERABILITIES:
            return {
                "totalCount": 0,
                "items": [],
            }

        raise RuntimeError(
            f"Unexpected URL: {url}"
        )


def target() -> CipTarget:
    return CipTarget(
        project_version_href=(
            PROJECT_VERSION
        ),
        component_version_href=(
            COMPONENT_VERSION
        ),
        cip_tag="v6.1.173-cip56",
        cip_branch="linux-6.1.y-cip",
    )


def test_targeting_is_bounded() -> None:
    client = Client()
    result = load_target_candidates(
        client,
        target(),
        start_offset=0,
        page_size=1,
        max_occurrences=1,
        max_candidates=1,
        progress_every=1,
    )

    assert not result.failures
    assert result.scanned_count == 1
    assert result.next_offset == 1
    assert result.total_count == 2
    assert len(result.candidates) == 1
    assert (
        result.candidates[0].cve
        == "CVE-2026-68446"
    )
    assert (
        result.candidates[0]
        .remediation_target
        .resource_href
        == REMEDIATION
    )


def test_alias_cache_avoids_second_read() -> None:
    client = Client()
    cache = Cache()

    first = load_target_candidates(
        client,
        target(),
        page_size=1,
        max_occurrences=1,
        max_candidates=1,
        alias_cache=cache,
        progress_every=10,
    )
    second = load_target_candidates(
        client,
        target(),
        page_size=1,
        max_occurrences=1,
        max_candidates=1,
        alias_cache=cache,
        progress_every=10,
    )

    assert len(first.candidates) == 1
    assert len(second.candidates) == 1
    assert client.alias_reads == 1


def test_cursor_reaches_end_and_wraps() -> None:
    result = load_target_candidates(
        Client(),
        target(),
        start_offset=1,
        page_size=1,
        max_occurrences=1,
        max_candidates=1,
        progress_every=10,
    )

    assert result.scanned_count == 1
    assert result.next_offset == 0
    assert result.wrapped is True
    assert not result.candidates
