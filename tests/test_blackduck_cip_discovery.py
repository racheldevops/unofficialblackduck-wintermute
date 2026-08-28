from __future__ import annotations

from wintermute.blackduck.jobs.cip.discover import (
    ProjectVersion,
    branch_from_value,
    inspect_version,
    normalized_version,
    suggested_tag,
    tag_parts,
)


BASE_URL = "https://blackduck.example.invalid"
PROJECT_VERSION_HREF = (
    f"{BASE_URL}/api/projects/p/versions/v"
)
COMPONENT_VERSION_HREF = (
    f"{BASE_URL}/api/components/c/versions/cv"
)


class Client:
    base_url = BASE_URL

    def paged_get(
        self,
        url: str,
    ):
        assert url == (
            f"{PROJECT_VERSION_HREF}/"
            "vulnerable-bom-components"
        )

        return [
            {
                "componentName": "Linux Kernel",
                "componentVersionName": "6.1.173",
                "componentVersionHref": (
                    COMPONENT_VERSION_HREF
                ),
                "_meta": {
                    "href": (
                        f"{PROJECT_VERSION_HREF}/"
                        "components/bom"
                    )
                },
            },
            {
                "componentName": "OpenSSL",
                "componentVersionName": "3.0.0",
                "componentVersionHref": (
                    f"{BASE_URL}/api/components/o/"
                    "versions/ov"
                ),
            },
        ]


def test_tag_parts() -> None:
    assert tag_parts(
        "v6.1.173-cip56"
    ) == (
        "v6.1.173-cip56",
        "6.1.173",
        "6.1",
    )


def test_version_normalization() -> None:
    assert normalized_version(
        "v6.1.173+cip56"
    ) == "6.1.173-cip56"


def test_branch_from_value() -> None:
    assert branch_from_value(
        "v6.1.173-cip56"
    ) == "linux-6.1.y-cip"


def test_suggested_tag() -> None:
    assert suggested_tag(
        "6.1.173",
        "v6.1.173-cip56",
    ) == "v6.1.173-cip56"


def test_discovery_matches_upstream_version() -> None:
    result = inspect_version(
        Client(),
        ProjectVersion(
            project="Firmware",
            project_version="release-1",
            project_version_href=(
                PROJECT_VERSION_HREF
            ),
            project_href=(
                f"{BASE_URL}/api/projects/p"
            ),
        ),
        component_name_contains="linux",
        requested_tag="v6.1.173-cip56",
        requested_branch="",
    )

    assert not result.failures
    assert len(result.candidates) == 1
    candidate = result.candidates[0]

    assert candidate.complete
    assert (
        candidate.component_version
        == "6.1.173"
    )
    assert (
        candidate.cip_tag
        == "v6.1.173-cip56"
    )
    assert (
        candidate.cip_branch
        == "linux-6.1.y-cip"
    )
    assert (
        candidate.environment[
            "WINTERMUTE_CIP_PROJECT_VERSION_HREF"
        ]
        == PROJECT_VERSION_HREF
    )
