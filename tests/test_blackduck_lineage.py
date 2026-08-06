from __future__ import annotations

from typing import Any

from wintermute.blackduck.lineage import (
    build_project_version_indexes,
    discover_lineage_contexts,
    extract_project_version_hrefs,
    lineage_context_to_row,
    project_href_from_version_href,
)
from wintermute.blackduck.models import ProjectVersionRef


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

PARENT_HREF = (
    f"https://bd.example/api/projects/{PARENT_PROJECT_ID}"
    f"/versions/{PARENT_VERSION_ID}"
)
CHILD_HREF = (
    f"https://bd.example/api/projects/{CHILD_PROJECT_ID}"
    f"/versions/{CHILD_VERSION_ID}"
)


class Client:
    base_url = "https://bd.example"

    def get(self, href: str) -> dict[str, Any]:
        if href == (
            f"https://bd.example/api/projects/"
            f"{CHILD_PROJECT_ID}"
        ):
            return {"name": "Child"}

        if href == CHILD_HREF:
            return {
                "versionName": "2.0",
                "phase": "RELEASED",
                "_meta": {"href": CHILD_HREF},
            }

        raise RuntimeError(f"Unexpected GET: {href}")

    def paged_get(
        self,
        href: str,
    ) -> list[dict[str, Any]]:
        raise RuntimeError(f"Unexpected paged GET: {href}")


def project_version(
    project: str,
    version: str,
    href: str,
) -> ProjectVersionRef:
    return ProjectVersionRef(
        instance_url="https://bd.example",
        project=project,
        version=version,
        project_href=href.rsplit(
            "/versions/",
            1,
        )[0],
        version_href=href,
        phase="RELEASED",
    )


def test_extracts_project_version_hrefs() -> None:
    raw = f"{CHILD_HREF}?ignored=true#fragment"

    assert extract_project_version_hrefs(
        raw,
        "https://bd.example",
    ) == [CHILD_HREF]
    assert project_href_from_version_href(
        CHILD_HREF
    ) == (
        f"https://bd.example/api/projects/"
        f"{CHILD_PROJECT_ID}"
    )


def test_builds_lineage_indexes() -> None:
    parent = project_version(
        "Parent",
        "1.0",
        PARENT_HREF,
    )
    child = project_version(
        "Child",
        "2.0",
        CHILD_HREF,
    )

    by_href, by_name = build_project_version_indexes(
        [parent, child]
    )

    assert by_href[CHILD_HREF] == child
    assert by_name[("Child", "2.0")] == [child]


def test_discovers_api_href_lineage() -> None:
    parent = project_version(
        "Parent",
        "1.0",
        PARENT_HREF,
    )
    child = project_version(
        "Child",
        "2.0",
        CHILD_HREF,
    )
    contexts = discover_lineage_contexts(
        Client(),
        parent,
        {
            PARENT_HREF: parent,
            CHILD_HREF: child,
        },
        {
            ("Parent", "1.0"): [parent],
            ("Child", "2.0"): [child],
        },
        resolve_bom_names=True,
        bom_loader=lambda client, current: [
            {
                "componentName": "Child",
                "componentVersionName": "2.0",
                "_meta": {
                    "links": [
                        {
                            "rel": "project-version",
                            "href": CHILD_HREF,
                        }
                    ]
                },
            }
        ],
    )

    assert len(contexts) == 1
    row = lineage_context_to_row(contexts[0])

    assert row["parent_project"] == "Parent"
    assert row["child_project"] == "Child"
    assert row["child_version_href"] == CHILD_HREF
    assert row["detection_method"] == "api-href"


def test_discovers_name_fallback_lineage() -> None:
    parent = project_version(
        "Parent",
        "1.0",
        PARENT_HREF,
    )
    child = project_version(
        "Child",
        "2.0",
        CHILD_HREF,
    )
    contexts = discover_lineage_contexts(
        Client(),
        parent,
        {
            PARENT_HREF: parent,
            CHILD_HREF: child,
        },
        {
            ("Parent", "1.0"): [parent],
            ("Child", "2.0"): [child],
        },
        resolve_bom_names=True,
        bom_loader=lambda client, current: [
            {
                "componentName": "Child",
                "componentVersionName": "2.0",
            }
        ],
    )

    assert len(contexts) == 1
    assert contexts[0].detection_method == (
        "bom-component-name-version"
    )


def test_same_child_is_collected_once_per_parent() -> None:
    parent = project_version(
        "Parent",
        "1.0",
        PARENT_HREF,
    )
    child = project_version(
        "Child",
        "2.0",
        CHILD_HREF,
    )
    component = {
        "componentName": "Child",
        "componentVersionName": "2.0",
        "_meta": {
            "links": [
                {
                    "rel": "project-version",
                    "href": CHILD_HREF,
                },
                {
                    "rel": "duplicate-project-version",
                    "href": CHILD_HREF,
                },
            ]
        },
    }

    contexts = discover_lineage_contexts(
        Client(),
        parent,
        {
            PARENT_HREF: parent,
            CHILD_HREF: child,
        },
        {
            ("Child", "2.0"): [child],
        },
        resolve_bom_names=True,
        bom_loader=lambda client, current: [component],
    )

    assert len(contexts) == 1
