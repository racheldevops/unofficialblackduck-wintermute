from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

import pytest

from wintermute.jira import find_parent_projects
from wintermute.jira import pipeline
from wintermute.jira import subp_vuln_rollup


class NoNetworkClient:
    base_url = "https://bd.example"
    debug = False
    timeout = 30
    retries = 0

    def get(self, href: str) -> dict[str, Any]:
        raise AssertionError(
            f"Unexpected network call: {href}"
        )


def test_parent_inventory_exclusion_is_exact() -> None:
    inventory = [
        find_parent_projects.VersionInfo(
            project_name="foo-bar",
            version_name="1.0.0",
            project_href="https://bd.example/api/projects/one",
            version_href=(
                "https://bd.example/api/projects/one/"
                "versions/version-one"
            ),
        ),
        find_parent_projects.VersionInfo(
            project_name="foo-bar-Other",
            version_name="1.0.0",
            project_href="https://bd.example/api/projects/two",
            version_href=(
                "https://bd.example/api/projects/two/"
                "versions/version-two"
            ),
        ),
    ]

    filtered = (
        find_parent_projects
        .filter_excluded_parent_projects(
            inventory,
            {"foo-bar"},
        )
    )

    assert [
        item.project_name
        for item in filtered
    ] == ["foo-bar-Other"]


def write_relationships(path: Path) -> None:
    fieldnames = [
        "parent_project",
        "parent_version",
        "child_project",
        "child_version",
        "parent_version_href",
        "child_version_href",
        "detection_method",
    ]
    rows = [
        {
            "parent_project": "foo-bar",
            "parent_version": "1.0.0",
            "child_project": "ffoo-bar",
            "child_version": "release/12.00.00",
            "parent_version_href": (
                "https://bd.example/parent/foo"
            ),
            "child_version_href": (
                "https://bd.example/child/ffoo"
            ),
            "detection_method": "api-href",
        },
        {
            "parent_project": "Safe-Parent",
            "parent_version": "1.0.0",
            "child_project": "Safe-Child",
            "child_version": "1.0.0",
            "parent_version_href": (
                "https://bd.example/parent/safe"
            ),
            "child_version_href": (
                "https://bd.example/child/safe"
            ),
            "detection_method": "api-href",
        },
    ]

    with path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as output_file:
        writer = csv.DictWriter(
            output_file,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerows(rows)


@pytest.mark.parametrize(
    (
        "excluded_parents",
        "excluded_children",
    ),
    [
        ({"foo-bar"}, set()),
        (set(), {"ffoo-bar"}),
    ],
)
def test_exclusion_happens_before_network(
    tmp_path: Path,
    excluded_parents: set[str],
    excluded_children: set[str],
) -> None:
    path = tmp_path / "relationships.csv"
    write_relationships(path)
    calls: list[str] = []

    class Client(NoNetworkClient):
        def get(self, href: str) -> dict[str, Any]:
            calls.append(href)

            if href != "https://bd.example/child/safe":
                raise AssertionError(
                    f"Excluded relationship made a network call: {href}"
                )

            return {
                "versionName": "1.0.0",
                "_meta": {"href": href},
            }

    relationships = (
        subp_vuln_rollup
        .load_subproject_refs_from_parent_csv(
            Client(),
            str(path),
            parent_project_filter=None,
            parent_version_filter=None,
            debug=False,
            workers=1,
            excluded_parent_projects=excluded_parents,
            excluded_child_projects=excluded_children,
        )
    )

    assert calls == [
        "https://bd.example/child/safe"
    ]
    assert len(relationships) == 1
    assert (
        relationships[0]["parent_project"]
        == "Safe-Parent"
    )
    assert (
        relationships[0]["project_name"]
        == "Safe-Child"
    )


def test_pipeline_accepts_multiple_exclusions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        [
            "blackduck-jira-pipeline",
            "--exclude-parent-project",
            "foo-bar",
            "--exclude-parent-project",
            "Another-Parent",
            "--exclude-child-project",
            "ffoo-bar",
        ],
    )

    args = pipeline.parse_args()
    pipeline.validate_args(args)

    assert args.exclude_parent_project == [
        "Another-Parent",
        "foo-bar",
    ]
    assert args.exclude_child_project == [
        "ffoo-bar",
    ]
