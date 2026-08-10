from __future__ import annotations

from wintermute.blackduck.inventory import (
    InventoryItem,
    InventoryResult,
)
from wintermute.blackduck.models import (
    ProjectVersionRef,
)
from wintermute.scm.coverage.blackduck import (
    observe_blackduck_inventory,
)


PROJECT_HREF = (
    "https://bd.example/api/projects/project-a"
)


def item(
    version_id: str,
    version_name: str,
) -> InventoryItem:
    project_resource = {
        "name": "Service A",
        "scm_provider": "github",
        "scm_provider_instance": (
            "github.example"
        ),
        "scm_repository_id": "R_service",
        "scm_repository_url": (
            "https://github.example/acme/service"
        ),
        "_meta": {
            "href": PROJECT_HREF,
        },
    }
    version_href = (
        f"{PROJECT_HREF}/versions/{version_id}"
    )

    return InventoryItem(
        project_resource=project_resource,
        version_resource={
            "versionName": version_name,
            "_meta": {
                "href": version_href,
            },
        },
        project_version=ProjectVersionRef(
            instance_url="https://bd.example",
            project="Service A",
            version=version_name,
            project_href=PROJECT_HREF,
            version_href=version_href,
            phase="RELEASED",
            updated="2026-08-01T00:00:00Z",
        ),
        created="2026-01-01T00:00:00Z",
    )


def test_blackduck_versions_aggregate_by_project() -> None:
    observation = observe_blackduck_inventory(
        InventoryResult(
            items=(
                item("version-1", "1.0"),
                item("version-2", "2.0"),
            ),
            failures=(),
            selected_project_count=1,
        )
    )

    assert len(observation.projects) == 1
    project = observation.projects[0]

    assert project.project_id == "project-a"
    assert [
        version.version_id
        for version in project.versions
    ] == [
        "version-1",
        "version-2",
    ]
    assert project.metadata_value(
        "scm_repository_id"
    ) == "R_service"


def test_registration_does_not_imply_scan() -> None:
    observation = observe_blackduck_inventory(
        InventoryResult(
            items=(item("version-1", "1.0"),),
            failures=(),
            selected_project_count=1,
        )
    )
    version = (
        observation.projects[0]
        .versions[0]
    )

    assert version.registration_exists is True
    assert version.bom_exists is None
    assert version.code_location_count is None
    assert version.last_successful_scan_at == ""
    assert version.successful_scan_known is False


def test_malformed_project_isolated_as_failure() -> None:
    value = item("version-1", "1.0")
    malformed = InventoryItem(
        project_resource=value.project_resource,
        version_resource=value.version_resource,
        project_version=ProjectVersionRef(
            instance_url="https://bd.example",
            project="Broken",
            version="1.0",
            project_href="https://bd.example/not-project",
            version_href=(
                "https://bd.example/not-version"
            ),
        ),
    )
    observation = observe_blackduck_inventory(
        InventoryResult(
            items=(value, malformed),
            failures=(),
            selected_project_count=2,
        )
    )

    assert len(observation.projects) == 1
    assert len(observation.failures) == 1
    assert observation.failures[0].stage == (
        "normalize-blackduck-inventory"
    )
