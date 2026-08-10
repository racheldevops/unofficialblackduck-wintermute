from __future__ import annotations

from typing import Any
from urllib.parse import unquote, urlsplit

from wintermute.blackduck.custom_fields import (
    find_named_custom_field,
)
from wintermute.blackduck.inventory import (
    InventoryResult,
)
from wintermute.scm.coverage.models import (
    BlackDuckInventoryObservation,
    BlackDuckObservationFailure,
    BlackDuckProjectObservation,
    BlackDuckVersionObservation,
    MappingMetadataFields,
)


def resource_id(
    href: str,
    collection: str,
) -> str:
    path = urlsplit(
        str(href or "")
    ).path
    parts = [
        unquote(part)
        for part in path.split("/")
        if part
    ]

    try:
        index = parts.index(collection)
        value = parts[index + 1]
    except (
        ValueError,
        IndexError,
    ) as error:
        raise ValueError(
            f"Could not extract {collection} ID "
            f"from href: {href!r}"
        ) from error

    if not value:
        raise ValueError(
            f"Empty {collection} ID in href"
        )

    return value


def mapping_metadata(
    project_resource: dict[str, Any],
    fields: MappingMetadataFields,
) -> tuple[tuple[str, str], ...]:
    values: list[
        tuple[str, str]
    ] = []

    for normalized_name, field_name in (
        (
            "scm_provider",
            fields.provider,
        ),
        (
            "scm_provider_instance",
            fields.provider_instance,
        ),
        (
            "scm_repository_id",
            fields.repository_id,
        ),
        (
            "scm_repository_url",
            fields.canonical_url,
        ),
    ):
        found, value = (
            find_named_custom_field(
                project_resource,
                field_name,
            )
        )

        if found and value:
            values.append(
                (
                    normalized_name,
                    value,
                )
            )

    return tuple(values)


def observe_blackduck_inventory(
    inventory: InventoryResult,
    *,
    metadata_fields: (
        MappingMetadataFields | None
    ) = None,
) -> BlackDuckInventoryObservation:
    fields = (
        metadata_fields
        or MappingMetadataFields()
    )
    project_data: dict[
        str,
        dict[str, Any],
    ] = {}
    failures: list[
        BlackDuckObservationFailure
    ] = [
        BlackDuckObservationFailure(
            project=failure.project,
            project_href=(
                failure.project_href
            ),
            stage=failure.stage,
            error=failure.error,
        )
        for failure in inventory.failures
    ]

    for item in inventory.items:
        project = item.project_version
        project_name = project.project
        project_href = project.project_href

        try:
            project_id = resource_id(
                project_href,
                "projects",
            )
            version_id = resource_id(
                project.version_href,
                "versions",
            )
            version = (
                BlackDuckVersionObservation(
                    project_id=project_id,
                    version_id=version_id,
                    name=project.version,
                    href=project.version_href,
                    phase=project.phase,
                    created=item.created,
                    updated=project.updated,
                )
            )
            metadata = mapping_metadata(
                item.project_resource,
                fields,
            )
            existing = project_data.get(
                project_id
            )

            if existing is None:
                project_data[project_id] = {
                    "instance_url": (
                        project.instance_url
                    ),
                    "project_id": project_id,
                    "name": project_name,
                    "href": project_href,
                    "metadata": metadata,
                    "versions": [version],
                }
                continue

            if (
                existing["name"]
                != project_name
                or existing["href"]
                != project_href
                or existing["metadata"]
                != metadata
            ):
                raise ValueError(
                    "Black Duck project metadata changed "
                    "within one inventory"
                )

            existing["versions"].append(
                version
            )

        except (
            TypeError,
            ValueError,
        ) as error:
            failures.append(
                BlackDuckObservationFailure(
                    project=project_name,
                    project_href=(
                        project_href
                    ),
                    stage=(
                        "normalize-blackduck-inventory"
                    ),
                    error=str(error),
                )
            )

    projects = tuple(
        BlackDuckProjectObservation(
            instance_url=value[
                "instance_url"
            ],
            project_id=value[
                "project_id"
            ],
            name=value["name"],
            href=value["href"],
            metadata=value[
                "metadata"
            ],
            versions=tuple(
                value["versions"]
            ),
        )
        for value in sorted(
            project_data.values(),
            key=lambda item: (
                str(item["name"]).casefold(),
                str(item["project_id"]),
            ),
        )
    )

    return BlackDuckInventoryObservation(
        projects=projects,
        failures=tuple(failures),
    )
