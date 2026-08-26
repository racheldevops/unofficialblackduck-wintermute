from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from wintermute.scm.models import (
    InventoryFailure,
    Repository,
    RepositoryExclusion,
    RepositoryInventory,
)


INVENTORY_SCHEMA_VERSION = 1


def repository_sort_key(
    repository: Repository,
) -> tuple[str, str, str, str]:
    return (
        repository.provider,
        repository.provider_instance,
        repository.name_with_owner.casefold(),
        repository.repository_id,
    )


def repository_payload(
    repository: Repository,
) -> dict[str, Any]:
    return {
        "provider": repository.provider,
        "provider_instance": (
            repository.provider_instance
        ),
        "tenant_id": repository.tenant_id,
        "repository_id": repository.repository_id,
        "identity_key": repository.identity_key,
        "external_id": repository.external_id,
        "namespace": repository.namespace,
        "name": repository.name,
        "name_with_owner": (
            repository.name_with_owner
        ),
        "canonical_url": repository.canonical_url,
        "default_branch": repository.default_branch,
        "head_sha": repository.head_sha,
        "visibility": repository.visibility,
        "archived": repository.archived,
        "fork": repository.fork,
        "template": repository.template,
        "pushed_at": repository.pushed_at,
        "activity_status": (
            repository.activity_status
        ),
        "languages": list(repository.languages),
        "language_bytes": [
            {
                "language": language,
                "bytes": byte_count,
            }
            for language, byte_count
            in repository.language_bytes
        ],
        "language_total_bytes": (
            repository.language_total_bytes
        ),
        "language_data_complete": (
            repository.language_data_complete
        ),
    }


def exclusion_payload(
    exclusion: RepositoryExclusion,
) -> dict[str, Any]:
    return {
        "reason": exclusion.reason,
        "repository": repository_payload(
            exclusion.repository
        ),
    }


def failure_payload(
    failure: InventoryFailure,
) -> dict[str, str]:
    return {
        "provider": failure.provider,
        "provider_instance": (
            failure.provider_instance
        ),
        "tenant_id": failure.tenant_id,
        "repository_id": failure.repository_id,
        "name_with_owner": (
            failure.name_with_owner
        ),
        "stage": failure.stage,
        "error": failure.error,
    }


def inventory_payload(
    inventory: RepositoryInventory,
) -> dict[str, Any]:
    return {
        "schema_version": (
            INVENTORY_SCHEMA_VERSION
        ),
        "discovered_repository_count": (
            inventory.discovered_count
        ),
        "repository_count": (
            inventory.repository_count
        ),
        "exclusion_count": (
            inventory.exclusion_count
        ),
        "failure_count": (
            inventory.failure_count
        ),
        "reconciled": inventory.reconciled,
        "repositories": [
            repository_payload(repository)
            for repository in sorted(
                inventory.repositories,
                key=repository_sort_key,
            )
        ],
        "exclusions": [
            exclusion_payload(exclusion)
            for exclusion in sorted(
                inventory.exclusions,
                key=lambda item: repository_sort_key(
                    item.repository
                ),
            )
        ],
        "failures": [
            failure_payload(failure)
            for failure in sorted(
                inventory.failures,
                key=lambda item: (
                    item.provider,
                    item.provider_instance,
                    item.name_with_owner.casefold(),
                    item.repository_id,
                    item.stage,
                ),
            )
        ],
    }


def merge_inventories(
    inventories: Iterable[RepositoryInventory],
) -> RepositoryInventory:
    repositories: list[Repository] = []
    exclusions: list[RepositoryExclusion] = []
    failures: list[InventoryFailure] = []
    discovered_count = 0
    identities: set[str] = set()

    for inventory in inventories:
        discovered_count += (
            inventory.discovered_count
        )

        for repository in inventory.repositories:
            if repository.external_id in identities:
                raise ValueError(
                    "Duplicate repository identity while "
                    f"merging inventory: "
                    f"{repository.external_id}"
                )

            identities.add(repository.external_id)
            repositories.append(repository)

        for exclusion in inventory.exclusions:
            repository = exclusion.repository

            if repository.external_id in identities:
                raise ValueError(
                    "Duplicate repository identity while "
                    f"merging inventory: "
                    f"{repository.external_id}"
                )

            identities.add(repository.external_id)
            exclusions.append(exclusion)

        failures.extend(inventory.failures)

    return RepositoryInventory(
        repositories=tuple(
            sorted(
                repositories,
                key=repository_sort_key,
            )
        ),
        exclusions=tuple(
            sorted(
                exclusions,
                key=lambda item: repository_sort_key(
                    item.repository
                ),
            )
        ),
        failures=tuple(failures),
        discovered_count=discovered_count,
    )


def _object_list(
    payload: dict[str, Any],
    field: str,
) -> list[dict[str, Any]]:
    values = payload.get(field)

    if not isinstance(values, list):
        raise ValueError(
            f"Inventory field {field!r} must be a list"
        )

    if not all(
        isinstance(value, dict)
        for value in values
    ):
        raise ValueError(
            f"Inventory field {field!r} must contain objects"
        )

    return [
        dict(value)
        for value in values
    ]


def repository_from_payload(
    payload: dict[str, Any],
) -> Repository:
    languages = payload.get("languages")

    if not isinstance(languages, list):
        raise ValueError(
            "Repository languages must be a list"
        )

    raw_language_bytes = payload.get(
        "language_bytes",
        [],
    )

    if (
        not isinstance(raw_language_bytes, list)
        or not all(
            isinstance(value, dict)
            for value in raw_language_bytes
        )
    ):
        raise ValueError(
            "Repository language_bytes must be "
            "a list of objects"
        )

    language_bytes = tuple(
        (
            value.get("language", ""),
            value.get("bytes"),
        )
        for value in raw_language_bytes
    )

    return Repository(
        provider=payload.get("provider", ""),
        provider_instance=payload.get(
            "provider_instance",
            "",
        ),
        tenant_id=payload.get("tenant_id", ""),
        repository_id=payload.get(
            "repository_id",
            "",
        ),
        namespace=payload.get("namespace", ""),
        name=payload.get("name", ""),
        canonical_url=payload.get(
            "canonical_url",
            "",
        ),
        default_branch=payload.get(
            "default_branch",
            "",
        ),
        head_sha=payload.get("head_sha", ""),
        visibility=payload.get(
            "visibility",
            "unknown",
        ),
        archived=payload.get("archived"),
        fork=payload.get("fork"),
        template=payload.get("template"),
        pushed_at=payload.get("pushed_at", ""),
        activity_status=payload.get(
            "activity_status",
            "unknown",
        ),
        languages=tuple(languages),
        language_bytes=language_bytes,
        language_total_bytes=payload.get(
            "language_total_bytes"
        ),
        language_data_complete=payload.get(
            "language_data_complete",
            False,
        ),
    )


def exclusion_from_payload(
    payload: dict[str, Any],
) -> RepositoryExclusion:
    repository = payload.get("repository")

    if not isinstance(repository, dict):
        raise ValueError(
            "Exclusion repository must be an object"
        )

    return RepositoryExclusion(
        repository=repository_from_payload(
            repository
        ),
        reason=payload.get("reason", ""),
    )


def failure_from_payload(
    payload: dict[str, Any],
) -> InventoryFailure:
    return InventoryFailure(
        provider=payload.get("provider", ""),
        provider_instance=payload.get(
            "provider_instance",
            "",
        ),
        tenant_id=payload.get("tenant_id", ""),
        repository_id=payload.get(
            "repository_id",
            "",
        ),
        name_with_owner=payload.get(
            "name_with_owner",
            "",
        ),
        stage=payload.get("stage", ""),
        error=payload.get("error", ""),
    )


def inventory_from_payload(
    payload: dict[str, Any],
) -> RepositoryInventory:
    if not isinstance(payload, dict):
        raise ValueError(
            "Repository inventory must be an object"
        )

    if (
        payload.get("schema_version")
        != INVENTORY_SCHEMA_VERSION
    ):
        raise ValueError(
            "Unsupported repository inventory schema version"
        )

    inventory = RepositoryInventory(
        repositories=tuple(
            repository_from_payload(value)
            for value in _object_list(
                payload,
                "repositories",
            )
        ),
        exclusions=tuple(
            exclusion_from_payload(value)
            for value in _object_list(
                payload,
                "exclusions",
            )
        ),
        failures=tuple(
            failure_from_payload(value)
            for value in _object_list(
                payload,
                "failures",
            )
        ),
        discovered_count=payload.get(
            "discovered_repository_count"
        ),
    )

    expected_counts = {
        "repository_count": (
            inventory.repository_count
        ),
        "exclusion_count": (
            inventory.exclusion_count
        ),
        "failure_count": (
            inventory.failure_count
        ),
    }

    for field, expected in expected_counts.items():
        if (
            field in payload
            and payload[field] != expected
        ):
            raise ValueError(
                f"Inventory field {field!r} does not "
                "match its records"
            )

    if (
        "reconciled" in payload
        and payload["reconciled"]
        is not inventory.reconciled
    ):
        raise ValueError(
            "Inventory reconciliation state does not match"
        )

    return inventory
