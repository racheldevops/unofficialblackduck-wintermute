from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from wintermute.scm.coverage.models import (
    BlackDuckInventoryObservation,
    BlackDuckProjectObservation,
    ExplicitMapping,
    MappingConfidence,
    MappingMethod,
    MappingProjectRef,
    MappingResult,
    RepositoryProjectMapping,
)
from wintermute.scm.models import (
    Repository,
    RepositoryInventory,
    canonical_repository_url,
    normalize_provider_instance,
)


AUTHORITATIVE_METHODS = (
    MappingMethod.PROVIDER_REPOSITORY_ID,
    MappingMethod.CANONICAL_REPOSITORY_URL,
    MappingMethod.EXPLICIT,
)


def project_ref(
    project: BlackDuckProjectObservation,
) -> MappingProjectRef:
    return MappingProjectRef(
        project_id=project.project_id,
        name=project.name,
        href=project.href,
    )


def all_repositories(
    inventory: RepositoryInventory,
) -> tuple[Repository, ...]:
    return tuple(
        sorted(
            [
                *inventory.repositories,
                *(
                    exclusion.repository
                    for exclusion
                    in inventory.exclusions
                ),
            ],
            key=lambda item: (
                item.name_with_owner.casefold(),
                item.repository_id,
            ),
        )
    )


def normalized_project_name(
    value: str,
) -> str:
    return re.sub(
        r"[^a-z0-9]+",
        "-",
        str(value or "").casefold(),
    ).strip("-")


def canonical_metadata_url(
    value: str,
) -> str:
    try:
        return canonical_repository_url(
            value
        )
    except ValueError:
        return ""


def provider_id_matches(
    repository: Repository,
    projects: Iterable[
        BlackDuckProjectObservation
    ],
) -> set[str]:
    matches: set[str] = set()

    for project in projects:
        provider = project.metadata_value(
            "scm_provider"
        ).casefold()
        instance = project.metadata_value(
            "scm_provider_instance"
        )
        repository_id = (
            project.metadata_value(
                "scm_repository_id"
            )
        )

        if (
            provider
            != repository.provider
            or not instance
            or not repository_id
        ):
            continue

        try:
            normalized_instance = (
                normalize_provider_instance(
                    instance
                )
            )
        except ValueError:
            continue

        if (
            normalized_instance
            == repository.provider_instance
            and repository_id
            == repository.repository_id
        ):
            matches.add(
                project.project_id
            )

    return matches


def repository_url_matches(
    repository: Repository,
    projects: Iterable[
        BlackDuckProjectObservation
    ],
) -> set[str]:
    return {
        project.project_id
        for project in projects
        if (
            canonical_metadata_url(
                project.metadata_value(
                    "scm_repository_url"
                )
            )
            == repository.canonical_url
        )
    }


def explicit_matches(
    repository: Repository,
    mappings: Iterable[
        ExplicitMapping
    ],
) -> set[str]:
    return {
        mapping.blackduck_project_id
        for mapping in mappings
        if (
            mapping.repository_external_id
            == repository.external_id
        )
    }


def inferred_matches(
    repository: Repository,
    projects: Iterable[
        BlackDuckProjectObservation
    ],
) -> tuple[
    MappingMethod,
    set[str],
]:
    exact = {
        project.project_id
        for project in projects
        if (
            project.name.casefold()
            == repository.name_with_owner.casefold()
        )
    }

    if exact:
        return (
            MappingMethod.EXACT_NAMESPACE_NAME,
            exact,
        )

    expected = {
        normalized_project_name(
            repository.name_with_owner
        ),
        normalized_project_name(
            f"{repository.namespace}-"
            f"{repository.name}"
        ),
    }
    inferred = {
        project.project_id
        for project in projects
        if normalized_project_name(
            project.name
        )
        in expected
    }

    return (
        MappingMethod.NORMALIZED_PROJECT_NAME,
        inferred,
    )


def mapping_candidates(
    project_ids: set[str],
    projects_by_id: dict[
        str,
        BlackDuckProjectObservation,
    ],
) -> tuple[MappingProjectRef, ...]:
    return tuple(
        project_ref(
            projects_by_id[project_id]
        )
        for project_id
        in sorted(project_ids)
        if project_id in projects_by_id
    )


def map_repository(
    repository: Repository,
    projects: tuple[
        BlackDuckProjectObservation,
        ...
    ],
    projects_by_id: dict[
        str,
        BlackDuckProjectObservation,
    ],
    explicit: tuple[
        ExplicitMapping,
        ...
    ],
) -> RepositoryProjectMapping:
    signals = (
        (
            MappingMethod
            .PROVIDER_REPOSITORY_ID,
            provider_id_matches(
                repository,
                projects,
            ),
        ),
        (
            MappingMethod
            .CANONICAL_REPOSITORY_URL,
            repository_url_matches(
                repository,
                projects,
            ),
        ),
        (
            MappingMethod.EXPLICIT,
            explicit_matches(
                repository,
                explicit,
            ),
        ),
    )
    missing_explicit = {
        project_id
        for method, project_ids
        in signals
        if method == MappingMethod.EXPLICIT
        for project_id in project_ids
        if project_id not in projects_by_id
    }
    authoritative_ids = {
        project_id
        for _, project_ids in signals
        for project_id in project_ids
        if project_id in projects_by_id
    }

    if missing_explicit:
        return RepositoryProjectMapping(
            repository_external_id=(
                repository.external_id
            ),
            name_with_owner=(
                repository.name_with_owner
            ),
            method=MappingMethod.EXPLICIT,
            confidence=(
                MappingConfidence.REJECTED
            ),
            authoritative=False,
            candidates=mapping_candidates(
                authoritative_ids,
                projects_by_id,
            ),
            conflicts=(
                "Explicit mapping references missing "
                "Black Duck project ID(s): "
                + ", ".join(
                    sorted(missing_explicit)
                ),
            ),
        )

    if len(authoritative_ids) > 1:
        signal_text = [
            (
                f"{method.value}="
                + ",".join(
                    sorted(project_ids)
                )
            )
            for method, project_ids
            in signals
            if project_ids
        ]

        return RepositoryProjectMapping(
            repository_external_id=(
                repository.external_id
            ),
            name_with_owner=(
                repository.name_with_owner
            ),
            method=MappingMethod.NONE,
            confidence=(
                MappingConfidence.AMBIGUOUS
            ),
            authoritative=False,
            candidates=mapping_candidates(
                authoritative_ids,
                projects_by_id,
            ),
            conflicts=(
                "Authoritative mapping signals "
                "disagree: "
                + "; ".join(signal_text),
            ),
        )

    if len(authoritative_ids) == 1:
        selected_id = next(
            iter(authoritative_ids)
        )
        selected_method = next(
            method
            for method, project_ids
            in signals
            if selected_id in project_ids
        )

        return RepositoryProjectMapping(
            repository_external_id=(
                repository.external_id
            ),
            name_with_owner=(
                repository.name_with_owner
            ),
            method=selected_method,
            confidence=(
                MappingConfidence.AUTHORITATIVE
            ),
            authoritative=True,
            candidates=mapping_candidates(
                {selected_id},
                projects_by_id,
            ),
        )

    method, inferred_ids = (
        inferred_matches(
            repository,
            projects,
        )
    )

    if len(inferred_ids) > 1:
        return RepositoryProjectMapping(
            repository_external_id=(
                repository.external_id
            ),
            name_with_owner=(
                repository.name_with_owner
            ),
            method=method,
            confidence=(
                MappingConfidence.AMBIGUOUS
            ),
            authoritative=False,
            candidates=mapping_candidates(
                inferred_ids,
                projects_by_id,
            ),
            conflicts=(
                "Naming inference matched multiple "
                "Black Duck projects",
            ),
        )

    if len(inferred_ids) == 1:
        confidence = (
            MappingConfidence.HIGH
            if method
            == MappingMethod
            .EXACT_NAMESPACE_NAME
            else MappingConfidence.INFERRED
        )

        return RepositoryProjectMapping(
            repository_external_id=(
                repository.external_id
            ),
            name_with_owner=(
                repository.name_with_owner
            ),
            method=method,
            confidence=confidence,
            authoritative=False,
            candidates=mapping_candidates(
                inferred_ids,
                projects_by_id,
            ),
        )

    return RepositoryProjectMapping(
        repository_external_id=(
            repository.external_id
        ),
        name_with_owner=(
            repository.name_with_owner
        ),
        method=MappingMethod.NONE,
        confidence=(
            MappingConfidence.INFERRED
        ),
        authoritative=False,
    )


def map_repositories_to_blackduck(
    repositories: RepositoryInventory,
    blackduck: BlackDuckInventoryObservation,
    *,
    explicit_mappings: Iterable[
        ExplicitMapping
    ] = (),
) -> MappingResult:
    projects = tuple(
        blackduck.projects
    )
    projects_by_id = {
        project.project_id: project
        for project in projects
    }
    explicit = tuple(
        explicit_mappings
    )
    mappings = tuple(
        map_repository(
            repository,
            projects,
            projects_by_id,
            explicit,
        )
        for repository
        in all_repositories(
            repositories
        )
    )
    accepted_project_ids = {
        mapping.accepted_project_id
        for mapping in mappings
        if mapping.accepted_project_id
    }
    orphaned = tuple(
        project_ref(project)
        for project in projects
        if (
            project.project_id
            not in accepted_project_ids
        )
    )

    return MappingResult(
        mappings=mappings,
        orphaned_blackduck_projects=(
            orphaned
        ),
    )


def mapping_payload(
    mapping: RepositoryProjectMapping,
) -> dict[str, Any]:
    return {
        "external_id": mapping.external_id,
        "identity_key": mapping.identity_key,
        "repository_external_id": (
            mapping.repository_external_id
        ),
        "name_with_owner": (
            mapping.name_with_owner
        ),
        "method": mapping.method.value,
        "confidence": (
            mapping.confidence.value
        ),
        "authoritative": (
            mapping.authoritative
        ),
        "accepted_project_id": (
            mapping.accepted_project_id
        ),
        "candidates": [
            {
                "project_id": candidate.project_id,
                "name": candidate.name,
                "href": candidate.href,
            }
            for candidate
            in mapping.candidates
        ],
        "conflicts": list(
            mapping.conflicts
        ),
    }


def mapping_result_payload(
    result: MappingResult,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mapping_count": len(
            result.mappings
        ),
        "authoritative_count": (
            result.authoritative_count
        ),
        "recommendation_count": (
            result.recommendation_count
        ),
        "conflict_count": (
            result.conflict_count
        ),
        "unmapped_count": (
            result.unmapped_count
        ),
        "orphaned_blackduck_project_count": (
            len(
                result
                .orphaned_blackduck_projects
            )
        ),
        "mappings": [
            mapping_payload(mapping)
            for mapping in result.mappings
        ],
        "orphaned_blackduck_projects": [
            {
                "project_id": project.project_id,
                "name": project.name,
                "href": project.href,
            }
            for project
            in result.orphaned_blackduck_projects
        ],
    }
