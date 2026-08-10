from __future__ import annotations

from wintermute.scm.coverage.mapping import (
    map_repositories_to_blackduck,
)
from wintermute.scm.coverage.models import (
    BlackDuckInventoryObservation,
    BlackDuckProjectObservation,
    ExplicitMapping,
    MappingConfidence,
    MappingMethod,
)
from wintermute.scm.models import (
    Repository,
    RepositoryInventory,
)


def repository(
    *,
    repository_id: str = "R_service",
    namespace: str = "acme",
    name: str = "service",
) -> Repository:
    return Repository(
        provider="github",
        provider_instance="github.example",
        tenant_id="O_acme",
        repository_id=repository_id,
        namespace=namespace,
        name=name,
        canonical_url=(
            f"https://github.example/"
            f"{namespace}/{name}"
        ),
        visibility="private",
        activity_status="active",
        languages=("python",),
    )


def project(
    project_id: str,
    name: str,
    *,
    metadata: tuple[
        tuple[str, str],
        ...
    ] = (),
) -> BlackDuckProjectObservation:
    return BlackDuckProjectObservation(
        instance_url="https://bd.example",
        project_id=project_id,
        name=name,
        href=(
            "https://bd.example/api/projects/"
            f"{project_id}"
        ),
        metadata=metadata,
    )


def inventory(
    *repositories: Repository,
) -> RepositoryInventory:
    return RepositoryInventory(
        repositories=tuple(repositories),
        exclusions=(),
        failures=(),
        discovered_count=len(repositories),
    )


def blackduck(
    *projects: BlackDuckProjectObservation,
) -> BlackDuckInventoryObservation:
    return BlackDuckInventoryObservation(
        projects=tuple(projects)
    )


def test_provider_repository_id_is_authoritative() -> None:
    source = repository()
    target = project(
        "project-a",
        "Renamed Black Duck project",
        metadata=(
            ("scm_provider", "github"),
            (
                "scm_provider_instance",
                "github.example",
            ),
            (
                "scm_repository_id",
                "R_service",
            ),
        ),
    )
    result = map_repositories_to_blackduck(
        inventory(source),
        blackduck(target),
    )
    mapping = result.mappings[0]

    assert mapping.authoritative is True
    assert mapping.method == (
        MappingMethod.PROVIDER_REPOSITORY_ID
    )
    assert mapping.confidence == (
        MappingConfidence.AUTHORITATIVE
    )
    assert mapping.accepted_project_id == (
        "project-a"
    )


def test_repository_url_is_authoritative() -> None:
    source = repository()
    target = project(
        "project-a",
        "Unrelated display name",
        metadata=(
            (
                "scm_repository_url",
                (
                    "https://github.example/"
                    "acme/service/"
                ),
            ),
        ),
    )
    mapping = map_repositories_to_blackduck(
        inventory(source),
        blackduck(target),
    ).mappings[0]

    assert mapping.authoritative is True
    assert mapping.method == (
        MappingMethod
        .CANONICAL_REPOSITORY_URL
    )


def test_explicit_mapping_is_authoritative() -> None:
    source = repository()
    target = project(
        "project-a",
        "Different name",
    )
    mapping = map_repositories_to_blackduck(
        inventory(source),
        blackduck(target),
        explicit_mappings=(
            ExplicitMapping(
                repository_external_id=(
                    source.external_id
                ),
                blackduck_project_id=(
                    "project-a"
                ),
            ),
        ),
    ).mappings[0]

    assert mapping.authoritative is True
    assert mapping.method == (
        MappingMethod.EXPLICIT
    )


def test_name_match_is_only_a_recommendation() -> None:
    source = repository()
    target = project(
        "project-a",
        "acme/service",
    )
    result = map_repositories_to_blackduck(
        inventory(source),
        blackduck(target),
    )
    mapping = result.mappings[0]

    assert mapping.authoritative is False
    assert mapping.method == (
        MappingMethod.EXACT_NAMESPACE_NAME
    )
    assert mapping.confidence == (
        MappingConfidence.HIGH
    )
    assert mapping.accepted_project_id == ""
    assert result.recommendation_count == 1
    assert result.authoritative_count == 0


def test_disagreeing_authoritative_signals_conflict() -> None:
    source = repository()
    by_id = project(
        "project-a",
        "By ID",
        metadata=(
            ("scm_provider", "github"),
            (
                "scm_provider_instance",
                "github.example",
            ),
            (
                "scm_repository_id",
                "R_service",
            ),
        ),
    )
    by_url = project(
        "project-b",
        "By URL",
        metadata=(
            (
                "scm_repository_url",
                (
                    "https://github.example/"
                    "acme/service"
                ),
            ),
        ),
    )
    result = map_repositories_to_blackduck(
        inventory(source),
        blackduck(by_id, by_url),
    )
    mapping = result.mappings[0]

    assert mapping.authoritative is False
    assert mapping.confidence == (
        MappingConfidence.AMBIGUOUS
    )
    assert result.conflict_count == 1
    assert {
        candidate.project_id
        for candidate in mapping.candidates
    } == {
        "project-a",
        "project-b",
    }


def test_missing_explicit_project_is_rejected() -> None:
    source = repository()
    mapping = map_repositories_to_blackduck(
        inventory(source),
        blackduck(),
        explicit_mappings=(
            ExplicitMapping(
                repository_external_id=(
                    source.external_id
                ),
                blackduck_project_id=(
                    "missing-project"
                ),
            ),
        ),
    ).mappings[0]

    assert mapping.confidence == (
        MappingConfidence.REJECTED
    )
    assert mapping.conflicts


def test_unaccepted_recommendation_leaves_project_orphaned() -> None:
    source = repository()
    target = project(
        "project-a",
        "acme/service",
    )
    result = map_repositories_to_blackduck(
        inventory(source),
        blackduck(target),
    )

    assert [
        value.project_id
        for value
        in result.orphaned_blackduck_projects
    ] == ["project-a"]
