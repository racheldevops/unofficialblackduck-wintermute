from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from wintermute.concurrency import (
    MAX_IO_WORKERS,
    bounded_worker_count,
    ordered_parallel_map,
)
from wintermute.scm.evidence import (
    EvidenceFailure,
    EvidenceInventory,
    EvidenceKind,
    EvidenceObservation,
    EvidenceScope,
    canonical_value,
)
from wintermute.scm.models import (
    Repository,
    RepositoryInventory,
    ScmTenant,
)
from wintermute.scm.providers.github.rest import (
    GitHubRestClient,
    GitHubRestError,
)


@dataclass(frozen=True)
class RepositoryWorkflowResult:
    repository: Repository
    workflows: tuple[
        dict[str, Any],
        ...
    ]
    error: str = ""


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
            key=lambda value: (
                value.name_with_owner.casefold(),
                value.repository_id,
            ),
        )
    )


def validate_tenant(
    client: GitHubRestClient,
    tenant: ScmTenant,
) -> None:
    if tenant.provider != "github":
        raise ValueError(
            "SCM tenant provider does not match GitHub"
        )

    if (
        tenant.provider_instance
        != client.provider_instance
    ):
        raise ValueError(
            "SCM tenant provider instance does not "
            "match GitHub REST"
        )


def language_evidence(
    tenant: ScmTenant,
    repository: Repository,
) -> list[EvidenceObservation]:
    observations = [
        EvidenceObservation(
            provider="github",
            provider_instance=(
                tenant.provider_instance
            ),
            tenant_id=tenant.tenant_id,
            kind=(
                EvidenceKind
                .REPOSITORY_LANGUAGE_INVENTORY
            ),
            scope=EvidenceScope.REPOSITORY,
            key="languages",
            source="github-graphql-languages",
            repository_external_id=(
                repository.external_id
            ),
            name_with_owner=(
                repository.name_with_owner
            ),
            attributes=(
                (
                    "complete",
                    canonical_value(
                        repository
                        .language_data_complete
                    ),
                ),
                (
                    "total_bytes",
                    canonical_value(
                        repository
                        .language_total_bytes
                    ),
                ),
                (
                    "classified_languages",
                    canonical_value(
                        list(
                            repository.languages
                        )
                    ),
                ),
                (
                    "observed_language_count",
                    str(
                        len(
                            repository
                            .language_bytes
                        )
                    ),
                ),
            ),
        )
    ]

    observations.extend(
        EvidenceObservation(
            provider="github",
            provider_instance=(
                tenant.provider_instance
            ),
            tenant_id=tenant.tenant_id,
            kind=(
                EvidenceKind
                .REPOSITORY_LANGUAGE
            ),
            scope=EvidenceScope.REPOSITORY,
            key=language,
            source="github-graphql-languages",
            repository_external_id=(
                repository.external_id
            ),
            name_with_owner=(
                repository.name_with_owner
            ),
            attributes=(
                ("bytes", str(byte_count)),
            ),
        )
        for language, byte_count
        in repository.language_bytes
    )

    return observations


def workflow_observations(
    tenant: ScmTenant,
    result: RepositoryWorkflowResult,
) -> list[EvidenceObservation]:
    repository = result.repository
    status = (
        "failed"
        if result.error
        else "available"
    )
    observations = [
        EvidenceObservation(
            provider="github",
            provider_instance=(
                tenant.provider_instance
            ),
            tenant_id=tenant.tenant_id,
            kind=(
                EvidenceKind
                .REPOSITORY_WORKFLOW_INVENTORY
            ),
            scope=EvidenceScope.REPOSITORY,
            key="actions-workflows",
            source="github-actions-workflows",
            repository_external_id=(
                repository.external_id
            ),
            name_with_owner=(
                repository.name_with_owner
            ),
            attributes=(
                ("status", status),
                (
                    "workflow_count",
                    str(len(result.workflows)),
                ),
                ("error", result.error),
            ),
        )
    ]

    for workflow in result.workflows:
        workflow_id = str(
            workflow.get("id") or ""
        )
        observations.append(
            EvidenceObservation(
                provider="github",
                provider_instance=(
                    tenant.provider_instance
                ),
                tenant_id=tenant.tenant_id,
                kind=(
                    EvidenceKind
                    .REPOSITORY_WORKFLOW
                ),
                scope=(
                    EvidenceScope.REPOSITORY
                ),
                key=workflow_id,
                source=(
                    "github-actions-workflow"
                ),
                provider_resource_id=(
                    workflow_id
                ),
                repository_external_id=(
                    repository.external_id
                ),
                name_with_owner=(
                    repository.name_with_owner
                ),
                attributes=(
                    (
                        "name",
                        str(
                            workflow.get("name")
                            or ""
                        ),
                    ),
                    (
                        "path",
                        str(
                            workflow.get("path")
                            or ""
                        ),
                    ),
                    (
                        "state",
                        str(
                            workflow.get("state")
                            or ""
                        ),
                    ),
                    (
                        "created_at",
                        str(
                            workflow.get(
                                "created_at"
                            )
                            or ""
                        ),
                    ),
                    (
                        "updated_at",
                        str(
                            workflow.get(
                                "updated_at"
                            )
                            or ""
                        ),
                    ),
                    (
                        "url",
                        str(
                            workflow.get("url")
                            or ""
                        ),
                    ),
                    (
                        "html_url",
                        str(
                            workflow.get(
                                "html_url"
                            )
                            or ""
                        ),
                    ),
                ),
            )
        )

    return observations


def collect_repository_evidence(
    client: GitHubRestClient,
    tenant: ScmTenant,
    inventory: RepositoryInventory,
    *,
    workers: int = 4,
) -> EvidenceInventory:
    validate_tenant(
        client,
        tenant,
    )
    repositories = all_repositories(
        inventory
    )
    observations: list[
        EvidenceObservation
    ] = []

    for repository in repositories:
        observations.extend(
            language_evidence(
                tenant,
                repository,
            )
        )

    if not repositories:
        return EvidenceInventory(
            observations=tuple(
                observations
            )
        )

    worker_count = min(
        bounded_worker_count(
            workers,
            maximum=MAX_IO_WORKERS,
        ),
        len(repositories),
    )

    def load(
        repository: Repository,
    ) -> RepositoryWorkflowResult:
        path = client.repository_path(
            repository.namespace,
            repository.name,
            "actions/workflows",
        )

        try:
            workflows = client.paged_workflows(
                path
            )

            return RepositoryWorkflowResult(
                repository=repository,
                workflows=tuple(workflows),
            )
        except GitHubRestError as error:
            return RepositoryWorkflowResult(
                repository=repository,
                workflows=(),
                error=str(error),
            )

    results = ordered_parallel_map(
        repositories,
        load,
        workers=worker_count,
        maximum=MAX_IO_WORKERS,
    )
    failures: list[
        EvidenceFailure
    ] = []

    for result in results:
        observations.extend(
            workflow_observations(
                tenant,
                result,
            )
        )

        if result.error:
            failures.append(
                EvidenceFailure(
                    provider="github",
                    provider_instance=(
                        tenant.provider_instance
                    ),
                    tenant_id=(
                        tenant.tenant_id
                    ),
                    repository_external_id=(
                        result.repository
                        .external_id
                    ),
                    name_with_owner=(
                        result.repository
                        .name_with_owner
                    ),
                    stage=(
                        "read-repository-workflows"
                    ),
                    error=result.error,
                )
            )

    return EvidenceInventory(
        observations=tuple(
            observations
        ),
        failures=tuple(failures),
    )
