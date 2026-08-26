from __future__ import annotations

from typing import Any

from wintermute.scm.controls import (
    ControlInventory,
)
from wintermute.scm.evidence import (
    EvidenceFailure,
    EvidenceInventory,
    EvidenceKind,
    EvidenceObservation,
    EvidenceScope,
    canonical_value,
    merge_evidence_inventories,
)
from wintermute.scm.models import (
    RepositoryInventory,
    ScmTenant,
)
from wintermute.scm.observations import (
    ScmObservationResult,
)
from wintermute.scm.providers.github.controls import (
    GitHubControlSettings,
    controls_from_resources,
)
from wintermute.scm.providers.github.resources import (
    GitHubResources,
    assignment_values,
    read_github_resources,
)
from wintermute.scm.providers.github.rest import (
    GitHubRestClient,
)
from wintermute.scm.providers.github.workflows import (
    collect_repository_evidence,
)


def repository_external_ids(
    inventory: RepositoryInventory,
) -> dict[str, str]:
    repositories = [
        *inventory.repositories,
        *(
            exclusion.repository
            for exclusion
            in inventory.exclusions
        ),
    ]

    return {
        repository.name_with_owner.casefold(): (
            repository.external_id
        )
        for repository in repositories
    }


def rule_types(
    ruleset: dict[str, Any],
) -> list[str]:
    rules = ruleset.get("rules")

    if not isinstance(rules, list):
        return []

    return sorted(
        {
            str(rule.get("type") or "")
            for rule in rules
            if (
                isinstance(rule, dict)
                and str(
                    rule.get("type") or ""
                )
            )
        }
    )


def required_workflows(
    ruleset: dict[str, Any],
) -> list[dict[str, Any]]:
    values: list[
        dict[str, Any]
    ] = []
    rules = ruleset.get("rules")

    if not isinstance(rules, list):
        return values

    for rule in rules:
        if (
            not isinstance(rule, dict)
            or rule.get("type")
            != "workflows"
        ):
            continue

        parameters = rule.get(
            "parameters"
        )

        if not isinstance(
            parameters,
            dict,
        ):
            continue

        workflows = parameters.get(
            "workflows"
        )

        if not isinstance(
            workflows,
            list,
        ):
            continue

        values.extend(
            dict(workflow)
            for workflow in workflows
            if isinstance(workflow, dict)
        )

    return values


def evidence_from_resources(
    tenant: ScmTenant,
    inventory: RepositoryInventory,
    resources: GitHubResources,
) -> EvidenceInventory:
    observations: list[
        EvidenceObservation
    ] = []
    repository_ids = (
        repository_external_ids(
            inventory
        )
    )

    for definition in (
        resources.property_definitions
    ):
        name = str(
            definition.get(
                "property_name"
            )
            or ""
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
                    .CUSTOM_PROPERTY_DEFINITION
                ),
                scope=EvidenceScope.TENANT,
                key=name,
                source=(
                    "github-custom-property-schema"
                ),
                provider_resource_id=name,
                attributes=(
                    (
                        "value_type",
                        str(
                            definition.get(
                                "value_type"
                            )
                            or ""
                        ),
                    ),
                    (
                        "required",
                        canonical_value(
                            definition.get(
                                "required"
                            )
                        ),
                    ),
                    (
                        "default_value",
                        canonical_value(
                            definition.get(
                                "default_value"
                            )
                        ),
                    ),
                    (
                        "allowed_values",
                        canonical_value(
                            definition.get(
                                "allowed_values",
                                [],
                            )
                        ),
                    ),
                    (
                        "description",
                        str(
                            definition.get(
                                "description"
                            )
                            or ""
                        ),
                    ),
                ),
            )
        )

    for assignment in (
        resources.property_assignments
    ):
        name_with_owner = str(
            assignment.get(
                "repository_full_name"
            )
            or ""
        )
        external_id = repository_ids.get(
            name_with_owner.casefold(),
            "",
        )

        for name, value in sorted(
            assignment_values(
                assignment
            ).items()
        ):
            observations.append(
                EvidenceObservation(
                    provider="github",
                    provider_instance=(
                        tenant.provider_instance
                    ),
                    tenant_id=(
                        tenant.tenant_id
                    ),
                    kind=(
                        EvidenceKind
                        .REPOSITORY_CUSTOM_PROPERTY
                    ),
                    scope=(
                        EvidenceScope.REPOSITORY
                    ),
                    key=name,
                    source=(
                        "github-custom-property-value"
                    ),
                    repository_external_id=(
                        external_id
                    ),
                    name_with_owner=(
                        name_with_owner
                    ),
                    attributes=(
                        (
                            "value",
                            canonical_value(value),
                        ),
                    ),
                )
            )

    for ruleset in resources.rulesets:
        ruleset_id = str(
            ruleset.get("id") or ""
        )
        name = str(
            ruleset.get("name") or ""
        )
        conditions = ruleset.get(
            "conditions",
            {},
        )
        rules = ruleset.get(
            "rules",
            [],
        )
        bypass_actors = ruleset.get(
            "bypass_actors",
            [],
        )

        observations.append(
            EvidenceObservation(
                provider="github",
                provider_instance=(
                    tenant.provider_instance
                ),
                tenant_id=tenant.tenant_id,
                kind=(
                    EvidenceKind.BRANCH_RULESET
                ),
                scope=EvidenceScope.TENANT,
                key=ruleset_id,
                source="github-ruleset",
                provider_resource_id=(
                    ruleset_id
                ),
                attributes=(
                    ("name", name),
                    (
                        "target",
                        str(
                            ruleset.get(
                                "target"
                            )
                            or ""
                        ),
                    ),
                    (
                        "enforcement",
                        str(
                            ruleset.get(
                                "enforcement"
                            )
                            or ""
                        ),
                    ),
                    (
                        "rule_types",
                        canonical_value(
                            rule_types(ruleset)
                        ),
                    ),
                    (
                        "conditions",
                        canonical_value(
                            conditions
                        ),
                    ),
                    (
                        "rules",
                        canonical_value(
                            rules
                        ),
                    ),
                    (
                        "bypass_actors",
                        canonical_value(
                            bypass_actors
                        ),
                    ),
                ),
            )
        )

        for index, workflow in enumerate(
            required_workflows(ruleset)
        ):
            repository_id = str(
                workflow.get(
                    "repository_id"
                )
                or ""
            )
            path = str(
                workflow.get("path")
                or ""
            )
            reference = str(
                workflow.get("ref")
                or ""
            )
            key = "|".join(
                (
                    ruleset_id,
                    repository_id,
                    path,
                    reference,
                    str(index),
                )
            )
            observations.append(
                EvidenceObservation(
                    provider="github",
                    provider_instance=(
                        tenant.provider_instance
                    ),
                    tenant_id=(
                        tenant.tenant_id
                    ),
                    kind=(
                        EvidenceKind
                        .REQUIRED_WORKFLOW_REFERENCE
                    ),
                    scope=(
                        EvidenceScope.TENANT
                    ),
                    key=key,
                    source=(
                        "github-ruleset-workflow"
                    ),
                    provider_resource_id=(
                        ruleset_id
                    ),
                    attributes=(
                        (
                            "ruleset_name",
                            name,
                        ),
                        (
                            "repository_id",
                            repository_id,
                        ),
                        ("path", path),
                        ("ref", reference),
                    ),
                )
            )

    failures = tuple(
        EvidenceFailure(
            provider="github",
            provider_instance=(
                tenant.provider_instance
            ),
            tenant_id=tenant.tenant_id,
            stage=failure.stage,
            error=failure.error,
        )
        for failure in resources.failures
    )

    return EvidenceInventory(
        observations=tuple(
            observations
        ),
        failures=failures,
    )


class GitHubObservationProvider:
    provider = "github"

    def __init__(
        self,
        client: GitHubRestClient,
        *,
        control_settings: (
            GitHubControlSettings | None
        ) = None,
        workers: int = 4,
    ) -> None:
        self.client = client
        self.provider_instance = (
            client.provider_instance
        )
        self.control_settings = (
            control_settings
            or GitHubControlSettings()
        )

        if workers < 1:
            raise ValueError(
                "GitHub evidence workers must be positive"
            )

        self.workers = workers

    def observe(
        self,
        tenant: ScmTenant,
        inventory: RepositoryInventory,
    ) -> ScmObservationResult:
        resources = read_github_resources(
            self.client,
            tenant,
        )
        organization_evidence = (
            evidence_from_resources(
                tenant,
                inventory,
                resources,
            )
        )
        repository_evidence = (
            collect_repository_evidence(
                self.client,
                tenant,
                inventory,
                workers=self.workers,
            )
        )
        evidence = merge_evidence_inventories(
            (
                organization_evidence,
                repository_evidence,
            )
        )
        controls: ControlInventory = (
            controls_from_resources(
                tenant,
                inventory,
                resources,
                self.control_settings,
            )
        )

        return ScmObservationResult(
            evidence=evidence,
            controls=controls,
        )
