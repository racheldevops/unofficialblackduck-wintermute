from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from wintermute.scm.controls import (
    ControlFailure,
    ControlInventory,
    ControlKind,
    ControlObservation,
    ControlState,
)
from wintermute.scm.models import (
    Repository,
    RepositoryInventory,
    ScmTenant,
)
from wintermute.scm.providers.github.resources import (
    RESOURCE_STATUS_FAILED,
    RESOURCE_STATUS_OK,
    RESOURCE_STATUS_UNSUPPORTED,
    GitHubResources,
    assignment_values,
    read_github_resources,
)
from wintermute.scm.providers.github.rest import (
    GitHubRestClient,
)


PROPERTY_NAME_PATTERN = re.compile(
    r"^[A-Za-z0-9_-]{1,75}$"
)


@dataclass(frozen=True)
class GitHubControlSettings:
    property_name: str = (
        "blackduck_sca_policy"
    )
    onboarding_values: tuple[
        str,
        ...
    ] = ("required",)
    ruleset_name: str = ""

    def __post_init__(self) -> None:
        property_name = str(
            self.property_name or ""
        ).strip()

        if (
            PROPERTY_NAME_PATTERN.fullmatch(
                property_name
            )
            is None
        ):
            raise ValueError(
                "GitHub property_name is invalid"
            )

        values = tuple(
            sorted(
                {
                    str(value).strip()
                    for value
                    in self.onboarding_values
                    if str(value).strip()
                }
            )
        )

        if not values:
            raise ValueError(
                "GitHub onboarding_values must "
                "not be empty"
            )

        object.__setattr__(
            self,
            "property_name",
            property_name,
        )
        object.__setattr__(
            self,
            "onboarding_values",
            values,
        )
        object.__setattr__(
            self,
            "ruleset_name",
            str(
                self.ruleset_name or ""
            ).strip(),
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


def assignments_by_name(
    resources: GitHubResources,
) -> dict[str, dict[str, Any]]:
    return {
        str(
            assignment[
                "repository_full_name"
            ]
        ).casefold(): assignment_values(
            assignment
        )
        for assignment
        in resources.property_assignments
    }


def selected_value(
    value: Any,
    expected: tuple[str, ...],
) -> bool:
    expected_values = set(expected)

    if isinstance(value, list):
        return bool(
            expected_values
            & {
                str(item).strip()
                for item in value
            }
        )

    return (
        str(value or "").strip()
        in expected_values
    )


def rendered_value(
    value: Any,
) -> str:
    if value in (None, "", []):
        return "<unset>"

    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def property_schema_state(
    definitions: tuple[
        dict[str, Any],
        ...
    ],
    settings: GitHubControlSettings,
) -> tuple[bool, str]:
    matches = [
        definition
        for definition in definitions
        if definition.get("property_name")
        == settings.property_name
    ]

    if not matches:
        return (
            False,
            "custom property is not defined",
        )

    if len(matches) > 1:
        return (
            False,
            "duplicate custom property definitions",
        )

    definition = matches[0]
    value_type = str(
        definition.get("value_type") or ""
    )

    if value_type not in {
        "single_select",
        "string",
    }:
        return (
            False,
            f"unsupported property type {value_type!r}",
        )

    if value_type == "single_select":
        allowed_values = definition.get(
            "allowed_values"
        )

        if not isinstance(
            allowed_values,
            list,
        ):
            return (
                False,
                "property allowed values are invalid",
            )

        missing = sorted(
            set(settings.onboarding_values)
            - {
                str(value)
                for value in allowed_values
            }
        )

        if missing:
            return (
                False,
                "property is missing onboarding value(s): "
                + ", ".join(missing),
            )

    return (
        True,
        "custom property is available",
    )


def repository_property_condition(
    ruleset: dict[str, Any],
    settings: GitHubControlSettings,
) -> bool:
    conditions = ruleset.get(
        "conditions"
    )

    if not isinstance(conditions, dict):
        return False

    repository_property = conditions.get(
        "repository_property"
    )

    if not isinstance(
        repository_property,
        dict,
    ):
        return False

    includes = repository_property.get(
        "include"
    )

    if not isinstance(includes, list):
        return False

    for include in includes:
        if not isinstance(include, dict):
            continue

        if (
            include.get("name")
            != settings.property_name
        ):
            continue

        values = include.get(
            "property_values"
        )

        if (
            isinstance(values, list)
            and set(
                settings.onboarding_values
            )
            & {
                str(value)
                for value in values
            }
        ):
            return True

    return False


def has_required_workflow(
    ruleset: dict[str, Any],
) -> bool:
    rules = ruleset.get("rules")

    if not isinstance(rules, list):
        return False

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

        if (
            isinstance(workflows, list)
            and any(
                isinstance(workflow, dict)
                and workflow.get("path")
                and workflow.get(
                    "repository_id"
                )
                for workflow in workflows
            )
        ):
            return True

    return False


def targets_default_branch(
    ruleset: dict[str, Any],
) -> bool:
    conditions = ruleset.get(
        "conditions"
    )

    if not isinstance(conditions, dict):
        return False

    ref_name = conditions.get(
        "ref_name"
    )

    return (
        isinstance(ref_name, dict)
        and isinstance(
            ref_name.get("include"),
            list,
        )
        and "~DEFAULT_BRANCH"
        in ref_name["include"]
    )


def controls_from_resources(
    tenant: ScmTenant,
    inventory: RepositoryInventory,
    resources: GitHubResources,
    settings: GitHubControlSettings,
) -> ControlInventory:
    repositories = all_repositories(
        inventory
    )
    assignments = assignments_by_name(
        resources
    )
    schema_ok = False
    schema_message = ""

    if (
        resources.property_status
        == RESOURCE_STATUS_OK
    ):
        (
            schema_ok,
            schema_message,
        ) = property_schema_state(
            resources.property_definitions,
            settings,
        )

    selected_rulesets = [
        ruleset
        for ruleset in resources.rulesets
        if (
            not settings.ruleset_name
            or ruleset.get("name")
            == settings.ruleset_name
        )
    ]
    matching_rulesets = [
        ruleset
        for ruleset in selected_rulesets
        if repository_property_condition(
            ruleset,
            settings,
        )
    ]
    observed_rulesets = (
        ", ".join(
            sorted(
                {
                    str(
                        ruleset.get("name")
                        or ruleset.get("id")
                        or ""
                    )
                    for ruleset
                    in matching_rulesets
                }
            )
        )
        or "<none>"
    )
    observations: list[
        ControlObservation
    ] = []

    for repository in repositories:
        values = assignments.get(
            repository.name_with_owner
            .casefold(),
            {},
        )
        value = values.get(
            settings.property_name
        )

        if (
            resources.property_status
            == RESOURCE_STATUS_UNSUPPORTED
        ):
            policy_state = (
                ControlState.UNSUPPORTED
            )
            selected = False
            policy_message = (
                resources.property_error
                or "GitHub custom properties are unsupported"
            )
        elif (
            resources.property_status
            == RESOURCE_STATUS_FAILED
        ):
            policy_state = (
                ControlState.FAILED
            )
            selected = False
            policy_message = (
                resources.property_error
            )
        elif not schema_ok:
            policy_state = (
                ControlState.NONCOMPLIANT
            )
            selected = False
            policy_message = schema_message
        else:
            selected = selected_value(
                value,
                settings.onboarding_values,
            )
            policy_state = (
                ControlState.COMPLIANT
                if selected
                else ControlState.NONCOMPLIANT
            )
            policy_message = (
                "repository is selected for onboarding"
                if selected
                else "repository is not selected for onboarding"
            )

        observations.append(
            ControlObservation(
                provider="github",
                provider_instance=(
                    tenant.provider_instance
                ),
                tenant_id=tenant.tenant_id,
                repository_external_id=(
                    repository.external_id
                ),
                name_with_owner=(
                    repository.name_with_owner
                ),
                control=(
                    ControlKind.ONBOARDING_POLICY
                ),
                state=policy_state,
                source=(
                    "github-custom-property"
                ),
                expected=(
                    settings.property_name
                    + "="
                    + "|".join(
                        settings.onboarding_values
                    )
                ),
                observed=rendered_value(
                    value
                ),
                message=policy_message,
            )
        )

        if (
            resources.property_status
            != RESOURCE_STATUS_OK
            or not schema_ok
        ):
            dependent_state = (
                ControlState.UNKNOWN
            )
            dependent_message = (
                "onboarding selection could not "
                "be determined"
            )
        elif not selected:
            dependent_state = (
                ControlState.AVAILABLE
            )
            dependent_message = (
                "control is available but the repository "
                "is not selected for onboarding"
            )
        elif (
            resources.ruleset_status
            == RESOURCE_STATUS_UNSUPPORTED
        ):
            dependent_state = (
                ControlState.UNSUPPORTED
            )
            dependent_message = (
                resources.ruleset_error
                or "GitHub rulesets are unsupported"
            )
        elif (
            resources.ruleset_status
            == RESOURCE_STATUS_FAILED
        ):
            dependent_state = (
                ControlState.FAILED
            )
            dependent_message = (
                resources.ruleset_error
            )
        elif not matching_rulesets:
            dependent_state = (
                ControlState.NONCOMPLIANT
            )
            dependent_message = (
                "no ruleset targets the onboarding property"
            )
        else:
            active_workflow = any(
                str(
                    ruleset.get(
                        "enforcement"
                    )
                    or ""
                )
                == "active"
                and has_required_workflow(
                    ruleset
                )
                for ruleset
                in matching_rulesets
            )
            active_default_branch = any(
                str(
                    ruleset.get(
                        "enforcement"
                    )
                    or ""
                )
                == "active"
                and targets_default_branch(
                    ruleset
                )
                for ruleset
                in matching_rulesets
            )
            workflow_state = (
                ControlState.COMPLIANT
                if active_workflow
                else ControlState.NONCOMPLIANT
            )
            workflow_message = (
                "an active ruleset requires a workflow"
                if active_workflow
                else "no active matching ruleset "
                "requires a workflow"
            )
            branch_state = (
                ControlState.COMPLIANT
                if active_default_branch
                else ControlState.NONCOMPLIANT
            )
            branch_message = (
                "an active ruleset targets the default branch"
                if active_default_branch
                else "no active matching ruleset targets "
                "the default branch"
            )

        if (
            not selected
            or resources.property_status
            != RESOURCE_STATUS_OK
            or not schema_ok
            or resources.ruleset_status
            != RESOURCE_STATUS_OK
            or not matching_rulesets
        ):
            workflow_state = dependent_state
            workflow_message = (
                dependent_message
            )
            branch_state = dependent_state
            branch_message = (
                dependent_message
            )

        observations.extend(
            [
                ControlObservation(
                    provider="github",
                    provider_instance=(
                        tenant.provider_instance
                    ),
                    tenant_id=(
                        tenant.tenant_id
                    ),
                    repository_external_id=(
                        repository.external_id
                    ),
                    name_with_owner=(
                        repository.name_with_owner
                    ),
                    control=(
                        ControlKind
                        .REQUIRED_SCAN_WORKFLOW
                    ),
                    state=workflow_state,
                    source="github-ruleset",
                    expected=(
                        "active required workflow"
                    ),
                    observed=(
                        observed_rulesets
                    ),
                    message=workflow_message,
                ),
                ControlObservation(
                    provider="github",
                    provider_instance=(
                        tenant.provider_instance
                    ),
                    tenant_id=(
                        tenant.tenant_id
                    ),
                    repository_external_id=(
                        repository.external_id
                    ),
                    name_with_owner=(
                        repository.name_with_owner
                    ),
                    control=(
                        ControlKind
                        .PROTECTED_DEFAULT_BRANCH
                    ),
                    state=branch_state,
                    source="github-ruleset",
                    expected=(
                        "active default-branch ruleset"
                    ),
                    observed=(
                        observed_rulesets
                    ),
                    message=branch_message,
                ),
            ]
        )

    failures = tuple(
        ControlFailure(
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

    return ControlInventory(
        observations=tuple(observations),
        failures=failures,
    )


class GitHubControlProvider:
    provider = "github"

    def __init__(
        self,
        client: GitHubRestClient,
        *,
        settings: (
            GitHubControlSettings | None
        ) = None,
    ) -> None:
        self.client = client
        self.provider_instance = (
            client.provider_instance
        )
        self.settings = (
            settings
            or GitHubControlSettings()
        )

    def controls(
        self,
        tenant: ScmTenant,
        inventory: RepositoryInventory,
        *,
        resources: GitHubResources | None = None,
    ) -> ControlInventory:
        selected = (
            resources
            or read_github_resources(
                self.client,
                tenant,
            )
        )

        return controls_from_resources(
            tenant,
            inventory,
            selected,
            self.settings,
        )
