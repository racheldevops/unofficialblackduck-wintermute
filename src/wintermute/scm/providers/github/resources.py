from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from wintermute.scm.models import (
    ScmTenant,
)
from wintermute.scm.providers.github.rest import (
    GitHubRestClient,
    GitHubRestError,
)


RESOURCE_STATUS_OK = "ok"
RESOURCE_STATUS_UNSUPPORTED = "unsupported"
RESOURCE_STATUS_FAILED = "failed"

PLAN_REQUIRED_MARKERS = (
    "upgrade to github",
    "to enable this feature",
)


@dataclass(frozen=True)
class GitHubResourceFailure:
    stage: str
    error: str


@dataclass(frozen=True)
class GitHubResources:
    property_definitions: tuple[
        dict[str, Any],
        ...
    ] = ()
    property_assignments: tuple[
        dict[str, Any],
        ...
    ] = ()
    rulesets: tuple[
        dict[str, Any],
        ...
    ] = ()
    property_status: str = (
        RESOURCE_STATUS_OK
    )
    property_error: str = ""
    ruleset_status: str = (
        RESOURCE_STATUS_OK
    )
    ruleset_error: str = ""
    failures: tuple[
        GitHubResourceFailure,
        ...
    ] = ()


def unsupported_feature_error(
    error: GitHubRestError,
) -> bool:
    if error.category == "not_found":
        return True

    if error.status_code != 403:
        return False

    message = str(error).casefold()

    return all(
        marker in message
        for marker in PLAN_REQUIRED_MARKERS
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


def validate_property_definitions(
    values: Any,
) -> tuple[dict[str, Any], ...]:
    if not isinstance(values, list):
        raise GitHubRestError(
            "invalid_response",
            "GitHub custom property schema "
            "must be a list",
            attempts=1,
        )

    definitions: list[
        dict[str, Any]
    ] = []
    names: set[str] = set()

    for value in values:
        if not isinstance(value, dict):
            raise GitHubRestError(
                "invalid_response",
                "GitHub custom property definition "
                "must be an object",
                attempts=1,
            )

        name = value.get(
            "property_name"
        )

        if (
            not isinstance(name, str)
            or not name
        ):
            raise GitHubRestError(
                "invalid_response",
                "GitHub custom property definition "
                "has no name",
                attempts=1,
            )

        if name in names:
            raise GitHubRestError(
                "invalid_response",
                "GitHub returned duplicate custom "
                f"property definition {name!r}",
                attempts=1,
            )

        names.add(name)
        definitions.append(
            dict(value)
        )

    return tuple(definitions)


def assignment_values(
    assignment: dict[str, Any],
) -> dict[str, Any]:
    properties = assignment.get(
        "properties"
    )

    if not isinstance(properties, list):
        raise GitHubRestError(
            "invalid_response",
            "GitHub repository property assignment "
            "has no properties list",
            attempts=1,
        )

    result: dict[str, Any] = {}

    for value in properties:
        if not isinstance(value, dict):
            raise GitHubRestError(
                "invalid_response",
                "GitHub repository property "
                "must be an object",
                attempts=1,
            )

        name = value.get(
            "property_name"
        )

        if (
            not isinstance(name, str)
            or not name
        ):
            raise GitHubRestError(
                "invalid_response",
                "GitHub repository property "
                "has no name",
                attempts=1,
            )

        if name in result:
            raise GitHubRestError(
                "invalid_response",
                "GitHub returned duplicate repository "
                f"property {name!r}",
                attempts=1,
            )

        result[name] = value.get(
            "value"
        )

    return result


def validate_property_assignments(
    values: list[dict[str, Any]],
    tenant: ScmTenant,
) -> tuple[dict[str, Any], ...]:
    assignments: list[
        dict[str, Any]
    ] = []
    names: set[str] = set()

    for value in values:
        name = value.get(
            "repository_full_name"
        )

        if (
            not isinstance(name, str)
            or name.count("/") != 1
            or name.startswith("/")
            or name.endswith("/")
        ):
            raise GitHubRestError(
                "invalid_response",
                "GitHub property assignment has no "
                "valid repository_full_name",
                attempts=1,
            )

        owner, _ = name.split(
            "/",
            1,
        )

        if (
            owner.casefold()
            != tenant.namespace.casefold()
        ):
            raise GitHubRestError(
                "invalid_response",
                "GitHub property assignment belongs "
                "to another organization",
                attempts=1,
            )

        key = name.casefold()

        if key in names:
            raise GitHubRestError(
                "invalid_response",
                "GitHub returned duplicate property "
                f"assignment for {name!r}",
                attempts=1,
            )

        assignment_values(value)
        names.add(key)
        assignments.append(
            dict(value)
        )

    return tuple(assignments)


def validate_ruleset_summary(
    value: dict[str, Any],
) -> tuple[int, str]:
    ruleset_id = value.get("id")
    name = value.get("name")

    if (
        type(ruleset_id) is not int
        or ruleset_id <= 0
    ):
        raise GitHubRestError(
            "invalid_response",
            "GitHub ruleset summary has no valid ID",
            attempts=1,
        )

    if (
        not isinstance(name, str)
        or not name
    ):
        raise GitHubRestError(
            "invalid_response",
            "GitHub ruleset summary has no name",
            attempts=1,
        )

    return ruleset_id, name


def read_github_resources(
    client: GitHubRestClient,
    tenant: ScmTenant,
) -> GitHubResources:
    validate_tenant(
        client,
        tenant,
    )
    definitions: tuple[
        dict[str, Any],
        ...
    ] = ()
    assignments: tuple[
        dict[str, Any],
        ...
    ] = ()
    rulesets: tuple[
        dict[str, Any],
        ...
    ] = ()
    property_status = RESOURCE_STATUS_OK
    property_error = ""
    ruleset_status = RESOURCE_STATUS_OK
    ruleset_error = ""
    failures: list[
        GitHubResourceFailure
    ] = []

    schema_path = client.organization_path(
        tenant.namespace,
        "properties/schema",
    )
    values_path = client.organization_path(
        tenant.namespace,
        "properties/values",
    )

    try:
        definitions = (
            validate_property_definitions(
                client.get_json(
                    schema_path
                )
            )
        )
        assignments = (
            validate_property_assignments(
                client.paged_list(
                    values_path
                ),
                tenant,
            )
        )
    except GitHubRestError as error:
        property_error = str(error)

        if unsupported_feature_error(error):
            property_status = (
                RESOURCE_STATUS_UNSUPPORTED
            )
        else:
            property_status = (
                RESOURCE_STATUS_FAILED
            )
            failures.append(
                GitHubResourceFailure(
                    stage=(
                        "read-custom-properties"
                    ),
                    error=str(error),
                )
            )

    rulesets_path = client.organization_path(
        tenant.namespace,
        "rulesets",
    )

    try:
        summaries = client.paged_list(
            rulesets_path,
            params={
                "includes_parents": "false",
            },
        )
        selected_rulesets: list[
            dict[str, Any]
        ] = []
        seen_ids: set[int] = set()

        for summary in summaries:
            ruleset_id, _ = (
                validate_ruleset_summary(
                    summary
                )
            )

            if ruleset_id in seen_ids:
                raise GitHubRestError(
                    "invalid_response",
                    "GitHub returned a duplicate "
                    "ruleset ID",
                    attempts=1,
                )

            seen_ids.add(ruleset_id)
            detail = client.get_json(
                f"{rulesets_path}/{ruleset_id}"
            )

            if not isinstance(detail, dict):
                raise GitHubRestError(
                    "invalid_response",
                    "GitHub ruleset detail must "
                    "be an object",
                    attempts=1,
                )

            if detail.get("id") != ruleset_id:
                raise GitHubRestError(
                    "invalid_response",
                    "GitHub returned a different "
                    "ruleset ID",
                    attempts=1,
                )

            selected_rulesets.append(
                dict(detail)
            )

        rulesets = tuple(
            selected_rulesets
        )

    except GitHubRestError as error:
        ruleset_error = str(error)

        if unsupported_feature_error(error):
            ruleset_status = (
                RESOURCE_STATUS_UNSUPPORTED
            )
        else:
            ruleset_status = (
                RESOURCE_STATUS_FAILED
            )
            failures.append(
                GitHubResourceFailure(
                    stage="read-rulesets",
                    error=str(error),
                )
            )

    return GitHubResources(
        property_definitions=definitions,
        property_assignments=assignments,
        rulesets=rulesets,
        property_status=property_status,
        property_error=property_error,
        ruleset_status=ruleset_status,
        ruleset_error=ruleset_error,
        failures=tuple(failures),
    )
