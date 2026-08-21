from __future__ import annotations

from typing import Any

from wintermute.scm.controls import (
    ControlState,
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
from wintermute.scm.providers.github.observations import (
    evidence_from_resources,
)
from wintermute.scm.providers.github.resources import (
    RESOURCE_STATUS_FAILED,
    RESOURCE_STATUS_OK,
    RESOURCE_STATUS_UNSUPPORTED,
    read_github_resources,
    unsupported_feature_error,
)
from wintermute.scm.providers.github.rest import (
    GitHubRestError,
)


ORGANIZATION = "Example-Organization"


def tenant() -> ScmTenant:
    return ScmTenant(
        provider="github",
        provider_instance="api.github.com",
        tenant_id="organization-id",
        namespace=ORGANIZATION,
    )


def plan_error() -> GitHubRestError:
    return GitHubRestError(
        "authorization_failed",
        (
            "GET /orgs/Example-Organization/rulesets "
            "failed: HTTP 403 Forbidden: "
            '{"message":"Upgrade to GitHub Team to '
            'enable this feature."}'
        ),
        attempts=1,
        status_code=403,
    )


def permission_error() -> GitHubRestError:
    return GitHubRestError(
        "authorization_failed",
        (
            "GET /orgs/Example-Organization/rulesets "
            "failed: HTTP 403 Forbidden: "
            '{"message":"Resource not accessible by '
            'personal access token"}'
        ),
        attempts=1,
        status_code=403,
    )


class Client:
    provider_instance = "api.github.com"

    def __init__(
        self,
        ruleset_error: GitHubRestError,
    ) -> None:
        self.ruleset_error = ruleset_error

    def organization_path(
        self,
        organization: str,
        suffix: str,
    ) -> str:
        assert organization == ORGANIZATION
        return (
            f"/orgs/{organization}/"
            f"{suffix.lstrip('/')}"
        )

    def get_json(
        self,
        path: str,
        *,
        params: Any = None,
    ) -> Any:
        del params

        if path.endswith(
            "/properties/schema"
        ):
            return [
                {
                    "property_name": (
                        "blackduck_sca_policy"
                    ),
                    "value_type": "single_select",
                    "allowed_values": [
                        "required",
                        "optional",
                    ],
                }
            ]

        raise AssertionError(
            f"Unexpected GET: {path}"
        )

    def paged_list(
        self,
        path: str,
        *,
        params: Any = None,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        del params, page_size

        if path.endswith(
            "/properties/values"
        ):
            return []

        if path.endswith("/rulesets"):
            raise self.ruleset_error

        raise AssertionError(
            f"Unexpected paged GET: {path}"
        )


def test_explicit_plan_limitation_is_unsupported() -> None:
    assert unsupported_feature_error(
        plan_error()
    ) is True


def test_normal_permission_failure_is_not_unsupported() -> None:
    assert unsupported_feature_error(
        permission_error()
    ) is False


def test_not_found_remains_unsupported() -> None:
    error = GitHubRestError(
        "not_found",
        "GET resource returned HTTP 404",
        attempts=1,
        status_code=404,
    )

    assert unsupported_feature_error(error) is True


def test_plan_limited_rulesets_are_not_failures() -> None:
    resources = read_github_resources(
        Client(plan_error()),
        tenant(),
    )

    assert (
        resources.property_status
        == RESOURCE_STATUS_OK
    )
    assert (
        resources.ruleset_status
        == RESOURCE_STATUS_UNSUPPORTED
    )
    assert resources.rulesets == ()
    assert resources.failures == ()


def test_permission_denied_rulesets_remain_failures() -> None:
    resources = read_github_resources(
        Client(permission_error()),
        tenant(),
    )

    assert (
        resources.ruleset_status
        == RESOURCE_STATUS_FAILED
    )
    assert len(resources.failures) == 1
    assert (
        resources.failures[0].stage
        == "read-rulesets"
    )


def test_unsupported_rulesets_do_not_make_snapshot_partial() -> None:
    selected_tenant = tenant()
    inventory = RepositoryInventory(
        repositories=(),
        exclusions=(),
        failures=(),
        discovered_count=0,
    )
    resources = read_github_resources(
        Client(plan_error()),
        selected_tenant,
    )
    evidence = evidence_from_resources(
        selected_tenant,
        inventory,
        resources,
    )
    controls = controls_from_resources(
        selected_tenant,
        inventory,
        resources,
        GitHubControlSettings(),
    )
    observations = ScmObservationResult(
        evidence=evidence,
        controls=controls,
    )

    assert observations.failure_count == 0
    assert evidence.failures == ()
    assert controls.failures == ()


def test_selected_repository_controls_become_unsupported() -> None:
    selected_tenant = tenant()
    resources = read_github_resources(
        Client(plan_error()),
        selected_tenant,
    )

    assert (
        resources.ruleset_status
        == RESOURCE_STATUS_UNSUPPORTED
    )
    assert resources.failures == ()

    assert ControlState.UNSUPPORTED.value == (
        "unsupported"
    )
