from __future__ import annotations

import dataclasses
from typing import Any

from wintermute.scm.controls import (
    ControlKind,
    ControlState,
)
from wintermute.scm.models import (
    Repository,
    RepositoryInventory,
    ScmTenant,
)
from wintermute.scm.protocols import (
    ScmControlProvider,
)
from wintermute.scm.providers.github.controls import (
    GitHubControlProvider,
    GitHubControlSettings,
)
from wintermute.scm.providers.github.rest import (
    GitHubRestError,
)


def repository(
    repository_id: str,
    name: str,
) -> Repository:
    return Repository(
        provider="github",
        provider_instance="github.example",
        tenant_id="O_acme",
        repository_id=repository_id,
        namespace="acme",
        name=name,
        canonical_url=(
            f"https://github.example/acme/{name}"
        ),
        default_branch="main",
        visibility="private",
        activity_status="active",
        languages=("python",),
    )


def inventory() -> RepositoryInventory:
    return RepositoryInventory(
        repositories=(
            repository(
                "R_service",
                "service",
            ),
            repository(
                "R_review",
                "review",
            ),
        ),
        exclusions=(),
        failures=(),
        discovered_count=2,
    )


def tenant() -> ScmTenant:
    return ScmTenant(
        provider="github",
        provider_instance="github.example",
        tenant_id="O_acme",
        namespace="acme",
    )


class FakeRestClient:
    provider_instance = "github.example"

    def __init__(
        self,
        *,
        ruleset_enforcement: str = "active",
        properties_unsupported: bool = False,
        rulesets_unsupported: bool = False,
    ) -> None:
        self.ruleset_enforcement = (
            ruleset_enforcement
        )
        self.properties_unsupported = (
            properties_unsupported
        )
        self.rulesets_unsupported = (
            rulesets_unsupported
        )

    def organization_path(
        self,
        organization: str,
        suffix: str,
    ) -> str:
        return (
            f"/orgs/{organization}/{suffix}"
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
            if self.properties_unsupported:
                raise GitHubRestError(
                    "not_found",
                    "properties unavailable",
                    attempts=1,
                    status_code=404,
                )

            return [
                {
                    "property_name": (
                        "blackduck_sca_policy"
                    ),
                    "value_type": (
                        "single_select"
                    ),
                    "allowed_values": [
                        "required",
                        "review",
                    ],
                }
            ]

        if path.endswith("/rulesets/42"):
            return {
                "id": 42,
                "name": (
                    "Black Duck SCA Required"
                ),
                "enforcement": (
                    self.ruleset_enforcement
                ),
                "conditions": {
                    "ref_name": {
                        "include": [
                            "~DEFAULT_BRANCH"
                        ],
                        "exclude": [],
                    },
                    "repository_property": {
                        "include": [
                            {
                                "name": (
                                    "blackduck_sca_policy"
                                ),
                                "property_values": [
                                    "required"
                                ],
                            }
                        ],
                        "exclude": [],
                    },
                },
                "rules": [
                    {
                        "type": "workflows",
                        "parameters": {
                            "workflows": [
                                {
                                    "path": (
                                        ".github/workflows/"
                                        "blackduck.yml"
                                    ),
                                    "repository_id": 17,
                                }
                            ]
                        },
                    }
                ],
            }

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
            if self.properties_unsupported:
                raise GitHubRestError(
                    "not_found",
                    "properties unavailable",
                    attempts=1,
                    status_code=404,
                )

            return [
                {
                    "repository_full_name": (
                        "acme/service"
                    ),
                    "properties": [
                        {
                            "property_name": (
                                "blackduck_sca_policy"
                            ),
                            "value": "required",
                        }
                    ],
                },
                {
                    "repository_full_name": (
                        "acme/review"
                    ),
                    "properties": [
                        {
                            "property_name": (
                                "blackduck_sca_policy"
                            ),
                            "value": "review",
                        }
                    ],
                },
            ]

        if path.endswith("/rulesets"):
            if self.rulesets_unsupported:
                raise GitHubRestError(
                    "not_found",
                    "rulesets unavailable",
                    attempts=1,
                    status_code=404,
                )

            return [
                {
                    "id": 42,
                    "name": (
                        "Black Duck SCA Required"
                    ),
                    "target": "branch",
                    "enforcement": (
                        self.ruleset_enforcement
                    ),
                }
            ]

        raise AssertionError(
            f"Unexpected list: {path}"
        )


def observations_by_repository(
    provider: GitHubControlProvider,
) -> dict[
    tuple[str, ControlKind],
    ControlState,
]:
    result = provider.controls(
        tenant(),
        inventory(),
    )

    return {
        (
            observation.name_with_owner,
            observation.control,
        ): observation.state
        for observation
        in result.observations
    }


def test_active_ruleset_produces_compliant_controls() -> None:
    provider = GitHubControlProvider(
        FakeRestClient()
    )
    states = observations_by_repository(
        provider
    )

    assert states[
        (
            "acme/service",
            ControlKind.ONBOARDING_POLICY,
        )
    ] == ControlState.COMPLIANT
    assert states[
        (
            "acme/service",
            ControlKind.REQUIRED_SCAN_WORKFLOW,
        )
    ] == ControlState.COMPLIANT
    assert states[
        (
            "acme/service",
            ControlKind.PROTECTED_DEFAULT_BRANCH,
        )
    ] == ControlState.COMPLIANT


def test_unselected_repository_is_not_marked_noncompliant() -> None:
    states = observations_by_repository(
        GitHubControlProvider(
            FakeRestClient()
        )
    )

    assert states[
        (
            "acme/review",
            ControlKind.ONBOARDING_POLICY,
        )
    ] == ControlState.NONCOMPLIANT
    assert states[
        (
            "acme/review",
            ControlKind.REQUIRED_SCAN_WORKFLOW,
        )
    ] == ControlState.AVAILABLE
    assert states[
        (
            "acme/review",
            ControlKind.PROTECTED_DEFAULT_BRANCH,
        )
    ] == ControlState.AVAILABLE


def test_evaluated_ruleset_is_not_active_compliance() -> None:
    states = observations_by_repository(
        GitHubControlProvider(
            FakeRestClient(
                ruleset_enforcement="evaluate"
            )
        )
    )

    assert states[
        (
            "acme/service",
            ControlKind.REQUIRED_SCAN_WORKFLOW,
        )
    ] == ControlState.NONCOMPLIANT
    assert states[
        (
            "acme/service",
            ControlKind.PROTECTED_DEFAULT_BRANCH,
        )
    ] == ControlState.NONCOMPLIANT


def test_unsupported_rulesets_are_not_noncompliant() -> None:
    states = observations_by_repository(
        GitHubControlProvider(
            FakeRestClient(
                rulesets_unsupported=True
            )
        )
    )

    assert states[
        (
            "acme/service",
            ControlKind.REQUIRED_SCAN_WORKFLOW,
        )
    ] == ControlState.UNSUPPORTED


def test_missing_property_capability_is_explicit() -> None:
    states = observations_by_repository(
        GitHubControlProvider(
            FakeRestClient(
                properties_unsupported=True
            )
        )
    )

    assert states[
        (
            "acme/service",
            ControlKind.ONBOARDING_POLICY,
        )
    ] == ControlState.UNSUPPORTED
    assert states[
        (
            "acme/service",
            ControlKind.REQUIRED_SCAN_WORKFLOW,
        )
    ] == ControlState.UNKNOWN


def test_control_provider_is_structural() -> None:
    provider = GitHubControlProvider(
        FakeRestClient(),
        settings=GitHubControlSettings(
            ruleset_name=(
                "Black Duck SCA Required"
            )
        ),
    )

    assert isinstance(
        provider,
        ScmControlProvider,
    )


def test_control_identity_survives_repository_rename() -> None:
    original = inventory().repositories[0]
    renamed = dataclasses.replace(
        original,
        namespace="renamed-acme",
        name="renamed-service",
        canonical_url=(
            "https://github.example/"
            "renamed-acme/renamed-service"
        ),
    )

    assert original.external_id == (
        renamed.external_id
    )
