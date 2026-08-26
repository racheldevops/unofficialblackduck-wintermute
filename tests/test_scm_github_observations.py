from __future__ import annotations

from typing import Any

from wintermute.scm.controls import (
    ControlKind,
    ControlState,
)
from wintermute.scm.evidence import (
    EvidenceKind,
)
from wintermute.scm.models import (
    Repository,
    RepositoryInventory,
    ScmTenant,
)
from wintermute.scm.protocols import (
    ScmObservationProvider,
)
from wintermute.scm.providers.github.observations import (
    GitHubObservationProvider,
)
from wintermute.scm.providers.github.rest import (
    GitHubRestError,
)


def tenant() -> ScmTenant:
    return ScmTenant(
        provider="github",
        provider_instance="github.example",
        tenant_id="O_acme",
        namespace="acme",
    )


def inventory() -> RepositoryInventory:
    repository = Repository(
        provider="github",
        provider_instance="github.example",
        tenant_id="O_acme",
        repository_id="R_service",
        namespace="acme",
        name="service",
        canonical_url=(
            "https://github.example/acme/service"
        ),
        default_branch="main",
        visibility="private",
        activity_status="active",
        languages=("python",),
    )

    return RepositoryInventory(
        repositories=(repository,),
        exclusions=(),
        failures=(),
        discovered_count=1,
    )


class FakeRestClient:
    provider_instance = "github.example"

    def __init__(
        self,
        *,
        properties_error: bool = False,
    ) -> None:
        self.properties_error = (
            properties_error
        )
        self.calls: list[
            tuple[str, str]
        ] = []

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
        self.calls.append(
            ("get", path)
        )

        if path.endswith(
            "/properties/schema"
        ):
            if self.properties_error:
                raise GitHubRestError(
                    "network_error",
                    "temporary property failure",
                    attempts=1,
                )

            return [
                {
                    "property_name": (
                        "blackduck_sca_policy"
                    ),
                    "value_type": (
                        "single_select"
                    ),
                    "required": False,
                    "default_value": None,
                    "description": (
                        "Black Duck onboarding policy"
                    ),
                    "allowed_values": [
                        "required",
                        "review",
                    ],
                },
                {
                    "property_name": (
                        "business_unit"
                    ),
                    "value_type": "string",
                    "required": False,
                    "default_value": None,
                    "description": (
                        "Owning business unit"
                    ),
                },
            ]

        if path.endswith("/rulesets/42"):
            return {
                "id": 42,
                "name": (
                    "Black Duck SCA Required"
                ),
                "target": "branch",
                "enforcement": "active",
                "bypass_actors": [],
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
                                    "ref": (
                                        "refs/heads/main"
                                    ),
                                    "repository_id": 17,
                                }
                            ]
                        },
                    }
                ],
            }

        raise AssertionError(
            f"Unexpected GET {path}"
        )

    def paged_list(
        self,
        path: str,
        *,
        params: Any = None,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        del params, page_size
        self.calls.append(
            ("list", path)
        )

        if path.endswith(
            "/properties/values"
        ):
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
                        },
                        {
                            "property_name": (
                                "business_unit"
                            ),
                            "value": "payments",
                        },
                    ],
                }
            ]

        if path.endswith("/rulesets"):
            return [
                {
                    "id": 42,
                    "name": (
                        "Black Duck SCA Required"
                    ),
                    "target": "branch",
                    "enforcement": "active",
                }
            ]

        raise AssertionError(
            f"Unexpected LIST {path}"
        )


    def paged_workflows(
        self,
        path: str,
        *,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        del page_size
        self.calls.append(
            ("workflows", path)
        )

        return [
            {
                "id": 101,
                "name": "Build",
                "path": (
                    ".github/workflows/build.yml"
                ),
                "state": "active",
                "created_at": (
                    "2026-01-01T00:00:00Z"
                ),
                "updated_at": (
                    "2026-08-01T00:00:00Z"
                ),
                "url": (
                    "https://api.github.example/"
                    "repos/acme/service/actions/"
                    "workflows/101"
                ),
                "html_url": (
                    "https://github.example/"
                    "acme/service/actions/"
                    "workflows/build.yml"
                ),
            }
        ]

    def repository_path(
        self,
        namespace: str,
        repository: str,
        suffix: str,
    ) -> str:
        return (
            f"/repos/{namespace}/{repository}/"
            f"{suffix}"
        )


def test_observation_provider_gathers_broad_evidence_once() -> None:
    client = FakeRestClient()
    provider = GitHubObservationProvider(
        client
    )
    result = provider.observe(
        tenant(),
        inventory(),
    )
    kinds = [
        observation.kind
        for observation
        in result.evidence.observations
    ]

    assert kinds.count(
        EvidenceKind
        .CUSTOM_PROPERTY_DEFINITION
    ) == 2
    assert kinds.count(
        EvidenceKind
        .REPOSITORY_CUSTOM_PROPERTY
    ) == 2
    assert kinds.count(
        EvidenceKind.BRANCH_RULESET
    ) == 1
    assert kinds.count(
        EvidenceKind
        .REQUIRED_WORKFLOW_REFERENCE
    ) == 1
    assert kinds.count(
        EvidenceKind
        .REPOSITORY_LANGUAGE_INVENTORY
    ) == 1
    assert kinds.count(
        EvidenceKind.REPOSITORY_LANGUAGE
    ) == 0
    assert kinds.count(
        EvidenceKind
        .REPOSITORY_WORKFLOW_INVENTORY
    ) == 1
    assert kinds.count(
        EvidenceKind.REPOSITORY_WORKFLOW
    ) == 1
    assert client.calls == [
        (
            "get",
            "/orgs/acme/properties/schema",
        ),
        (
            "list",
            "/orgs/acme/properties/values",
        ),
        (
            "list",
            "/orgs/acme/rulesets",
        ),
        (
            "get",
            "/orgs/acme/rulesets/42",
        ),
        (
            "workflows",
            "/repos/acme/service/actions/workflows",
        ),
    ]


def test_controls_are_derived_from_same_read() -> None:
    result = GitHubObservationProvider(
        FakeRestClient()
    ).observe(
        tenant(),
        inventory(),
    )
    states = {
        observation.control: (
            observation.state
        )
        for observation
        in result.controls.observations
    }

    assert states[
        ControlKind.ONBOARDING_POLICY
    ] == ControlState.COMPLIANT
    assert states[
        ControlKind.REQUIRED_SCAN_WORKFLOW
    ] == ControlState.COMPLIANT
    assert states[
        ControlKind.PROTECTED_DEFAULT_BRANCH
    ] == ControlState.COMPLIANT


def test_one_capability_failure_preserves_other_evidence() -> None:
    result = GitHubObservationProvider(
        FakeRestClient(
            properties_error=True
        )
    ).observe(
        tenant(),
        inventory(),
    )
    kinds = {
        observation.kind
        for observation
        in result.evidence.observations
    }

    assert (
        EvidenceKind.BRANCH_RULESET
        in kinds
    )
    assert (
        EvidenceKind
        .REQUIRED_WORKFLOW_REFERENCE
        in kinds
    )
    assert (
        EvidenceKind
        .CUSTOM_PROPERTY_DEFINITION
        not in kinds
    )
    assert result.evidence.failure_count == 1


def test_observation_provider_is_structural() -> None:
    assert isinstance(
        GitHubObservationProvider(
            FakeRestClient()
        ),
        ScmObservationProvider,
    )
