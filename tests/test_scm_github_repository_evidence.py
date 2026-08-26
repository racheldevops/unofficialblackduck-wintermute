from __future__ import annotations

from typing import Any

from wintermute.scm.evidence import (
    EvidenceKind,
)
from wintermute.scm.models import (
    Repository,
    RepositoryInventory,
    ScmTenant,
)
from wintermute.scm.providers.github.rest import (
    GitHubRestError,
)
from wintermute.scm.providers.github.workflows import (
    collect_repository_evidence,
)


class Client:
    provider_instance = "github.example"

    def __init__(
        self,
        *,
        fail: str = "",
    ) -> None:
        self.fail = fail
        self.paths: list[str] = []

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

    def paged_workflows(
        self,
        path: str,
        *,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        del page_size
        self.paths.append(path)

        if path.endswith(
            f"/{self.fail}/actions/workflows"
        ):
            raise GitHubRestError(
                "not_found",
                "repository workflow endpoint unavailable",
                attempts=1,
                status_code=404,
            )

        return [
            {
                "id": 17,
                "name": "Black Duck",
                "path": (
                    ".github/workflows/blackduck.yml"
                ),
                "state": "active",
                "created_at": (
                    "2026-01-01T00:00:00Z"
                ),
                "updated_at": (
                    "2026-08-01T00:00:00Z"
                ),
            }
        ]


def tenant() -> ScmTenant:
    return ScmTenant(
        provider="github",
        provider_instance="github.example",
        tenant_id="O_acme",
        namespace="acme",
    )


def repository(
    name: str,
) -> Repository:
    return Repository(
        provider="github",
        provider_instance="github.example",
        tenant_id="O_acme",
        repository_id=f"R_{name}",
        namespace="acme",
        name=name,
        canonical_url=(
            f"https://github.example/acme/{name}"
        ),
        visibility="private",
        activity_status="active",
        languages=("python",),
        language_bytes=(
            ("python", 700),
            ("typescript", 300),
        ),
        language_total_bytes=1000,
        language_data_complete=True,
    )


def test_language_and_workflow_evidence_are_preserved() -> None:
    value = repository("service")
    result = collect_repository_evidence(
        Client(),
        tenant(),
        RepositoryInventory(
            repositories=(value,),
            exclusions=(),
            failures=(),
            discovered_count=1,
        ),
        workers=2,
    )
    by_kind = {}

    for observation in result.observations:
        by_kind.setdefault(
            observation.kind,
            [],
        ).append(observation)

    language_inventory = by_kind[
        EvidenceKind
        .REPOSITORY_LANGUAGE_INVENTORY
    ][0]
    attributes = dict(
        language_inventory.attributes
    )

    assert attributes["complete"] == "true"
    assert attributes["total_bytes"] == "1000"
    assert {
        observation.key
        for observation in by_kind[
            EvidenceKind.REPOSITORY_LANGUAGE
        ]
    } == {
        "python",
        "typescript",
    }
    assert by_kind[
        EvidenceKind
        .REPOSITORY_WORKFLOW
    ][0].key == "17"
    assert result.failure_count == 0


def test_repository_workflow_failure_is_isolated() -> None:
    good = repository("good")
    bad = repository("bad")
    result = collect_repository_evidence(
        Client(fail="bad"),
        tenant(),
        RepositoryInventory(
            repositories=(
                good,
                bad,
            ),
            exclusions=(),
            failures=(),
            discovered_count=2,
        ),
        workers=2,
    )
    inventory_observations = [
        observation
        for observation
        in result.observations
        if (
            observation.kind
            == EvidenceKind
            .REPOSITORY_WORKFLOW_INVENTORY
        )
    ]
    statuses = {
        observation.name_with_owner: dict(
            observation.attributes
        )["status"]
        for observation
        in inventory_observations
    }

    assert statuses == {
        "acme/bad": "failed",
        "acme/good": "available",
    }
    assert result.failure_count == 1
    assert (
        result.failures[0]
        .repository_external_id
        == bad.external_id
    )
    assert (
        result.failures[0]
        .name_with_owner
        == "acme/bad"
    )
