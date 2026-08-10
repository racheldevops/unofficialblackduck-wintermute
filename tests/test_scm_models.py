from __future__ import annotations

import dataclasses

import pytest

from wintermute.scm.inventory import (
    inventory_payload,
    merge_inventories,
)
from wintermute.scm.models import (
    Repository,
    RepositoryInventory,
    ScmTenant,
)
from wintermute.scm.protocols import (
    ScmInventoryProvider,
)


def repository(
    **overrides: object,
) -> Repository:
    values: dict[str, object] = {
        "provider": "github",
        "provider_instance": "github.example",
        "tenant_id": "O_acme",
        "repository_id": "R_service",
        "namespace": "acme",
        "name": "service",
        "canonical_url": (
            "https://github.example/acme/service"
        ),
        "default_branch": "main",
        "head_sha": "a" * 40,
        "visibility": "private",
        "archived": False,
        "fork": False,
        "template": False,
        "pushed_at": (
            "2026-07-01T00:00:00Z"
        ),
        "activity_status": "active",
        "languages": (
            "Python",
            "TypeScript",
        ),
    }
    values.update(overrides)

    return Repository(**values)


def test_repository_identity_survives_rename() -> None:
    original = repository()
    renamed = dataclasses.replace(
        original,
        namespace="renamed-acme",
        name="renamed-service",
        canonical_url=(
            "https://github.example/"
            "renamed-acme/renamed-service"
        ),
    )

    assert original.identity_key == (
        renamed.identity_key
    )
    assert original.external_id == (
        renamed.external_id
    )
    assert original.name_with_owner == (
        "acme/service"
    )
    assert renamed.name_with_owner == (
        "renamed-acme/renamed-service"
    )


def test_repository_identity_is_instance_scoped() -> None:
    first = repository()
    second = dataclasses.replace(
        first,
        provider_instance=(
            "github.customer.example"
        ),
    )

    assert first.external_id != second.external_id


def test_repository_normalizes_values() -> None:
    value = repository(
        provider="GitHub",
        provider_instance=(
            "https://GITHUB.EXAMPLE/"
        ),
        canonical_url=(
            "https://GITHUB.EXAMPLE/acme/service/"
        ),
    )

    assert value.provider == "github"
    assert value.provider_instance == (
        "github.example"
    )
    assert value.canonical_url == (
        "https://github.example/acme/service"
    )
    assert value.languages == (
        "python",
        "typescript",
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {
            "canonical_url": (
                "http://github.example/acme/service"
            )
        },
        {"head_sha": "short"},
        {"visibility": "secret"},
        {
            "languages": (
                "unknown",
                "python",
            )
        },
    ],
)
def test_repository_rejects_invalid_values(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        repository(**overrides)


def test_inventory_merge_is_deterministic() -> None:
    first = RepositoryInventory(
        repositories=(repository(),),
        exclusions=(),
        failures=(),
        discovered_count=1,
    )
    second_repository = repository(
        provider="gitlab",
        provider_instance="gitlab.example",
        tenant_id="G_acme",
        repository_id="17",
        canonical_url=(
            "https://gitlab.example/acme/service"
        ),
    )
    second = RepositoryInventory(
        repositories=(second_repository,),
        exclusions=(),
        failures=(),
        discovered_count=1,
    )

    merged = merge_inventories(
        [second, first]
    )
    payload = inventory_payload(merged)

    assert merged.reconciled is True
    assert [
        item["provider"]
        for item in payload["repositories"]
    ] == [
        "github",
        "gitlab",
    ]


def test_inventory_merge_rejects_duplicate_identity() -> None:
    value = repository()
    inventory = RepositoryInventory(
        repositories=(value,),
        exclusions=(),
        failures=(),
        discovered_count=1,
    )

    with pytest.raises(
        ValueError,
        match="Duplicate repository identity",
    ):
        merge_inventories(
            [inventory, inventory]
        )


def test_provider_protocol_is_structural() -> None:
    class Provider:
        provider = "github"
        provider_instance = "github.example"

        def list_tenants(
            self,
        ) -> tuple[ScmTenant, ...]:
            return (
                ScmTenant(
                    provider=self.provider,
                    provider_instance=(
                        self.provider_instance
                    ),
                    tenant_id="O_acme",
                    namespace="acme",
                ),
            )

        def inventory(
            self,
            tenant: ScmTenant,
        ) -> RepositoryInventory:
            del tenant

            return RepositoryInventory(
                repositories=(),
                exclusions=(),
                failures=(),
                discovered_count=0,
            )

    assert isinstance(
        Provider(),
        ScmInventoryProvider,
    )
