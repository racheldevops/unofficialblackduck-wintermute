from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

import pytest

from wintermute.scm.models import (
    ScmTenant,
)
from wintermute.scm.protocols import (
    ScmInventoryProvider,
)
from wintermute.scm.providers.github.client import (
    GitHubClient,
)


def client() -> GitHubClient:
    return GitHubClient(
        "acme",
        "test-token",
        endpoint=(
            "https://github.example/api/graphql"
        ),
        clock=lambda: datetime(
            2026,
            7,
            31,
            tzinfo=timezone.utc,
        ),
    )


def test_github_client_satisfies_provider_protocol() -> None:
    assert isinstance(
        client(),
        ScmInventoryProvider,
    )


@pytest.mark.parametrize(
    "tenant",
    [
        ScmTenant(
            provider="gitlab",
            provider_instance="github.example",
            tenant_id="O_acme",
            namespace="acme",
        ),
        ScmTenant(
            provider="github",
            provider_instance="other.example",
            tenant_id="O_acme",
            namespace="acme",
        ),
        ScmTenant(
            provider="github",
            provider_instance="github.example",
            tenant_id="O_acme",
            namespace="other",
        ),
    ],
)
def test_github_client_rejects_wrong_tenant(
    tenant: ScmTenant,
) -> None:
    with pytest.raises(ValueError):
        client().inventory(tenant)


def test_tenant_identity_survives_namespace_rename() -> None:
    original = ScmTenant(
        provider="github",
        provider_instance="github.example",
        tenant_id="O_acme",
        namespace="acme",
    )
    renamed = dataclasses.replace(
        original,
        namespace="renamed-acme",
    )

    assert original.identity_key == (
        renamed.identity_key
    )
    assert original.external_id == (
        renamed.external_id
    )
