from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from wintermute.scm.models import (
    ScmTenant,
)
from wintermute.scm.protocols import (
    ScmInventoryProvider,
)
from wintermute.scm.providers.gitlab.inventory import (
    GitLabClient,
)


class Client(GitLabClient):
    def __init__(self) -> None:
        super().__init__(
            group="group",
            token="token",
            base_url=(
                "https://gitlab.example.invalid/api/v4"
            ),
            request_interval_seconds=0,
            clock=lambda: datetime(
                2026,
                8,
                1,
                tzinfo=timezone.utc,
            ),
        )

    def get_json(
        self,
        path: str,
        *,
        params=None,
    ) -> Any:
        del params

        if path == "/groups/group":
            return {
                "id": 10,
                "full_path": "group",
            }

        if path.endswith("/languages"):
            return {
                "Python": 80.0,
                "Shell": 20.0,
            }

        if "/repository/commits/" in path:
            return {
                "id": "a" * 40,
            }

        raise AssertionError(path)

    def group_projects(self):
        return [
            {
                "id": 20,
                "path_with_namespace": (
                    "group/subgroup/service"
                ),
                "web_url": (
                    "https://gitlab.example.invalid/"
                    "group/subgroup/service"
                ),
                "visibility": "private",
                "archived": False,
                "default_branch": "main",
                "last_activity_at": (
                    "2026-07-01T00:00:00Z"
                ),
                "forked_from_project": None,
            },
            {
                "id": 21,
                "path_with_namespace": (
                    "group/archived"
                ),
                "web_url": (
                    "https://gitlab.example.invalid/"
                    "group/archived"
                ),
                "visibility": "internal",
                "archived": True,
                "default_branch": None,
                "last_activity_at": (
                    "2025-01-01T00:00:00Z"
                ),
                "forked_from_project": None,
            },
        ]


def test_gitlab_inventory_includes_subgroups() -> None:
    client = Client()
    tenant = client.list_tenants()[0]
    inventory = client.inventory(tenant)

    assert tenant == ScmTenant(
        provider="gitlab",
        provider_instance=(
            "gitlab.example.invalid"
        ),
        tenant_id="10",
        namespace="group",
    )
    assert inventory.reconciled is True
    assert inventory.repository_count == 1
    assert inventory.exclusion_count == 1
    repository = inventory.repositories[0]

    assert repository.name_with_owner == (
        "group/subgroup/service"
    )
    assert repository.head_sha == "a" * 40
    assert repository.languages == (
        "python",
    )


def test_gitlab_client_is_inventory_provider() -> None:
    assert isinstance(
        Client(),
        ScmInventoryProvider,
    )
