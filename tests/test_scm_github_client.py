from __future__ import annotations

import io
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError

import pytest

from wintermute.scm.providers.github import (
    client as client_module,
)
from wintermute.scm.providers.github.client import (
    GitHubClient,
    GitHubClientError,
)
from wintermute.scm.providers.github.graphql import (
    DISCOVERY_QUERY,
    PREFLIGHT_QUERY,
)


ROOT = Path(__file__).resolve().parents[1]
DISCOVERY_FIXTURE = (
    ROOT
    / "tests"
    / "fixtures"
    / "scm"
    / "github"
    / "discovery-page.json"
)


class Response:
    def __init__(
        self,
        payload: object,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.payload = payload
        self.status = status
        self.headers = dict(
            headers or {}
        )

    def __enter__(self) -> Response:
        return self

    def __exit__(
        self,
        *args: object,
    ) -> None:
        return None

    def read(
        self,
        size: int = -1,
    ) -> bytes:
        if isinstance(
            self.payload,
            bytes,
        ):
            content = self.payload
        else:
            content = json.dumps(
                self.payload
            ).encode("utf-8")

        return (
            content
            if size < 0
            else content[:size]
        )


def discovery_payload() -> dict[str, Any]:
    value = json.loads(
        DISCOVERY_FIXTURE.read_text(
            encoding="utf-8"
        )
    )

    assert isinstance(value, dict)
    return value


def test_graphql_client_posts_authenticated_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[Any] = []

    def fake_urlopen(
        request: Any,
        timeout: float,
        context: object,
    ) -> Response:
        del context
        requests.append(
            (
                request,
                timeout,
            )
        )
        return Response(
            {
                "data": {
                    "viewer": {
                        "login": "operator"
                    },
                    "rateLimit": {
                        "cost": 2,
                        "remaining": 4998,
                        "resetAt": (
                            "2099-01-01T00:00:00Z"
                        ),
                    },
                }
            }
        )

    monkeypatch.setattr(
        client_module,
        "urlopen",
        fake_urlopen,
    )
    client = GitHubClient(
        "acme",
        "test-token",
        endpoint=(
            "https://github.example/"
            "api/graphql"
        ),
    )

    data = client.graphql(
        "query Test { viewer { login } }",
        {},
        operation="Test",
    )

    request, timeout = requests[0]
    body = json.loads(
        request.data.decode("utf-8")
    )
    stats = client.stats()

    assert data["viewer"]["login"] == (
        "operator"
    )
    assert request.full_url == (
        "https://github.example/api/graphql"
    )
    assert request.get_method() == "POST"
    assert request.get_header(
        "Authorization"
    ) == "Bearer test-token"
    assert body["operationName"] == "Test"
    assert timeout == 30.0
    assert stats.requests == 1
    assert stats.retries == 0
    assert stats.graphql_cost == 2
    assert stats.rate_remaining == 4998


def test_graphql_client_retries_server_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0
    sleeps: list[float] = []

    def fake_urlopen(
        request: Any,
        timeout: float,
        context: object,
    ) -> Response:
        del timeout, context
        nonlocal attempts
        attempts += 1

        if attempts == 1:
            raise HTTPError(
                request.full_url,
                503,
                "Unavailable",
                {},
                io.BytesIO(b"temporary"),
            )

        return Response(
            {
                "data": {
                    "ok": True,
                }
            }
        )

    monkeypatch.setattr(
        client_module,
        "urlopen",
        fake_urlopen,
    )
    client = GitHubClient(
        "acme",
        "test-token",
        retries=1,
        retry_delay=0.5,
        sleeper=sleeps.append,
    )

    result = client.graphql(
        "query Test { viewer { login } }",
        {},
        operation="Test",
    )

    assert result == {"ok": True}
    assert attempts == 2
    assert sleeps == [0.5]
    assert client.stats().retries == 1


def test_authentication_failure_is_not_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0
    sleeps: list[float] = []

    def fake_urlopen(
        request: Any,
        timeout: float,
        context: object,
    ) -> Response:
        del timeout, context
        nonlocal attempts
        attempts += 1

        raise HTTPError(
            request.full_url,
            401,
            "Unauthorized",
            {},
            io.BytesIO(b"unauthorized"),
        )

    monkeypatch.setattr(
        client_module,
        "urlopen",
        fake_urlopen,
    )
    client = GitHubClient(
        "acme",
        "invalid-token",
        retries=3,
        sleeper=sleeps.append,
    )

    with pytest.raises(
        GitHubClientError,
    ) as captured:
        client.graphql(
            "query Test { viewer { login } }",
            {},
            operation="Test",
        )

    assert captured.value.category == (
        "authentication_failed"
    )
    assert captured.value.attempts == 1
    assert attempts == 1
    assert sleeps == []


def test_network_failure_redacts_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "secret-test-token"

    def fake_urlopen(
        request: Any,
        timeout: float,
        context: object,
    ) -> Response:
        del request, timeout, context
        raise URLError(
            f"connection rejected for {token}"
        )

    monkeypatch.setattr(
        client_module,
        "urlopen",
        fake_urlopen,
    )
    client = GitHubClient(
        "acme",
        token,
        retries=0,
    )

    with pytest.raises(
        GitHubClientError,
    ) as captured:
        client.graphql(
            "query Test { viewer { login } }",
            {},
            operation="Test",
        )

    assert token not in str(
        captured.value
    )
    assert "[REDACTED]" in str(
        captured.value
    )


def test_graphql_errors_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        client_module,
        "urlopen",
        lambda *_args, **_kwargs: Response(
            {
                "data": {
                    "organization": None,
                },
                "errors": [
                    {
                        "type": "FORBIDDEN",
                        "message": "Access denied",
                    }
                ],
            }
        ),
    )
    client = GitHubClient(
        "acme",
        "test-token",
        retries=0,
    )

    with pytest.raises(
        GitHubClientError,
    ) as captured:
        client.graphql(
            PREFLIGHT_QUERY,
            {"organization": "acme"},
            operation="InventoryPreflight",
        )

    assert captured.value.category == (
        "authorization_failed"
    )


def test_client_rejects_conflicting_tls_modes() -> None:
    with pytest.raises(ValueError):
        GitHubClient(
            "acme",
            "test-token",
            insecure=True,
            ca_bundle="/tmp/ca.pem",
        )


def test_runtime_deadline_precedes_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def fake_urlopen(
        *_args: object,
        **_kwargs: object,
    ) -> Response:
        nonlocal called
        called = True
        return Response({"data": {}})

    monkeypatch.setattr(
        client_module,
        "urlopen",
        fake_urlopen,
    )
    client = GitHubClient(
        "acme",
        "test-token",
        deadline=time.monotonic() - 1,
    )

    with pytest.raises(
        GitHubClientError,
    ) as captured:
        client.graphql(
            "query Test { viewer { login } }",
            {},
            operation="Test",
        )

    assert captured.value.category == (
        "runtime_budget_exceeded"
    )
    assert called is False


class StubGraphQLClient(GitHubClient):
    def __init__(
        self,
        responses: list[dict[str, Any]],
    ) -> None:
        super().__init__(
            "acme",
            "test-token",
            endpoint=(
                "https://github.example/"
                "api/graphql"
            ),
            clock=lambda: datetime(
                2026,
                7,
                31,
                tzinfo=timezone.utc,
            ),
        )
        self.responses = list(
            responses
        )
        self.calls: list[
            tuple[
                str,
                dict[str, Any],
            ]
        ] = []

    def graphql(
        self,
        query: str,
        variables: dict[str, Any],
        *,
        operation: str,
    ) -> dict[str, Any]:
        del query
        self.calls.append(
            (
                operation,
                dict(variables),
            )
        )

        if not self.responses:
            raise AssertionError(
                "Unexpected GraphQL request"
            )

        return self.responses.pop(0)


def test_provider_preflight_and_inventory_paginate() -> None:
    raw = discovery_payload()
    source_nodes = raw[
        "data"
    ]["organization"]["repositories"]["nodes"]
    preflight = {
        "viewer": {
            "login": "operator",
        },
        "organization": {
            "id": "O_acme",
            "login": "acme",
            "viewerCanAdminister": False,
            "repositories": {
                "totalCount": 3,
            },
        },
        "rateLimit": {
            "cost": 1,
            "remaining": 4999,
            "resetAt": "2099-01-01T00:00:00Z",
        },
    }
    first_page = {
        "organization": {
            "id": "O_acme",
            "login": "acme",
            "repositories": {
                "totalCount": 3,
                "nodes": source_nodes[:2],
                "pageInfo": {
                    "hasNextPage": True,
                    "endCursor": "cursor-1",
                },
            },
        }
    }
    second_page = {
        "organization": {
            "id": "O_acme",
            "login": "acme",
            "repositories": {
                "totalCount": 3,
                "nodes": source_nodes[2:],
                "pageInfo": {
                    "hasNextPage": False,
                    "endCursor": None,
                },
            },
        }
    }
    client = StubGraphQLClient(
        [
            preflight,
            first_page,
            second_page,
        ]
    )

    tenants = client.list_tenants()
    inventory = client.inventory(
        tenants[0]
    )

    assert len(tenants) == 1
    assert tenants[0].tenant_id == (
        "O_acme"
    )
    assert tenants[0].provider_instance == (
        "github.example"
    )
    assert inventory.reconciled is True
    assert inventory.repository_count == 2
    assert inventory.exclusion_count == 1
    assert inventory.failure_count == 0
    assert client.calls == [
        (
            "InventoryPreflight",
            {
                "organization": "acme",
            },
        ),
        (
            "OrganizationInventory",
            {
                "organization": "acme",
                "cursor": None,
                "pageSize": 100,
            },
        ),
        (
            "OrganizationInventory",
            {
                "organization": "acme",
                "cursor": "cursor-1",
                "pageSize": 100,
            },
        ),
    ]


def test_provider_rejects_repeated_cursor() -> None:
    page = {
        "organization": {
            "id": "O_acme",
            "login": "acme",
            "repositories": {
                "totalCount": 2,
                "nodes": [
                    {
                        "id": "R_one",
                    }
                ],
                "pageInfo": {
                    "hasNextPage": True,
                    "endCursor": "same",
                },
            },
        }
    }
    client = StubGraphQLClient(
        [
            page,
            page,
        ]
    )
    tenant = client.list_tenants

    from wintermute.scm.models import (
        ScmTenant,
    )

    configured = ScmTenant(
        provider="github",
        provider_instance="github.example",
        tenant_id="O_acme",
        namespace="acme",
    )

    with pytest.raises(
        GitHubClientError,
        match="cursor",
    ):
        client.inventory(configured)

    del tenant


def test_graphql_documents_are_read_only() -> None:
    for query in (
        PREFLIGHT_QUERY,
        DISCOVERY_QUERY,
    ):
        assert "mutation" not in (
            query.casefold()
        )
