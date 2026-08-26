from __future__ import annotations

import io
import json
from typing import Any
from urllib.error import HTTPError, URLError

import pytest

from wintermute.scm.providers.github import (
    rest as rest_module,
)
from wintermute.scm.providers.github.rest import (
    GitHubRestClient,
    GitHubRestError,
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
        self.headers = dict(headers or {})

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
        content = (
            self.payload
            if isinstance(self.payload, bytes)
            else json.dumps(
                self.payload
            ).encode("utf-8")
        )

        return (
            content
            if size < 0
            else content[:size]
        )


def test_rest_client_uses_allowlisted_get(
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
            (request, timeout)
        )
        return Response(
            [],
            headers={
                "X-RateLimit-Remaining": "4999",
            },
        )

    monkeypatch.setattr(
        rest_module,
        "urlopen",
        fake_urlopen,
    )
    client = GitHubRestClient(
        "test-token",
        base_url=(
            "https://github.example/api/v3"
        ),
    )
    path = client.organization_path(
        "acme",
        "rulesets",
    )

    assert client.get_json(
        path,
        params={
            "per_page": 100,
            "page": 1,
        },
    ) == []

    request, timeout = requests[0]

    assert request.get_method() == "GET"
    assert request.full_url == (
        "https://github.example/api/v3/"
        "orgs/acme/rulesets?per_page=100&page=1"
    )
    assert request.get_header(
        "Authorization"
    ) == "Bearer test-token"
    assert timeout == 30.0
    assert client.stats().rate_remaining == 4999


def test_rest_client_rejects_unapproved_endpoint() -> None:
    client = GitHubRestClient(
        "test-token"
    )

    with pytest.raises(
        GitHubRestError,
        match="not allowlisted",
    ):
        client.get_json("/user")


def test_rest_client_paginates_lists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pages: list[int] = []

    def fake_urlopen(
        request: Any,
        timeout: float,
        context: object,
    ) -> Response:
        del timeout, context
        page = int(
            request.full_url.rsplit(
                "page=",
                1,
            )[1]
        )
        pages.append(page)

        if page == 1:
            return Response(
                [
                    {"id": index}
                    for index in range(100)
                ]
            )

        return Response([{"id": 100}])

    monkeypatch.setattr(
        rest_module,
        "urlopen",
        fake_urlopen,
    )
    client = GitHubRestClient(
        "test-token"
    )
    path = client.organization_path(
        "acme",
        "rulesets",
    )

    values = client.paged_list(path)

    assert len(values) == 101
    assert pages == [1, 2]


def test_rest_client_retries_server_failure(
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

        return Response([])

    monkeypatch.setattr(
        rest_module,
        "urlopen",
        fake_urlopen,
    )
    client = GitHubRestClient(
        "test-token",
        retries=1,
        retry_delay=0.25,
        sleeper=sleeps.append,
    )
    path = client.organization_path(
        "acme",
        "rulesets",
    )

    assert client.get_json(path) == []
    assert attempts == 2
    assert sleeps == [0.25]


def test_rest_client_redacts_network_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "secret-test-token"

    def fake_urlopen(
        *_args: object,
        **_kwargs: object,
    ) -> Response:
        raise URLError(
            f"rejected {token}"
        )

    monkeypatch.setattr(
        rest_module,
        "urlopen",
        fake_urlopen,
    )
    client = GitHubRestClient(
        token,
        retries=0,
    )
    path = client.organization_path(
        "acme",
        "rulesets",
    )

    with pytest.raises(
        GitHubRestError,
    ) as captured:
        client.get_json(path)

    assert token not in str(
        captured.value
    )
    assert "[REDACTED]" in str(
        captured.value
    )


def test_rest_client_reports_unsupported_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(
        request: Any,
        timeout: float,
        context: object,
    ) -> Response:
        del timeout, context

        raise HTTPError(
            request.full_url,
            404,
            "Not Found",
            {},
            io.BytesIO(b"not found"),
        )

    monkeypatch.setattr(
        rest_module,
        "urlopen",
        fake_urlopen,
    )
    client = GitHubRestClient(
        "test-token",
        retries=0,
    )
    path = client.organization_path(
        "acme",
        "properties/schema",
    )

    with pytest.raises(
        GitHubRestError,
    ) as captured:
        client.get_json(path)

    assert captured.value.category == "not_found"
    assert captured.value.status_code == 404


def test_rest_client_paginates_workflows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pages: list[int] = []

    def fake_urlopen(
        request: Any,
        timeout: float,
        context: object,
    ) -> Response:
        del timeout, context
        query = request.full_url.rsplit(
            "?",
            1,
        )[1]
        parameters = {
            key: value
            for key, value in (
                item.split("=", 1)
                for item in query.split("&")
            )
        }
        page = int(parameters["page"])
        pages.append(page)

        if page == 1:
            return Response(
                {
                    "total_count": 101,
                    "workflows": [
                        {
                            "id": index + 1,
                            "name": f"Workflow {index + 1}",
                        }
                        for index in range(100)
                    ],
                }
            )

        return Response(
            {
                "total_count": 101,
                "workflows": [
                    {
                        "id": 101,
                        "name": "Workflow 101",
                    }
                ],
            }
        )

    monkeypatch.setattr(
        rest_module,
        "urlopen",
        fake_urlopen,
    )
    client = GitHubRestClient(
        "test-token"
    )
    path = client.repository_path(
        "acme",
        "service",
        "actions/workflows",
    )

    workflows = client.paged_workflows(
        path
    )

    assert len(workflows) == 101
    assert pages == [1, 2]


def test_rest_client_rejects_duplicate_workflow_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        rest_module,
        "urlopen",
        lambda *_args, **_kwargs: Response(
            {
                "total_count": 2,
                "workflows": [
                    {"id": 17},
                    {"id": 17},
                ],
            }
        ),
    )
    client = GitHubRestClient(
        "test-token"
    )

    with pytest.raises(
        GitHubRestError,
        match="duplicate",
    ):
        client.paged_workflows(
            client.repository_path(
                "acme",
                "service",
                "actions/workflows",
            )
        )
