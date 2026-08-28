from __future__ import annotations

import json
from typing import Any

import pytest

from wintermute.blackduck.actions.http import (
    BlackDuckActionHttpClient,
    BlackDuckActionHttpError,
)


BASE_URL = "https://blackduck.example.invalid"


class RequestControl:
    def __init__(self) -> None:
        self.requests = 0
        self.successes = 0

    def before_request(
        self,
        method: str,
        url: str,
    ) -> Any:
        self.requests += 1

        return type(
            "Permit",
            (),
            {
                "context": {},
                "wait_seconds": 0,
                "sanitized_url": url,
            },
        )()

    def record_success(self) -> None:
        self.successes += 1

    def record_server_failure(
        self,
        status: int,
        url: str,
        *,
        context: dict[str, str],
    ) -> tuple[int, bool]:
        del status
        del url
        del context
        return 1, False


class Client:
    base_url = BASE_URL
    bearer_token = "token"
    timeout = 30
    ssl_context = None

    def __init__(self) -> None:
        self.request_control = RequestControl()


class Response:
    status = 200
    url = (
        f"{BASE_URL}/api/projects/p/"
        "versions/v/components/c/"
        "vulnerabilities/x/remediation"
    )

    def __enter__(self) -> Response:
        return self

    def __exit__(
        self,
        exception_type: Any,
        exception: Any,
        traceback: Any,
    ) -> None:
        del exception_type
        del exception
        del traceback

    def read(self, limit: int) -> bytes:
        del limit
        return json.dumps(
            {
                "remediationStatus": "PATCHED"
            }
        ).encode("utf-8")


def test_action_http_put(
    monkeypatch,
) -> None:
    requests = []

    def fake_urlopen(
        request,
        **kwargs,
    ):
        del kwargs
        requests.append(request)
        return Response()

    monkeypatch.setattr(
        (
            "wintermute.blackduck.actions."
            "http.urlopen"
        ),
        fake_urlopen,
    )
    client = Client()
    action_client = (
        BlackDuckActionHttpClient(client)
    )
    response = action_client.put_json(
        Response.url,
        {
            "remediationStatus": "PATCHED"
        },
        media_type=(
            "application/vnd.example+json"
        ),
    )

    assert response.status_code == 200
    assert response.payload == {
        "remediationStatus": "PATCHED"
    }
    assert requests[0].method == "PUT"
    assert (
        requests[0].headers["Content-type"]
        == "application/vnd.example+json"
    )
    assert client.request_control.requests == 1
    assert client.request_control.successes == 1


def test_action_http_rejects_other_instance() -> None:
    client = BlackDuckActionHttpClient(
        Client()
    )

    with pytest.raises(
        ValueError,
        match="another Black Duck instance",
    ):
        client.put_json(
            (
                "https://other.example.invalid/"
                "api/remediation"
            ),
            {
                "remediationStatus": "PATCHED"
            },
        )


def test_action_http_requires_authentication() -> None:
    client = Client()
    client.bearer_token = None
    action_client = (
        BlackDuckActionHttpClient(client)
    )

    with pytest.raises(
        BlackDuckActionHttpError,
        match="not authenticated",
    ):
        action_client.put_json(
            Response.url,
            {
                "remediationStatus": "PATCHED"
            },
        )
