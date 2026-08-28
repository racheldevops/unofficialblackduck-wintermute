from __future__ import annotations

import json
from typing import Any

from wintermute.scm.providers.gitlab.client import (
    GitLabRepositoryRef,
)
from wintermute.scm.providers.gitlab.commits import (
    GitLabCommitClient,
)


class Response:
    status = 200
    headers: dict[str, str] = {}

    def __init__(
        self,
        payload: dict[str, Any],
    ) -> None:
        self.payload = payload

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
            self.payload
        ).encode("utf-8")


def repository() -> GitLabRepositoryRef:
    return GitLabRepositoryRef(
        repository_url=(
            "https://gitlab.example.invalid/"
            "group/repository"
        ),
        project_path="group/repository",
        revision="v1.0",
        commit="b" * 40,
    )


def test_contains_commit_uses_merge_base(
    monkeypatch,
) -> None:
    requests = []

    def fake_urlopen(
        request,
        **kwargs,
    ):
        del kwargs
        requests.append(request)
        return Response(
            {
                "id": "a" * 40
            }
        )

    monkeypatch.setattr(
        (
            "wintermute.scm.providers."
            "gitlab.client.urlopen"
        ),
        fake_urlopen,
    )
    client = GitLabCommitClient(
        base_url=(
            "https://gitlab.example.invalid/api/v4"
        ),
        request_interval_seconds=0,
    )

    assert client.contains_commit(
        repository(),
        "a" * 40,
    )
    assert len(requests) == 1
    assert (
        "/repository/merge_base?"
        in requests[0].full_url
    )
    assert (
        requests[0]
        .full_url
        .count("refs%5B%5D=")
        == 2
    )


def test_same_commit_needs_no_request(
    monkeypatch,
) -> None:
    called = False

    def fake_urlopen(
        request,
        **kwargs,
    ):
        del request
        del kwargs
        nonlocal called
        called = True
        return Response({})

    monkeypatch.setattr(
        (
            "wintermute.scm.providers."
            "gitlab.client.urlopen"
        ),
        fake_urlopen,
    )
    client = GitLabCommitClient(
        base_url=(
            "https://gitlab.example.invalid/api/v4"
        ),
        request_interval_seconds=0,
    )

    assert client.contains_commit(
        repository(),
        "b" * 40,
    )
    assert called is False
