from __future__ import annotations

import json
from typing import Any

import pytest

from wintermute.scm.providers.gitlab import (
    GitLabRestClient,
    repository_path_from_url,
)


class Response:
    def __init__(
        self,
        payload: bytes,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.payload = payload
        self.headers = headers or {}
        self.status = 200

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

    def read(self, limit: int = -1) -> bytes:
        if limit < 0:
            return self.payload

        return self.payload[:limit]


def test_repository_path_from_url() -> None:
    assert repository_path_from_url(
        (
            "https://gitlab.example.invalid/"
            "group/subgroup/repository.git"
        ),
        provider_instance=(
            "gitlab.example.invalid"
        ),
    ) == "group/subgroup/repository"


def test_repository_path_rejects_other_host() -> None:
    with pytest.raises(
        ValueError,
        match="another provider instance",
    ):
        repository_path_from_url(
            (
                "https://other.example.invalid/"
                "group/repository.git"
            ),
            provider_instance=(
                "gitlab.example.invalid"
            ),
        )


def test_resolve_tag_and_read_file(
    monkeypatch,
) -> None:
    responses = [
        Response(
            json.dumps(
                {
                    "commit": {
                        "id": "a" * 40
                    }
                }
            ).encode("utf-8")
        ),
        Response(b"fixed-by:\n"),
    ]
    requests = []

    def fake_urlopen(
        request,
        **kwargs,
    ):
        del kwargs
        requests.append(request)
        return responses.pop(0)

    monkeypatch.setattr(
        (
            "wintermute.scm.providers."
            "gitlab.client.urlopen"
        ),
        fake_urlopen,
    )
    client = GitLabRestClient(
        base_url=(
            "https://gitlab.example.invalid/api/v4"
        ),
        request_interval_seconds=0,
    )
    repository = (
        client.resolve_repository_ref(
            (
                "https://gitlab.example.invalid/"
                "group/repository.git"
            ),
            "v1.0",
            tag=True,
        )
    )
    content = client.read_repository_file(
        repository,
        "issues/CVE-2026-0001.yml",
    )

    assert repository.commit == "a" * 40
    assert content == b"fixed-by:\n"
    assert len(requests) == 2
    assert "%2F" in requests[0].full_url
    assert "%2F" in requests[1].full_url
