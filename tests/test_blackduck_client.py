from __future__ import annotations

import io
import json
import threading
import time
from pathlib import Path
from urllib.error import HTTPError

import pytest

from wintermute.blackduck import client as client_module
from wintermute.blackduck.cache import ApiResponseCache
from wintermute.blackduck.client import BlackDuckClient
from wintermute.concurrency import ordered_parallel_map


class Response:
    def __init__(
        self,
        payload: object,
        status: int = 200,
    ) -> None:
        self.payload = payload
        self.status = status

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        if isinstance(self.payload, bytes):
            return self.payload

        return json.dumps(self.payload).encode("utf-8")


def test_client_builds_urls_and_pages_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = BlackDuckClient(
        "https://bd.example/",
        "token",
        page_limit=2,
    )
    calls: list[int] = []

    def fake_get(
        path: str,
        params: dict[str, object] | None = None,
    ) -> dict[str, object]:
        assert path == "/api/items"
        offset = int((params or {})["offset"])
        calls.append(offset)

        if offset == 0:
            return {
                "items": [{"id": 1}, {"id": 2}],
                "totalCount": 3,
            }

        return {
            "items": [{"id": 3}],
            "totalCount": 3,
        }

    monkeypatch.setattr(client, "get", fake_get)

    assert client.paged_get("/api/items") == [
        {"id": 1},
        {"id": 2},
        {"id": 3},
    ]
    assert calls == [0, 2]
    assert client._make_url(
        "/api/items?existing=yes",
        {"q": "name:Project A"},
    ) == (
        "https://bd.example/api/items?"
        "existing=yes&q=name%3AProject+A"
    )


def test_worker_clones_share_bearer_token() -> None:
    client = BlackDuckClient(
        "https://bd.example",
        "token",
        bearer_token="first",
    )
    clone = client.clone_for_worker()

    clone.bearer_token = "second"

    assert client.bearer_token == "second"
    assert clone.bearer_token == "second"


def test_client_refreshes_token_after_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    methods: list[str] = []

    def fake_urlopen(
        request: object,
        timeout: int,
        context: object,
    ) -> Response:
        del timeout, context
        method = request.get_method()
        methods.append(method)

        if methods == ["GET"]:
            raise HTTPError(
                request.full_url,
                401,
                "Unauthorized",
                {},
                io.BytesIO(b"unauthorized"),
            )

        if method == "POST":
            return Response({"bearerToken": "refreshed"})

        return Response({"value": "ok"})

    monkeypatch.setattr(
        client_module,
        "urlopen",
        fake_urlopen,
    )

    client = BlackDuckClient(
        "https://bd.example",
        "token",
        retries=0,
        bearer_token="expired",
    )

    assert client.get("/api/test") == {"value": "ok"}
    assert client.bearer_token == "refreshed"
    assert methods == ["GET", "POST", "GET"]


def test_cache_coalesces_concurrent_loads(
    tmp_path: Path,
) -> None:
    cache = ApiResponseCache(
        path=str(tmp_path / "cache.json"),
        base_url="https://bd.example",
        max_age_hours=-1,
        max_entries=10,
    )
    calls = 0
    lock = threading.Lock()

    def operation(_: int) -> list[dict[str, object]]:
        def loader() -> tuple[
            list[dict[str, object]],
            int,
        ]:
            nonlocal calls

            with lock:
                calls += 1

            time.sleep(0.03)
            return [{"id": 1}], 1

        return cache.get_or_load_items(
            "https://bd.example/items",
            loader,
        )

    results = ordered_parallel_map(
        range(4),
        operation,
        workers=4,
    )

    assert results == [[{"id": 1}]] * 4
    assert calls == 1


def test_cache_save_and_load_round_trip(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cache.json"
    cache = ApiResponseCache(
        path=str(path),
        base_url="https://bd.example",
        max_age_hours=-1,
        max_entries=10,
    )
    cache.put_items(
        "https://bd.example/items",
        [{"id": 1}],
    )
    cache.save()

    loaded = ApiResponseCache.load(
        path=str(path),
        base_url="https://bd.example",
        max_age_hours=-1,
        refresh=False,
        max_entries=10,
        debug=False,
    )

    assert loaded.get_items(
        "https://bd.example/items"
    ) == [{"id": 1}]


def test_paged_cache_can_be_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = BlackDuckClient(
        "https://bd.example",
        "token",
        page_limit=10,
    )
    client.cache_raw_gets = False
    client.cache_paged_results = False
    calls = 0

    def fake_get(
        path: str,
        params: dict[str, object] | None = None,
    ) -> dict[str, object]:
        del path, params
        nonlocal calls
        calls += 1
        return {
            "items": [],
            "totalCount": 0,
        }

    monkeypatch.setattr(client, "get", fake_get)

    assert client.paged_get("/api/items") == []
    assert client.paged_get("/api/items") == []
    assert calls == 2
    assert client.raw_get_cache == {}
    assert client.paged_result_cache == {}
