from __future__ import annotations

import importlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from wintermute.blackduck.cache import (
    ApiResponseCache,
)
from wintermute.blackduck.client import (
    BlackDuckClient,
)
from wintermute.blackduck.criteria import (
    jira_parent_rollup_criteria,
)
from wintermute.blackduck.request_control import (
    BlackDuckCircuitOpenError,
    BlackDuckRequestController,
    sanitized_url,
)


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.value

    def wall_time(self) -> float:
        return 1000.0 + self.value

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += seconds


def controller(
    clock: FakeClock,
    *,
    interval: float = 0.5,
    threshold: int = 5,
    window: float = 60.0,
) -> BlackDuckRequestController:
    return BlackDuckRequestController(
        request_interval_seconds=interval,
        circuit_breaker_threshold=threshold,
        circuit_breaker_window_seconds=window,
        monotonic=clock.monotonic,
        wall_time=clock.wall_time,
        sleeper=clock.sleep,
    )


def test_rate_limit_is_shared_by_worker_clones() -> None:
    clock = FakeClock()
    shared = controller(clock)
    client = BlackDuckClient(
        "https://bd.example",
        "token",
        request_control=shared,
    )
    worker = client.clone_for_worker()

    first = shared.before_request(
        "GET",
        "https://bd.example/api/one",
    )
    second = worker.request_control.before_request(
        "GET",
        "https://bd.example/api/two",
    )
    third = client.request_control.before_request(
        "GET",
        "https://bd.example/api/three",
    )

    assert first.wait_seconds == 0
    assert second.wait_seconds == pytest.approx(0.5)
    assert third.wait_seconds == pytest.approx(0.5)
    assert clock.sleeps == pytest.approx(
        [0.5, 0.5]
    )
    assert worker.request_control is shared


def test_independent_clients_share_default_controller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "WINTERMUTE_BLACKDUCK_REQUEST_INTERVAL_SECONDS",
        "0.41731",
    )
    monkeypatch.setenv(
        "WINTERMUTE_BLACKDUCK_CIRCUIT_BREAKER_THRESHOLD",
        "7",
    )
    monkeypatch.setenv(
        "WINTERMUTE_BLACKDUCK_CIRCUIT_BREAKER_WINDOW_SECONDS",
        "73",
    )

    first = BlackDuckClient(
        "https://one.example",
        "token-one",
    )
    second = BlackDuckClient(
        "https://two.example",
        "token-two",
    )

    assert (
        first.request_control
        is second.request_control
    )


def test_concurrent_callers_reserve_spaced_slots() -> None:
    waits: list[float] = []
    waits_lock = threading.Lock()

    def record_sleep(seconds: float) -> None:
        with waits_lock:
            waits.append(seconds)

    shared = BlackDuckRequestController(
        request_interval_seconds=0.5,
        circuit_breaker_threshold=5,
        circuit_breaker_window_seconds=60,
        monotonic=lambda: 0.0,
        sleeper=record_sleep,
    )

    def reserve(index: int) -> float:
        permit = shared.before_request(
            "GET",
            f"https://bd.example/api/{index}",
        )
        return permit.wait_seconds

    with ThreadPoolExecutor(
        max_workers=4
    ) as executor:
        reserved = list(
            executor.map(reserve, range(4))
        )

    assert sorted(reserved) == pytest.approx(
        [0.0, 0.5, 1.0, 1.5]
    )
    assert sorted(waits) == pytest.approx(
        [0.5, 1.0, 1.5]
    )


def test_zero_interval_disables_pacing() -> None:
    clock = FakeClock()
    shared = controller(
        clock,
        interval=0,
    )

    for index in range(10):
        permit = shared.before_request(
            "GET",
            f"https://bd.example/api/{index}",
        )
        assert permit.wait_seconds == 0

    assert clock.sleeps == []


def test_five_server_failures_open_circuit() -> None:
    clock = FakeClock()
    shared = controller(
        clock,
        threshold=5,
    )

    for _ in range(4):
        _, opened = (
            shared.record_server_failure(
                502,
                "https://bd.example/api/items",
            )
        )
        assert opened is False

    count, opened = (
        shared.record_server_failure(
            503,
            "https://bd.example/api/items",
        )
    )

    assert count == 5
    assert opened is True

    clock.value += 120

    with pytest.raises(
        BlackDuckCircuitOpenError,
        match="5 server failure",
    ):
        shared.before_request(
            "GET",
            "https://bd.example/api/blocked",
        )


def test_open_circuit_prevents_urlopen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = FakeClock()
    shared = controller(
        clock,
        threshold=1,
    )
    shared.record_server_failure(
        502,
        "https://bd.example/api/failure",
    )
    client = BlackDuckClient(
        "https://bd.example",
        "token",
        request_control=shared,
    )
    calls = 0

    def forbidden_urlopen(*args: object, **kwargs: object) -> None:
        nonlocal calls
        del args, kwargs
        calls += 1
        raise AssertionError(
            "urlopen must not be called"
        )

    client_module = importlib.import_module(
        "wintermute.blackduck.client"
    )
    monkeypatch.setattr(
        client_module,
        "urlopen",
        forbidden_urlopen,
    )

    with pytest.raises(
        BlackDuckCircuitOpenError,
    ):
        client.get("/api/projects")

    assert calls == 0


def test_non_server_errors_do_not_open_circuit() -> None:
    clock = FakeClock()
    shared = controller(
        clock,
        threshold=2,
    )

    shared.record_server_failure(
        429,
        "https://bd.example/api/items",
    )
    shared.record_server_failure(
        401,
        "https://bd.example/api/items",
    )

    assert shared.snapshot().open is False
    assert shared.failure_count() == 0


def test_old_failures_expire_from_window() -> None:
    clock = FakeClock()
    shared = controller(
        clock,
        threshold=3,
        window=10,
    )

    shared.record_server_failure(
        500,
        "https://bd.example/api/one",
    )
    shared.record_server_failure(
        500,
        "https://bd.example/api/two",
    )
    clock.value += 11

    assert shared.failure_count() == 0

    _, opened = shared.record_server_failure(
        500,
        "https://bd.example/api/three",
    )

    assert opened is False


def test_sanitized_url_removes_query_values() -> None:
    value = sanitized_url(
        "https://bd.example/api/projects"
        "?offset=10&limit=100&q=secret-project"
    )

    assert "secret-project" not in value
    assert "offset=<redacted>" in value
    assert "limit=<redacted>" in value
    assert "q=<redacted>" in value


def test_jira_entity_lookup_is_opt_in() -> None:
    criteria = jira_parent_rollup_criteria()

    assert criteria.entity_custom_field == ""
    assert criteria.require_entity is False


def test_cache_checkpoints_after_entry_count(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cache.json"
    cache = ApiResponseCache(
        path=str(path),
        base_url="https://bd.example",
        max_age_hours=-1,
        max_entries=100,
        checkpoint_entries=2,
        checkpoint_seconds=3600,
    )

    cache.put_items(
        "https://bd.example/api/one",
        [{"id": 1}],
    )
    assert not path.exists()

    cache.put_items(
        "https://bd.example/api/two",
        [{"id": 2}],
    )

    assert path.is_file()
    payload = json.loads(
        path.read_text(encoding="utf-8")
    )
    assert len(payload["entries"]) == 2

    cache.save()


def test_cache_checkpoints_after_elapsed_time(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cache.json"
    cache = ApiResponseCache(
        path=str(path),
        base_url="https://bd.example",
        max_age_hours=-1,
        max_entries=100,
        checkpoint_entries=100,
        checkpoint_seconds=0.05,
    )
    cache.put_items(
        "https://bd.example/api/one",
        [{"id": 1}],
    )

    deadline = time.monotonic() + 2

    while (
        not path.exists()
        and time.monotonic() < deadline
    ):
        time.sleep(0.01)

    assert path.is_file()
    payload = json.loads(
        path.read_text(encoding="utf-8")
    )
    assert len(payload["entries"]) == 1

    cache.save()


def test_cache_checkpoint_has_no_temp_files(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cache.json"
    cache = ApiResponseCache(
        path=str(path),
        base_url="https://bd.example",
        max_age_hours=-1,
        max_entries=100,
        checkpoint_entries=1,
        checkpoint_seconds=3600,
    )
    cache.put_items(
        "https://bd.example/api/one",
        [{"id": 1}],
    )

    assert path.exists()
    assert list(
        tmp_path.glob("cache.json.tmp-*")
    ) == []

    cache.save()
