from __future__ import annotations

from types import SimpleNamespace

import pytest

from wintermute.scan import trigger


class Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class Client:
    def __init__(self, responses, clock, request_duration=0):
        self.timeout = 30.0
        self.retries = 2
        self.responses = iter(responses)
        self.clock = clock
        self.request_duration = request_duration
        self.calls = []

    def get_json(self, path):
        self.calls.append((path, self.timeout, self.retries))
        self.clock.now += self.request_duration
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return SimpleNamespace(payload=response)


def pipeline(status, **changes):
    return {
        "id": 99,
        "project_id": 10,
        "status": status,
        **changes,
    }


@pytest.fixture
def clock(monkeypatch):
    selected = Clock()
    monkeypatch.setattr(trigger.time, "monotonic", selected.monotonic)
    monkeypatch.setattr(trigger.time, "sleep", selected.sleep)
    return selected


def wait(client, **overrides):
    return trigger.wait_for_pipeline(
        client,
        central_project_id=10,
        pipeline_id=99,
        timeout=overrides.get("timeout", 60),
        poll_interval=overrides.get("poll_interval", 15),
    )


def test_polling_uses_only_pipeline_status_endpoint(clock):
    client = Client([pipeline("running"), pipeline("success")], clock)
    result = wait(client)
    assert result["status"] == "success"
    assert [call[0] for call in client.calls] == [
        "/projects/10/pipelines/99",
        "/projects/10/pipelines/99",
    ]
    assert clock.sleeps == [15]
    assert all(call[2] == 0 for call in client.calls)
    assert client.timeout == 30
    assert client.retries == 2


def test_polling_bounds_sleep_and_stops_at_deadline(clock):
    client = Client([pipeline("running")], clock)
    with pytest.raises(trigger.LauncherTriggerError, match="timed out"):
        wait(client, timeout=4)
    assert clock.sleeps == [4]
    assert len(client.calls) == 1
    assert client.calls[0][1] == 4
    assert client.timeout == 30
    assert client.retries == 2


def test_polling_caps_request_timeout_by_remaining_budget(clock):
    client = Client(
        [pipeline("running"), pipeline("success")],
        clock,
        request_duration=1,
    )
    wait(client, timeout=20, poll_interval=15)
    assert [call[1] for call in client.calls] == [20, 4]


@pytest.mark.parametrize(
    "changes",
    [
        {"id": 100},
        {"project_id": 11},
        {"id": "99"},
        {"project_id": "10"},
        {"project_id": None},
    ],
)
def test_polling_rejects_wrong_pipeline_identity(clock, changes):
    client = Client([pipeline("success", **changes)], clock)
    with pytest.raises(trigger.LauncherTriggerError, match="identity"):
        wait(client)
    assert client.timeout == 30
    assert client.retries == 2


@pytest.mark.parametrize("status", ["failed", "canceled", "skipped"])
def test_polling_reports_terminal_failure(clock, status):
    client = Client([pipeline(status)], clock)
    with pytest.raises(trigger.LauncherTriggerError, match=status):
        wait(client)
    assert clock.sleeps == []


def test_polling_reports_manual_intervention(clock):
    client = Client([pipeline("manual")], clock)
    with pytest.raises(trigger.LauncherTriggerError, match="manual intervention"):
        wait(client)
    assert clock.sleeps == []


def test_polling_rejects_unknown_status(clock):
    client = Client([pipeline("unexpected")], clock)
    with pytest.raises(trigger.LauncherTriggerError, match="unsupported"):
        wait(client)


def test_polling_restores_transport_after_request_failure(clock):
    client = Client([RuntimeError("synthetic network failure")], clock)
    with pytest.raises(RuntimeError, match="synthetic network"):
        wait(client)
    assert client.timeout == 30
    assert client.retries == 2


def test_success_received_after_deadline_is_not_accepted(clock):
    client = Client(
        [pipeline("success")],
        clock,
        request_duration=6,
    )
    with pytest.raises(trigger.LauncherTriggerError, match="budget"):
        wait(client, timeout=5)


@pytest.mark.parametrize("value", [0, -1, float("nan"), float("inf"), True])
def test_invalid_polling_budget_is_rejected(clock, value):
    client = Client([], clock)
    with pytest.raises(trigger.LauncherTriggerError, match="finite and positive"):
        wait(client, timeout=value)
    assert client.calls == []
