from __future__ import annotations

import json
from pathlib import Path

import pytest

from wintermute.blackduck.circuit_recovery import (
    classify_target,
    load_active_quarantine,
    run_with_circuit_recovery,
)
from wintermute.blackduck.request_control import (
    BlackDuckRequestController,
)


def controller(
    threshold: int = 2,
) -> BlackDuckRequestController:
    return BlackDuckRequestController(
        request_interval_seconds=0,
        circuit_breaker_threshold=threshold,
        circuit_breaker_window_seconds=60,
    )


def open_for_one_target(
    shared: BlackDuckRequestController,
) -> Exception:
    context = {
        "child_project": "Example-Child",
        "child_version": "1.0.0",
        "child_version_href": (
            "https://bd.example/api/projects/child/"
            "versions/version"
        ),
        "parent_projects": "Parent-A;Parent-B",
        "stage": "component-vulnerabilities",
    }

    shared.record_server_failure(
        502,
        "https://bd.example/api/components/one",
        context=context,
    )
    shared.record_server_failure(
        503,
        "https://bd.example/api/components/two",
        context=context,
    )
    return shared.circuit_error()


def test_single_target_is_classified() -> None:
    shared = controller()
    error = open_for_one_target(shared)
    target = classify_target(
        error.snapshot,
        retry_after_epoch=2000,
    )

    assert target is not None
    assert target.child_project == "Example-Child"
    assert target.child_version == "1.0.0"
    assert target.parent_projects == (
        "Parent-A",
        "Parent-B",
    )


def test_multiple_targets_are_not_quarantined() -> None:
    shared = controller()
    shared.record_server_failure(
        502,
        "https://bd.example/api/one",
        context={
            "child_version_href": (
                "https://bd.example/version/one"
            )
        },
    )
    shared.record_server_failure(
        502,
        "https://bd.example/api/two",
        context={
            "child_version_href": (
                "https://bd.example/version/two"
            )
        },
    )

    target = classify_target(
        shared.snapshot(),
        retry_after_epoch=2000,
    )

    assert target is None


def test_same_pod_waits_resets_and_retries(
    tmp_path: Path,
) -> None:
    shared = controller()
    path = tmp_path / "quarantine.json"
    calls = 0
    sleeps: list[float] = []

    def operation() -> int:
        nonlocal calls
        calls += 1

        if calls == 1:
            raise open_for_one_target(shared)

        shared.raise_if_open()
        return 0

    result = run_with_circuit_recovery(
        operation,
        quarantine_path=path,
        delay_seconds=600,
        recovery_attempts=1,
        sleeper=sleeps.append,
    )

    assert result == 0
    assert calls == 2
    assert sleeps == [600]

    payload = json.loads(
        path.read_text(encoding="utf-8")
    )
    assert payload["status"] == "recovered"


def test_active_quarantine_expires(
    tmp_path: Path,
) -> None:
    path = tmp_path / "quarantine.json"
    path.write_text(
        json.dumps(
            {
                "status": "active",
                "target": {
                    "child_project": "Example",
                    "child_version": "1",
                    "child_version_href": (
                        "https://bd.example/version"
                    ),
                    "parent_projects": [],
                    "retry_after_epoch": 2000,
                    "retry_after": "later",
                    "failure_count": 5,
                },
            }
        ),
        encoding="utf-8",
    )

    assert load_active_quarantine(
        path,
        current_time=1000,
    ) is not None
    assert load_active_quarantine(
        path,
        current_time=3000,
    ) is None


def test_final_circuit_failure_remains_active(
    tmp_path: Path,
) -> None:
    shared = controller()
    path = tmp_path / "quarantine.json"

    with pytest.raises(Exception):
        run_with_circuit_recovery(
            lambda: (_ for _ in ()).throw(
                open_for_one_target(shared)
            ),
            quarantine_path=path,
            delay_seconds=0,
            recovery_attempts=0,
            sleeper=lambda _: None,
        )

    payload = json.loads(
        path.read_text(encoding="utf-8")
    )
    assert payload["status"] == "active"
