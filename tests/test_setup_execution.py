from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace

import pytest

from wintermute.scm.onboarding.setup_execution import (
    SetupExecutionError,
    approval_digest,
    approval_payload,
    execute_phases,
)


def phase(name="project-access", actions=1):
    return {
        "name": name,
        "loaded": SimpleNamespace(
            digest="sha256:" + "a" * 64,
            plan={
                "plan_id": "generated-plan-one",
                "created_at": "2026-01-01T00:00:00Z",
                "mutation_allowed": False,
                "estimated_writes": actions,
                "actions": [{"kind": "test-action"} for _ in range(actions)],
                "observation": {"source_project_id": 10},
                "observation_digest": "sha256:" + "b" * 64,
                "source_project": "example/security-scans",
                "source_project_id": 10,
                "target_projects": ["example/application"],
                "access_mode": "only-project-and-allowlist",
            },
        ),
        "client": SimpleNamespace(writes=0),
    }


def payload(phases):
    return approval_payload(
        configuration_digest="sha256:" + "c" * 64,
        template_plan_digest="sha256:" + "d" * 64,
        bundle_digest="sha256:" + "e" * 64,
        image="registry.example.invalid/scan@sha256:" + "f" * 64,
        phases=phases,
    )


def test_approval_digest_ignores_generated_plan_identity():
    first = phase()
    second = copy.deepcopy(first)
    second["loaded"].plan["plan_id"] = "generated-plan-two"
    second["loaded"].plan["created_at"] = "2026-02-01T00:00:00Z"
    assert approval_digest(payload([first])) == approval_digest(payload([second]))


def test_approval_digest_binds_observed_state():
    first = phase()
    second = copy.deepcopy(first)
    second["loaded"].plan["observation"]["source_project_id"] = 99
    assert approval_digest(payload([first])) != approval_digest(payload([second]))


def test_approval_digest_binds_actions():
    first = phase()
    second = copy.deepcopy(first)
    second["loaded"].plan["actions"][0]["kind"] = "different-action"
    assert approval_digest(payload([first])) != approval_digest(payload([second]))


def test_duplicate_phases_are_rejected():
    with pytest.raises(SetupExecutionError, match="identity"):
        payload([phase(), phase()])


def test_invalid_plan_write_count_is_rejected():
    selected = phase()
    selected["loaded"].plan["estimated_writes"] = 0
    with pytest.raises(SetupExecutionError, match="reconcile"):
        payload([selected])


def test_failure_counts_attempted_mutation_and_stops():
    first = phase()
    second = phase("central-variables")
    calls = []

    def fail(client, **kwargs):
        calls.append("first")
        client.writes += 1
        raise RuntimeError("Ambiguous network failure after request")

    def forbidden(client, **kwargs):
        calls.append("second")
        raise AssertionError("Later phase must not execute")

    first["execute"] = fail
    second["execute"] = forbidden
    records = []
    accounting = {}

    with pytest.raises(RuntimeError, match="Ambiguous"):
        execute_phases(
            [first, second],
            maximum_writes=2,
            records=records,
            accounting=accounting,
        )

    assert calls == ["first"]
    assert accounting["mutation_attempts"] == 1
    assert accounting["reported_successful_writes"] == 0
    assert accounting["remote_write_outcome"] == "partially-applied-or-unknown"
    assert records[0]["mutation_attempts"] == 1
    assert records[0]["status"] == "failed"


def test_completed_phase_is_preserved_after_later_failure():
    first = phase("central-variables")
    second = phase()

    def succeed(client, **kwargs):
        client.writes += 1
        return 0, {"status": "ok", "outcome": "applied", "writes": 1}, Path("result")

    def fail(client, **kwargs):
        client.writes += 1
        raise RuntimeError("Second phase failed")

    first["execute"] = succeed
    second["execute"] = fail
    records = []
    accounting = {}

    with pytest.raises(RuntimeError, match="Second"):
        execute_phases(
            [first, second],
            maximum_writes=2,
            records=records,
            accounting=accounting,
        )

    assert accounting["mutation_attempts"] == 2
    assert accounting["verified_phase_writes"] == 1
    assert accounting["reported_successful_writes"] == 1
    assert records[0]["status"] == "ok"
    assert records[1]["status"] == "failed"


def test_budget_is_checked_before_first_mutation():
    selected = phase(actions=2)
    called = []

    def forbidden(client, **kwargs):
        called.append(True)
        raise AssertionError("Must not execute")

    selected["execute"] = forbidden
    with pytest.raises(SetupExecutionError, match="budget"):
        execute_phases(
            [selected],
            maximum_writes=1,
            records=[],
            accounting={},
        )
    assert called == []


def test_remaining_budget_uses_attempts():
    first = phase("central-variables")
    second = phase()
    budgets = []

    def execute(client, **kwargs):
        budgets.append(kwargs["maximum_writes"])
        client.writes += 1
        return 0, {"status": "ok", "outcome": "applied", "writes": 1}, Path("result")

    first["execute"] = execute
    second["execute"] = execute
    accounting = {}
    execute_phases(
        [first, second],
        maximum_writes=2,
        records=[],
        accounting=accounting,
    )
    assert budgets == [2, 1]
    assert accounting["remote_write_outcome"] == "verified-complete"


def test_readback_failure_preserves_reported_write():
    selected = phase()

    def execute(client, **kwargs):
        client.writes += 1
        return 1, {
            "status": "failed",
            "outcome": "verification-failed",
            "writes": 1,
        }, Path("result")

    selected["execute"] = execute
    accounting = {}
    with pytest.raises(SetupExecutionError, match="verify"):
        execute_phases(
            [selected],
            maximum_writes=1,
            records=[],
            accounting=accounting,
        )
    assert accounting["mutation_attempts"] == 1
    assert accounting["reported_successful_writes"] == 1
    assert accounting["verified_phase_writes"] == 0


def test_accounting_redacts_failure(monkeypatch):
    monkeypatch.setenv("GITLAB_ACTION_TOKEN", "synthetic-private-token")
    selected = phase()

    def execute(client, **kwargs):
        raise RuntimeError("failed synthetic-private-token")

    selected["execute"] = execute
    records = []
    with pytest.raises(RuntimeError):
        execute_phases(
            [selected],
            maximum_writes=1,
            records=records,
            accounting={},
        )
    assert "synthetic-private-token" not in str(records)
    assert "[REDACTED]" in records[0]["error"]


def test_interruption_counts_attempts():
    selected = phase()

    def execute(client, **kwargs):
        client.writes += 1
        raise KeyboardInterrupt

    selected["execute"] = execute
    accounting = {}
    with pytest.raises(KeyboardInterrupt):
        execute_phases(
            [selected],
            maximum_writes=1,
            records=[],
            accounting=accounting,
        )
    assert accounting["mutation_attempts"] == 1
    assert accounting["remote_write_outcome"] == "partially-applied-or-unknown"
