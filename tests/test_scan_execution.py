from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from wintermute.scan import engine
from wintermute.scan.contracts import ResolvedScan


COMMIT = "a" * 40


@pytest.fixture
def scan_case(tmp_path: Path, monkeypatch):
    bridge = tmp_path / "bridge"
    bridge.write_bytes(b"synthetic executable; never launched")
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.setenv("BLACKDUCK_URL", "https://blackduck.example.invalid")
    monkeypatch.setenv("BLACKDUCK_API_TOKEN", "synthetic-blackduck-token")

    resolved = ResolvedScan(
        contract_id="scan-example",
        provider="gitlab",
        provider_instance="gitlab.example.invalid",
        repository_id="42",
        contract={
            "engine": "bridge",
            "products": ["blackduck-sca"],
            "scan_mode": "hybrid",
            "timeout_seconds": 60,
            "runtime_parameters": {
                "buildless": False,
                "binary_scan": False,
                "detector_search_depth": 3,
                "project_name_strategy": "provider-id",
            },
        },
    )
    return resolved, {
        "source_root": source,
        "commit_sha": COMMIT,
        "bridge_executable": str(bridge),
        "bridge_sha256": hashlib.sha256(bridge.read_bytes()).hexdigest(),
        "execute": True,
        "confirm_execute": True,
    }


def test_dry_run_does_not_start_scanner(scan_case, monkeypatch):
    resolved, arguments = scan_case
    arguments["execute"] = False
    arguments["confirm_execute"] = False
    monkeypatch.delenv("BLACKDUCK_URL")
    monkeypatch.delenv("BLACKDUCK_API_TOKEN")

    def forbidden(*args, **kwargs):
        raise AssertionError("Dry-run started a scanner")

    monkeypatch.setattr(engine.subprocess, "run", forbidden)
    result = engine.run_scan(resolved, **arguments)
    assert result["remote_writes"] == 0
    assert result["scanner_executed"] is False
    assert result["stages_started"] == 0


def test_timeout_returns_failure_for_receipt_writer(scan_case, monkeypatch):
    resolved, arguments = scan_case

    def timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(engine.subprocess, "run", timeout)
    result = engine.run_scan(resolved, **arguments)
    assert result["status"] == "failed"
    assert result["outcome"] == "timeout"
    assert result["remote_writes"] is None
    assert result["stages_started"] == 1
    assert result["results"][0]["status"] == "timed-out"


def test_start_failure_reports_no_started_stage(scan_case, monkeypatch):
    resolved, arguments = scan_case

    def fail(*args, **kwargs):
        raise OSError("failed synthetic-blackduck-token")

    monkeypatch.setattr(engine.subprocess, "run", fail)
    result = engine.run_scan(resolved, **arguments)
    assert result["outcome"] == "start-failed"
    assert result["stages_started"] == 0
    assert result["remote_writes"] == 0
    assert "synthetic-blackduck-token" not in str(result)
    assert "[REDACTED]" in result["results"][0]["error"]


def test_scanner_failure_stops_remaining_stages(scan_case, monkeypatch):
    resolved, arguments = scan_case
    resolved.contract["products"] = ["blackduck-sca", "coverity"]
    calls = []

    def fail(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=7)

    monkeypatch.setattr(engine.subprocess, "run", fail)
    result = engine.run_scan(resolved, **arguments)
    assert result["outcome"] == "scanner-failed"
    assert len(calls) == 1
    assert result["remote_writes"] is None


def test_timeout_budget_is_shared_across_stages(scan_case, monkeypatch):
    resolved, arguments = scan_case
    resolved.contract["products"] = ["blackduck-sca", "coverity"]
    clock = {"now": 0.0}
    timeouts = []

    monkeypatch.setattr(engine.time, "monotonic", lambda: clock["now"])

    def run(command, **kwargs):
        timeouts.append(kwargs["timeout"])
        clock["now"] += 20
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(engine.subprocess, "run", run)
    result = engine.run_scan(resolved, **arguments)
    assert timeouts == [60, 40]
    assert result["status"] == "succeeded"
    assert result["stages_started"] == 2
    assert result["writes_measurement"] == "scanner-stages-started"


def test_no_next_stage_after_budget_exhaustion(scan_case, monkeypatch):
    resolved, arguments = scan_case
    resolved.contract["products"] = ["blackduck-sca", "coverity"]
    clock = {"now": 0.0}
    calls = []

    monkeypatch.setattr(engine.time, "monotonic", lambda: clock["now"])

    def run(command, **kwargs):
        calls.append(command)
        clock["now"] = 60
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(engine.subprocess, "run", run)
    result = engine.run_scan(resolved, **arguments)
    assert len(calls) == 1
    assert result["outcome"] == "timeout"
    assert result["results"][-1]["status"] == "not-started"


@pytest.mark.parametrize("commit", ["", "main", "abc123"])
def test_execution_requires_full_commit(scan_case, commit):
    resolved, arguments = scan_case
    arguments["commit_sha"] = commit
    with pytest.raises(ValueError, match="full commit"):
        engine.run_scan(resolved, **arguments)


def test_confirmation_precedes_execution(scan_case):
    resolved, arguments = scan_case
    arguments["confirm_execute"] = False
    with pytest.raises(ValueError, match="confirmation"):
        engine.run_scan(resolved, **arguments)
