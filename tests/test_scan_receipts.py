from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from wintermute.scan import cli


@pytest.fixture
def cli_case(tmp_path, monkeypatch):
    from wintermute.scan import execution_policy

    monkeypatch.setattr(
        execution_policy,
        "require_supported_execution",
        lambda contract: None,
    )
    args = argparse.Namespace(
        registry=str(tmp_path / "registry.json"),
        expected_registry_sha256="a" * 64,
        scm_provider="gitlab",
        scm_provider_instance="gitlab.example.invalid",
        scm_repository_id="42",
        commit_sha="b" * 40,
        source_root=str(tmp_path),
        bridge_executable=str(tmp_path / "bridge"),
        expected_bridge_sha256="c" * 64,
        mode="dry-run",
        confirm_execute=False,
        receipt_root=str(tmp_path / "receipts"),
    )
    monkeypatch.setattr(cli, "load_registry", lambda *a, **k: {})
    monkeypatch.setattr(
        cli,
        "resolve_scan",
        lambda *a, **k: SimpleNamespace(
            contract_id="scan-example",
            contract={"engine": "bridge", "products": ["blackduck-sca"]},
        ),
    )
    return args


def receipt(root):
    directory = Path(root)
    paths = [
        path for path in directory.glob("*.json")
        if not path.name.endswith(".checksums.json")
    ]
    assert len(paths) == 1
    path = paths[0]
    checksum_path = path.with_name(path.stem + ".checksums.json")
    checksums = json.loads(checksum_path.read_text(encoding="utf-8"))
    assert checksums["sha256"][path.name] == hashlib.sha256(
        path.read_bytes()
    ).hexdigest()
    return json.loads(path.read_text(encoding="utf-8"))


def test_dry_run_writes_verified_receipt(cli_case, monkeypatch):
    monkeypatch.setattr(
        cli,
        "run_scan",
        lambda *a, **k: {
            "mode": "dry-run",
            "contract_id": "scan-example",
            "engine": "bridge",
            "products": ["blackduck-sca"],
            "writes": 0,
            "remote_writes": 0,
        },
    )
    assert cli.run(cli_case) == 0
    payload = receipt(cli_case.receipt_root)
    assert payload["exit_code"] == 0
    assert payload["bridge_sha256"] == "c" * 64
    assert payload["result"]["remote_writes"] == 0


def test_timeout_result_is_retained(cli_case, monkeypatch):
    cli_case.mode = "execute"
    cli_case.confirm_execute = True
    monkeypatch.setattr(
        cli,
        "run_scan",
        lambda *a, **k: {
            "mode": "execute",
            "status": "failed",
            "outcome": "timeout",
            "writes": 1,
            "remote_writes": None,
        },
    )
    assert cli.run(cli_case) == 1
    payload = receipt(cli_case.receipt_root)
    assert payload["result"]["outcome"] == "timeout"
    assert payload["result"]["remote_writes"] is None


def test_registry_failure_is_retained(cli_case, monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("Scan registry checksum mismatch")

    monkeypatch.setattr(cli, "load_registry", fail)
    assert cli.run(cli_case) == 2
    payload = receipt(cli_case.receipt_root)
    assert payload["result"]["outcome"] == "validation-failed"
    assert payload["result"]["remote_writes"] == 0


def test_exception_receipt_is_redacted(cli_case, monkeypatch):
    cli_case.mode = "execute"
    cli_case.confirm_execute = True
    monkeypatch.setenv("BLACKDUCK_API_TOKEN", "synthetic-private-token")

    def fail(*args, **kwargs):
        raise RuntimeError("Failure with synthetic-private-token")

    monkeypatch.setattr(cli, "run_scan", fail)
    assert cli.run(cli_case) == 2
    payload = receipt(cli_case.receipt_root)
    assert "synthetic-private-token" not in json.dumps(payload)
    assert "[REDACTED]" in payload["error"]
    assert payload["result"]["remote_writes"] is None


def test_interrupt_receipt_does_not_claim_zero_writes(cli_case, monkeypatch):
    cli_case.mode = "execute"
    cli_case.confirm_execute = True

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "run_scan", interrupt)
    assert cli.run(cli_case) == 130
    payload = receipt(cli_case.receipt_root)
    assert payload["result"]["status"] == "interrupted"
    assert payload["result"]["remote_writes"] is None


def test_unconfirmed_execution_never_calls_engine(cli_case, monkeypatch):
    cli_case.mode = "execute"

    def forbidden(*args, **kwargs):
        raise AssertionError("Unconfirmed execution reached the engine")

    monkeypatch.setattr(cli, "run_scan", forbidden)
    assert cli.run(cli_case) == 2
    payload = receipt(cli_case.receipt_root)
    assert "confirmation" in payload["error"]
    assert payload["result"]["remote_writes"] == 0
