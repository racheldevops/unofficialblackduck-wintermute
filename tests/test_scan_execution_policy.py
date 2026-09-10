from __future__ import annotations

import argparse
import json
from types import SimpleNamespace

import pytest

from wintermute.scan import cli
from wintermute.scan.execution_policy import (
    ExecutionPolicyError,
    require_supported_execution,
)


def test_unverified_sca_mapping_is_blocked():
    with pytest.raises(ExecutionPolicyError, match="not yet been verified"):
        require_supported_execution({"products": ["blackduck-sca"]})


@pytest.mark.parametrize("product", ["coverity", "polaris"])
def test_future_products_are_not_silently_executed(product):
    with pytest.raises(ExecutionPolicyError, match="not implemented"):
        require_supported_execution({"products": [product]})


def test_public_execution_stops_before_engine(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "load_registry", lambda *a, **k: {})
    monkeypatch.setattr(
        cli,
        "resolve_scan",
        lambda *a, **k: SimpleNamespace(
            contract_id="scan-example",
            contract={
                "engine": "bridge",
                "products": ["blackduck-sca"],
            },
        ),
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("Blocked execution reached the engine")

    monkeypatch.setattr(cli, "run_scan", forbidden)
    args = argparse.Namespace(
        registry="unused",
        expected_registry_sha256="a" * 64,
        scm_provider="gitlab",
        scm_provider_instance="gitlab.example.invalid",
        scm_repository_id="42",
        commit_sha="b" * 40,
        source_root=str(tmp_path),
        bridge_executable="unused",
        expected_bridge_sha256="c" * 64,
        mode="execute",
        confirm_execute=True,
        receipt_root=str(tmp_path / "receipts"),
    )
    assert cli.run(args) == 2

    receipts = [
        path for path in (tmp_path / "receipts").glob("*.json")
        if not path.name.endswith(".checksums.json")
    ]
    assert len(receipts) == 1
    result = json.loads(receipts[0].read_text(encoding="utf-8"))
    assert result["result"]["outcome"] == "validation-failed"
    assert result["result"]["remote_writes"] == 0
    assert "No scanner was started" in result["error"]
