from __future__ import annotations

import ast
import hashlib
import io
import json
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from wintermute.scan import trigger
from wintermute.scm.onboarding import central_bundle_job


COMMIT = "a" * 40
INSTANCE = "gitlab.example.invalid"


def artifact(**changes):
    receipt = {
        "schema_version": 1,
        "status": "succeeded",
        "mode": "dry-run",
        "provider": "gitlab",
        "provider_instance": INSTANCE,
        "project_id": "42",
        "commit_sha": COMMIT,
        "scan_contract_id": "scan-example",
        "registry_sha256": "b" * 64,
        "bridge_sha256": "c" * 64,
        "archive_sha256": "d" * 64,
        "scan_exit_code": 0,
        "workspace_deleted": True,
        "target_repository_modified": False,
    }
    receipt.update(changes)
    content = json.dumps(receipt).encode("utf-8")
    checksums = {
        "schema_version": 1,
        "sha256": {
            "launcher-receipt.json": hashlib.sha256(content).hexdigest(),
        },
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(
            ".wintermute/scan/receipts/test/launcher-receipt.json",
            content,
        )
        archive.writestr(
            ".wintermute/scan/receipts/test/checksums.json",
            json.dumps(checksums),
        )
    return output.getvalue()


def test_bridge_platform_probe_uses_explicit_platforms(monkeypatch):
    commands = []

    def command(arguments, *, timeout):
        commands.append(arguments)
        selected = arguments[arguments.index("--platform") + 1]
        machine = "x86_64" if selected == "linux/amd64" else "aarch64"
        digest = "a" * 64 if selected == "linux/amd64" else "b" * 64
        return SimpleNamespace(stdout=json.dumps({
            "machine": machine,
            "bridge_sha256": digest,
        }))

    monkeypatch.setattr(central_bundle_job, "run_command", command)
    result = central_bundle_job.inspect_bridge_platforms(
        "docker",
        "registry.example.invalid/scan@sha256:" + "c" * 64,
        timeout=10,
    )
    assert result == {
        "linux/amd64": "a" * 64,
        "linux/arm64": "b" * 64,
    }
    assert len(commands) == 2
    for arguments in commands:
        assert arguments[arguments.index("--network") + 1] == "none"
        assert "--read-only" in arguments


def test_bridge_platform_probe_rejects_wrong_architecture(monkeypatch):
    monkeypatch.setattr(
        central_bundle_job,
        "run_command",
        lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps({
            "machine": "aarch64",
            "bridge_sha256": "a" * 64,
        })),
    )
    with pytest.raises(RuntimeError, match="architecture mismatch"):
        central_bundle_job.inspect_bridge_platforms(
            "docker",
            "registry.example.invalid/scan@sha256:" + "c" * 64,
            timeout=10,
        )


def test_bundle_job_uses_two_platform_checksums():
    tree = ast.parse(
        Path(central_bundle_job.__file__).read_text(encoding="utf-8")
    )
    run = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "run"
    )
    configuration = next(
        node for node in ast.walk(run)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "CentralBundleConfiguration"
    )
    checksum = next(
        keyword.value for keyword in configuration.keywords
        if keyword.arg == "bridge_sha256"
    )
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "inspect_bridge_platforms"
        for node in ast.walk(checksum)
    )


def test_launcher_artifact_expected_identities():
    receipt, _, _ = trigger.verify_launcher_artifact(
        artifact(),
        provider_instance=INSTANCE,
        project_id=42,
        commit_sha=COMMIT,
        expected_registry_sha256="b" * 64,
        expected_bridge_sha256="c" * 64,
        expected_contract_id="scan-example",
    )
    assert receipt["workspace_deleted"] is True


@pytest.mark.parametrize(
    "expected",
    [
        {"expected_registry_sha256": "e" * 64},
        {"expected_bridge_sha256": "e" * 64},
        {"expected_contract_id": "scan-another"},
    ],
)
def test_launcher_artifact_rejects_unexpected_identity(expected):
    with pytest.raises(trigger.LauncherTriggerError):
        trigger.verify_launcher_artifact(
            artifact(),
            provider_instance=INSTANCE,
            project_id=42,
            commit_sha=COMMIT,
            **expected,
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"scan_exit_code": False},
        {"workspace_deleted": 1},
        {"target_repository_modified": 0},
        {"schema_version": True},
        {"registry_sha256": "invalid"},
    ],
)
def test_launcher_artifact_rejects_invalid_field_types(changes):
    with pytest.raises(trigger.LauncherTriggerError):
        trigger.verify_launcher_artifact(
            artifact(**changes),
            provider_instance=INSTANCE,
            project_id=42,
            commit_sha=COMMIT,
        )


def test_trigger_uses_separate_action_client(tmp_path, monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "synthetic-read-token")
    monkeypatch.setenv("GITLAB_ACTION_TOKEN", "synthetic-action-token")
    clients = []
    triggered = []

    class Client:
        def __init__(self, provider, base_url, token, **kwargs):
            self.token = token
            self.requests = 0
            self.writes = 0
            clients.append(self)

    monkeypatch.setattr(trigger, "GitLabLauncherTriggerClient", Client)

    def project(client, path):
        assert client.token == "synthetic-read-token"
        return {
            "id": 10 if path == "example/security-scans" else 42,
            "path": path,
            "default_branch": "main",
        }

    def commit(client, project_id, revision):
        assert client.token == "synthetic-read-token"
        return {"commit_sha": COMMIT}

    def create(client, **kwargs):
        assert client.token == "synthetic-action-token"
        client.writes += 1
        client.requests += 1
        triggered.append(kwargs)
        return {"id": 99, "ref": "main", "status": "pending"}

    monkeypatch.setattr(trigger, "exact_project", project)
    monkeypatch.setattr(trigger, "exact_commit", commit)
    monkeypatch.setattr(trigger, "trigger_pipeline", create)
    monkeypatch.setattr(
        trigger,
        "wait_for_pipeline",
        lambda *a, **k: {"id": 99, "ref": "main", "status": "success"},
    )
    monkeypatch.setattr(
        trigger,
        "launcher_job",
        lambda *a, **k: {
            "id": 100,
            "name": "wintermute_central_scan",
            "status": "success",
        },
    )
    monkeypatch.setattr(trigger, "download_artifact", lambda *a, **k: artifact())

    args = SimpleNamespace(
        confirm_trigger=True,
        expected_registry_sha256="b" * 64,
        expected_bridge_sha256="c" * 64,
        expected_contract_id="scan-example",
        gitlab_url=f"https://{INSTANCE}",
        central_project="example/security-scans",
        central_ref="main",
        target_project="example/application",
        target_ref="main",
        commit_sha=COMMIT,
        result_root=str(tmp_path),
        timeout=10,
        retries=0,
        retry_delay=0,
        request_interval_seconds=0,
        wait_timeout=30,
        poll_interval=15,
        insecure=False,
        ca_bundle=None,
    )
    assert trigger.run(args) == 0
    assert len(triggered) == 1
    assert triggered[0]["commit_sha"] == COMMIT
    assert clients[0].writes == 0
    assert clients[1].writes == 1

    results = list(tmp_path.glob("*/result.json"))
    assert len(results) == 1
    result = json.loads(results[0].read_text(encoding="utf-8"))
    assert result["status"] == "succeeded"
    assert result["writes"] == 1


def test_trigger_result_redacts_action_token(tmp_path, monkeypatch):
    monkeypatch.setenv("GITLAB_ACTION_TOKEN", "synthetic-private-action-token")
    directory = trigger.write_trigger_result(
        tmp_path,
        "test-trigger",
        {"error": "failed synthetic-private-action-token"},
    )
    text = (directory / "result.json").read_text(encoding="utf-8")
    assert "synthetic-private-action-token" not in text
    assert "[REDACTED]" in text
