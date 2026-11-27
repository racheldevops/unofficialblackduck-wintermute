from __future__ import annotations

import argparse
import hashlib
import io
import json
import tarfile
from pathlib import Path
from urllib.error import HTTPError

import pytest

from wintermute.scan import launcher


COMMIT = "a" * 40
INSTANCE = "gitlab.example.invalid"
TOKEN = "synthetic-provisioned-token"


class Response(io.BytesIO):
    def __init__(self, content, content_type):
        super().__init__(content)
        self.status = 200
        self.headers = {
            "Content-Type": content_type,
            "Content-Length": str(len(content)),
        }


def source_archive():
    output = io.BytesIO()
    content = b"print('example')\n"
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        member = tarfile.TarInfo("project/main.py")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


@pytest.fixture
def launch_case(tmp_path, monkeypatch):
    monkeypatch.delenv("CI_API_V4_URL", raising=False)
    monkeypatch.delenv("CI_JOB_TOKEN", raising=False)
    monkeypatch.setenv("WINTERMUTE_GITLAB_READ_TOKEN", TOKEN)

    bridge = tmp_path / "bridge"
    bridge.write_bytes(b"synthetic executable; never started")
    registry = {
        "schema_version": 1,
        "contracts": [{
            "scan_contract_id": "scan-example",
            "contract": {
                "engine": "bridge",
                "products": ["blackduck-sca"],
                "scan_mode": "hybrid",
                "timeout_seconds": 60,
                "runtime_parameters": {
                    "buildless": True,
                    "binary_scan": False,
                    "detector_search_depth": 3,
                    "project_name_strategy": "provider-id",
                },
            },
        }],
        "assignments": [{
            "provider": "gitlab",
            "provider_instance": INSTANCE,
            "repository_id": "42",
            "scan_contract_id": "scan-example",
        }],
    }
    content = json.dumps(registry).encode()
    registry_path = tmp_path / "registry.json"
    registry_path.write_bytes(content)

    args = argparse.Namespace(
        gitlab_api_url=f"https://{INSTANCE}/api/v4",
        project_id="42",
        commit_sha=COMMIT,
        registry=str(registry_path),
        expected_registry_sha256=hashlib.sha256(content).hexdigest(),
        expected_bridge_sha256=hashlib.sha256(bridge.read_bytes()).hexdigest(),
        bridge_executable=str(bridge),
        mode="dry-run",
        confirmation="",
        receipt_root=str(tmp_path / "receipts"),
        timeout=10,
        scan_timeout=60,
        insecure=False,
        ca_bundle=None,
    )
    requests = []
    scans = []
    control = {"commit_status": 200, "archive_status": 200, "commit_id": COMMIT}

    def respond(request, **kwargs):
        requests.append(request)
        url = request.full_url
        if url.endswith("/projects/42"):
            return Response(
                json.dumps({
                    "id": 42,
                    "archived": False,
                    "web_url": f"https://{INSTANCE}/example/application",
                    "path_with_namespace": "example/application",
                    "default_branch": "main",
                }).encode(),
                "application/json",
            )
        if url.endswith(f"/repository/commits/{COMMIT}"):
            if control["commit_status"] != 200:
                raise HTTPError(url, control["commit_status"], "Denied", {}, io.BytesIO())
            return Response(
                json.dumps({"id": control["commit_id"]}).encode(),
                "application/json",
            )
        if url.endswith(f"/repository/archive.tar.gz?sha={COMMIT}"):
            if control["archive_status"] != 200:
                raise HTTPError(url, control["archive_status"], "Denied", {}, io.BytesIO())
            return Response(source_archive(), "application/gzip")
        raise AssertionError(f"Unexpected request: {url}")

    def scan(scan_args, source_root, **kwargs):
        assert (source_root / "main.py").is_file()
        scans.append(source_root)
        return 0

    monkeypatch.setattr(launcher, "open_response", respond)
    monkeypatch.setattr(launcher, "run_scan", scan)
    return args, requests, scans, control


def receipt(args):
    paths = list(Path(args.receipt_root).glob("*/launcher-receipt.json"))
    assert len(paths) == 1
    content = paths[0].read_bytes()
    checksums = json.loads(paths[0].with_name("checksums.json").read_bytes())
    assert checksums["sha256"]["launcher-receipt.json"] == (
        hashlib.sha256(content).hexdigest()
    )
    return json.loads(content)


def headers(request):
    return {key.lower(): value for key, value in request.header_items()}


def test_all_three_reads_use_provisioned_token(launch_case, monkeypatch):
    args, requests, scans, _ = launch_case
    monkeypatch.setenv("CI_JOB_TOKEN", "synthetic-job-token")

    assert launcher.run(args) == 0
    assert len(requests) == 3
    for request in requests:
        assert request.get_method() == "GET"
        assert headers(request)["private-token"] == TOKEN
        assert "job-token" not in headers(request)

    result = receipt(args)
    assert result["status"] == "succeeded"
    assert result["archive_sha256"]
    assert result["workspace_deleted"] is True
    assert result["target_repository_modified"] is False
    assert not scans[0].exists()
    assert TOKEN not in json.dumps(result)


def test_job_token_is_not_required_for_target_reads(launch_case):
    args, requests, scans, _ = launch_case
    assert launcher.run(args) == 0
    assert len(requests) == 3
    assert len(scans) == 1


def test_missing_provisioned_token_does_not_fall_back(launch_case, monkeypatch):
    args, requests, scans, _ = launch_case
    monkeypatch.delenv("WINTERMUTE_GITLAB_READ_TOKEN")
    monkeypatch.setenv("CI_JOB_TOKEN", "synthetic-job-token")
    monkeypatch.setenv("GITLAB_TOKEN", "synthetic-general-token")
    monkeypatch.setenv("GITLAB_ACTION_TOKEN", "synthetic-action-token")

    assert launcher.run(args) == 2
    assert requests == []
    assert scans == []
    assert "WINTERMUTE_GITLAB_READ_TOKEN must be set" in receipt(args)["error"]


def test_commit_404_stops_without_authentication_fallback(launch_case):
    args, requests, scans, control = launch_case
    control["commit_status"] = 404

    assert launcher.run(args) == 2
    assert len(requests) == 2
    assert scans == []
    assert "commit request failed with HTTP 404" in receipt(args)["error"]


def test_wrong_commit_stops_before_archive_download(launch_case):
    args, requests, scans, control = launch_case
    control["commit_id"] = "b" * 40

    assert launcher.run(args) == 2
    assert len(requests) == 2
    assert scans == []
    assert "exact requested commit" in receipt(args)["error"]


def test_archive_failure_stops_before_scanner(launch_case):
    args, requests, scans, control = launch_case
    control["archive_status"] = 403

    assert launcher.run(args) == 2
    assert len(requests) == 3
    assert scans == []
    result = receipt(args)
    assert "archive request failed with HTTP 403" in result["error"]
    assert result["workspace_deleted"] is True


def test_scanner_environment_removes_gitlab_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("WINTERMUTE_GITLAB_READ_TOKEN", TOKEN)
    monkeypatch.setenv("CI_JOB_TOKEN", "synthetic-job-token")
    monkeypatch.setenv("GITLAB_TOKEN", "synthetic-general-token")
    monkeypatch.setenv("GITLAB_ACTION_TOKEN", "synthetic-action-token")

    environment = launcher.scanner_environment(tmp_path)
    for name in (
        "WINTERMUTE_GITLAB_READ_TOKEN",
        "CI_JOB_TOKEN",
        "GITLAB_TOKEN",
        "GITLAB_ACTION_TOKEN",
    ):
        assert name not in environment


def test_multiple_authentication_methods_are_rejected():
    with pytest.raises(launcher.LauncherError, match="one authentication"):
        launcher.request_headers(
            "synthetic-job-token",
            api_token=TOKEN,
            accept="application/json",
        )


@pytest.mark.parametrize("token", ["bad\ntoken", "bad\rtoken", ""])
def test_invalid_token_is_rejected(token):
    with pytest.raises(launcher.LauncherError):
        launcher.request_headers(api_token=token, accept="application/json")
