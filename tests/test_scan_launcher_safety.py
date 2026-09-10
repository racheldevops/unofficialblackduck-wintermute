from __future__ import annotations

import argparse
import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace
from urllib.request import Request

import pytest

from wintermute.scan import launcher


COMMIT = "a" * 40


def archive_bytes(
    entries: list[tuple[str, bytes]],
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, content in entries:
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


@pytest.fixture
def launch_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("WINTERMUTE_GITLAB_READ_TOKEN", "synthetic-read-token")
    monkeypatch.delenv("CI_API_V4_URL", raising=False)
    monkeypatch.setenv("CI_JOB_TOKEN", "synthetic-job-token")

    bridge = tmp_path / "fake-bridge"
    bridge.write_bytes(b"fake bridge; never executed")
    digest = hashlib.sha256(bridge.read_bytes()).hexdigest()

    args = argparse.Namespace(
        gitlab_api_url="https://gitlab.example.invalid/api/v4",
        project_id="42",
        commit_sha=COMMIT,
        registry=str(tmp_path / "registry.json"),
        expected_registry_sha256="b" * 64,
        expected_bridge_sha256=digest,
        bridge_executable=str(bridge),
        mode="dry-run",
        confirmation="",
        receipt_root=str(tmp_path / "receipts"),
        timeout=5,
        scan_timeout=10,
        insecure=False,
        ca_bundle=None,
    )
    monkeypatch.setattr(launcher, "load_registry", lambda *a, **k: {})
    monkeypatch.setattr(
        launcher,
        "resolve_scan",
        lambda *a, **k: SimpleNamespace(contract_id="scan-example"),
    )

    requests: list[str] = []

    def request_json(url, **kwargs):
        requests.append(url)
        if "/repository/commits/" in url:
            return {"id": COMMIT}
        return {
            "id": 42,
            "archived": False,
            "web_url": "https://gitlab.example.invalid/example/application",
            "path_with_namespace": "example/application",
            "default_branch": "main",
        }

    def download(url, destination, **kwargs):
        requests.append(url)
        content = archive_bytes([("project/main.py", b"print('test')\n")])
        destination.write_bytes(content)
        return hashlib.sha256(content).hexdigest()

    monkeypatch.setattr(launcher, "request_json", request_json)
    monkeypatch.setattr(launcher, "download_archive", download)
    return args, requests


def read_receipt(root: str) -> tuple[Path, dict]:
    paths = list(Path(root).glob("*/launcher-receipt.json"))
    assert len(paths) == 1
    path = paths[0]
    receipt = json.loads(path.read_text(encoding="utf-8"))
    checksums = json.loads(
        path.with_name("checksums.json").read_text(encoding="utf-8")
    )
    assert checksums["sha256"][path.name] == hashlib.sha256(
        path.read_bytes()
    ).hexdigest()
    return path, receipt


def test_success_uses_three_source_requests_and_retains_receipt(
    launch_case,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args, requests = launch_case
    workspaces: list[Path] = []

    def scan(scan_args, source_root, **kwargs):
        workspaces.append(source_root)
        receipt_root = Path(scan_args.receipt_root)
        assert not receipt_root.is_relative_to(
            Path(scan_args.launcher_temporary_root)
        )
        receipt_root.mkdir(parents=True)
        (receipt_root / "scan-result.json").write_text(
            '{"status": "planned"}',
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(launcher, "run_scan", scan)
    assert launcher.run(args) == 0

    path, receipt = read_receipt(args.receipt_root)
    assert receipt["status"] == "succeeded"
    assert receipt["workspace_deleted"] is True
    assert receipt["target_repository_modified"] is False
    assert (path.parent / "scan" / "scan-result.json").is_file()
    assert all(not workspace.exists() for workspace in workspaces)
    assert len(requests) == 3
    assert requests[-1].endswith(f"archive.tar.gz?sha={COMMIT}")


def test_invalid_confirmation_fails_before_any_request(
    launch_case,
) -> None:
    args, requests = launch_case
    args.mode = "execute"
    assert launcher.run(args) == 2

    _, receipt = read_receipt(args.receipt_root)
    assert "confirmation" in receipt["error"]
    assert requests == []


def test_invalid_registry_records_failure_without_requests(
    launch_case,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args, requests = launch_case

    def fail(*args, **kwargs):
        raise RuntimeError("Scan registry checksum mismatch")

    monkeypatch.setattr(launcher, "load_registry", fail)
    assert launcher.run(args) == 2
    _, receipt = read_receipt(args.receipt_root)
    assert "checksum mismatch" in receipt["error"]
    assert requests == []


def test_wrong_ci_instance_fails_without_requests(
    launch_case,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args, requests = launch_case
    monkeypatch.setenv("CI_API_V4_URL", "https://other.example.invalid/api/v4")
    assert launcher.run(args) == 2
    _, receipt = read_receipt(args.receipt_root)
    assert "CI instance" in receipt["error"]
    assert requests == []


def test_failure_receipt_redacts_credentials(
    launch_case,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args, _ = launch_case
    monkeypatch.setenv("BLACKDUCK_API_TOKEN", "synthetic-blackduck-token")

    def fail(*args, **kwargs):
        raise RuntimeError(
            "failure synthetic-job-token synthetic-blackduck-token"
        )

    monkeypatch.setattr(launcher, "run_scan", fail)
    assert launcher.run(args) == 2
    path, receipt = read_receipt(args.receipt_root)
    text = path.read_text(encoding="utf-8")
    assert "synthetic-job-token" not in text
    assert "synthetic-blackduck-token" not in text
    assert receipt["workspace_deleted"] is True
    assert "[REDACTED]" in receipt["error"]


def test_interrupt_retains_receipt_and_cleans_workspace(
    launch_case,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args, _ = launch_case

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(launcher, "run_scan", interrupt)
    assert launcher.run(args) == 130
    _, receipt = read_receipt(args.receipt_root)
    assert receipt["status"] == "interrupted"
    assert receipt["workspace_deleted"] is True


def test_cleanup_failure_is_not_success(
    launch_case,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args, _ = launch_case
    monkeypatch.setattr(launcher, "run_scan", lambda *a, **k: 0)
    original_rmtree = launcher.shutil.rmtree
    leftovers: list[Path] = []

    def fail_cleanup(path, *a, **k):
        leftovers.append(Path(path))
        raise OSError("synthetic cleanup failure")

    monkeypatch.setattr(launcher.shutil, "rmtree", fail_cleanup)
    try:
        assert launcher.run(args) == 2
        _, receipt = read_receipt(args.receipt_root)
        assert receipt["status"] == "cleanup-failed"
        assert receipt["workspace_deleted"] is False
    finally:
        for path in leftovers:
            original_rmtree(path, ignore_errors=True)


@pytest.mark.parametrize(
    "path",
    ["../outside", "/absolute", "project/../outside", "project\\file",
     "project/./file", "project//file", "C:/file", "project/\x00file"],
)
def test_unsafe_archive_paths_are_rejected(path: str) -> None:
    with pytest.raises(launcher.LauncherError, match="unsafe path"):
        launcher.safe_member_path(path)


@pytest.mark.parametrize(
    "entries, message",
    [
        ([("project/a", b"a"), ("project/a", b"b")], "duplicate"),
        ([("first/a", b"a"), ("second/b", b"b")], "top-level"),
    ],
)
def test_invalid_archive_is_removed(
    tmp_path: Path,
    entries,
    message: str,
) -> None:
    archive = tmp_path / "source.tar.gz"
    archive.write_bytes(archive_bytes(entries))
    destination = tmp_path / "workspace"
    with pytest.raises(launcher.LauncherError, match=message):
        launcher.extract_archive(archive, destination)
    assert not destination.exists()


def test_archive_member_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = tmp_path / "source.tar.gz"
    archive.write_bytes(archive_bytes([
        ("project/a", b"a"),
        ("project/b", b"b"),
    ]))
    monkeypatch.setattr(launcher, "MAX_ARCHIVE_MEMBERS", 1)
    with pytest.raises(launcher.LauncherError, match="member-count"):
        launcher.extract_archive(archive, tmp_path / "workspace")
    assert not (tmp_path / "workspace").exists()


def test_archive_expanded_byte_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = tmp_path / "source.tar.gz"
    archive.write_bytes(archive_bytes([("project/a", b"too large")]))
    monkeypatch.setattr(launcher, "MAX_EXTRACTED_BYTES", 2)
    with pytest.raises(launcher.LauncherError, match="extracted size"):
        launcher.extract_archive(archive, tmp_path / "workspace")


def test_redirect_is_rejected_before_following() -> None:
    handler = launcher.RejectRedirects()
    request = Request("https://gitlab.example.invalid/api/v4/projects/42")
    with pytest.raises(launcher.LauncherError, match="not forwarded"):
        handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://other.example.invalid/source",
        )


def test_scanner_environment_does_not_receive_scm_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CI_JOB_TOKEN", "job-token")
    monkeypatch.setenv("CI_REPOSITORY_URL", "https://token@example.invalid")
    monkeypatch.setenv("GITLAB_ACTION_TOKEN", "action-token")
    monkeypatch.setenv("GITHUB_TOKEN", "github-token")
    monkeypatch.setenv("PYTHONPATH", "/untrusted")
    monkeypatch.setenv("BLACKDUCK_API_TOKEN", "scanner-token")

    environment = launcher.scanner_environment(tmp_path)
    for name in (
        "CI_JOB_TOKEN",
        "CI_REPOSITORY_URL",
        "GITLAB_ACTION_TOKEN",
        "GITHUB_TOKEN",
        "PYTHONPATH",
    ):
        assert name not in environment
    assert environment["BLACKDUCK_API_TOKEN"] == "scanner-token"
    assert Path(environment["HOME"]).is_relative_to(tmp_path)
    assert Path(environment["TMPDIR"]).is_relative_to(tmp_path)


def test_scanner_timeout_stops_process_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}
    stopped: list[object] = []

    class FakeProcess:
        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired("synthetic-scanner", timeout)

    process = FakeProcess()

    def popen(command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        return process

    monkeypatch.setattr(launcher.subprocess, "Popen", popen)
    monkeypatch.setattr(
        launcher,
        "stop_process_tree",
        lambda value: stopped.append(value),
    )

    args = argparse.Namespace(
        registry=str(tmp_path / "registry.json"),
        expected_registry_sha256="a" * 64,
        expected_bridge_sha256="b" * 64,
        bridge_executable=str(tmp_path / "bridge"),
        mode="dry-run",
        confirmation="",
        scan_timeout=1,
        receipt_root=str(tmp_path / "receipts"),
        launcher_temporary_root=str(tmp_path / "temporary"),
    )
    with pytest.raises(launcher.LauncherError, match="timeout"):
        launcher.run_scan(
            args,
            tmp_path / "source",
            provider_instance="gitlab.example.invalid",
            project_id="42",
            commit=COMMIT,
        )

    assert captured["command"][1:4] == ["-I", "-m", "wintermute.scan.cli"]
    assert "--receipt-root" in captured["command"]
    assert captured["cwd"] != tmp_path / "source"
    assert stopped == [process]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), 0, -1])
def test_invalid_timeouts_are_rejected(value: float) -> None:
    with pytest.raises(launcher.LauncherError, match="finite and positive"):
        launcher.positive_timeout(value, "timeout")
