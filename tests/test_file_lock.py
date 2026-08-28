from __future__ import annotations

import json
import socket
import time
from pathlib import Path

import pytest

from wintermute import file_lock
from wintermute.file_lock import (
    FileLock,
    LockUnavailableError,
)
from wintermute.jira.pipeline_lock import (
    PipelineLock,
    inspect_lock,
)


def test_file_lock_reuses_pipeline_lock() -> None:
    assert issubclass(
        FileLock,
        PipelineLock,
    )


def test_file_lock_releases_normally(
    tmp_path: Path,
) -> None:
    path = tmp_path / "action.lock"

    with FileLock(
        path,
        stale_seconds=60,
        heartbeat_seconds=0.05,
        install_signal_handlers=False,
    ):
        assert inspect_lock(path).exists

    assert not path.exists()


def test_file_lock_rejects_live_owner(
    tmp_path: Path,
) -> None:
    path = tmp_path / "action.lock"

    with FileLock(
        path,
        stale_seconds=60,
        install_signal_handlers=False,
    ):
        with pytest.raises(
            LockUnavailableError,
        ):
            with FileLock(
                path,
                stale_seconds=60,
                install_signal_handlers=False,
            ):
                pass


def test_file_lock_archives_dead_local_owner(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "action.lock"
    path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "run_id": "stopped-run",
                "token": "stopped-token",
                "hostname": socket.gethostname(),
                "pid": 12345,
                "created_at_epoch": time.time(),
                "heartbeat_at_epoch": time.time(),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        file_lock,
        "_process_exists",
        lambda pid: False,
    )

    with FileLock(
        path,
        stale_seconds=7200,
        install_signal_handlers=False,
    ) as lock:
        assert lock.stale_archive_path is not None
        assert lock.stale_archive_path.is_file()
        assert inspect_lock(path).exists

    assert not path.exists()


def test_file_lock_does_not_clear_remote_owner(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "action.lock"
    path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "run_id": "remote-run",
                "token": "remote-token",
                "hostname": "another-host",
                "pid": 12345,
                "created_at_epoch": time.time(),
                "heartbeat_at_epoch": time.time(),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        file_lock,
        "_process_exists",
        lambda pid: False,
    )

    with pytest.raises(
        LockUnavailableError,
    ):
        with FileLock(
            path,
            stale_seconds=7200,
            install_signal_handlers=False,
        ):
            pass

    assert path.exists()
