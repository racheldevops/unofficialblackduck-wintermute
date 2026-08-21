from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from wintermute.jira import pipeline
from wintermute.jira.pipeline_lock import (
    PipelineLock,
    clear_lock,
    inspect_lock,
)


def test_lock_is_removed_after_normal_exit(
    tmp_path: Path,
) -> None:
    path = tmp_path / "pipeline.lock"

    with PipelineLock(
        path,
        "run-1",
        3600,
        heartbeat_seconds=0.05,
        install_signal_handlers=False,
    ):
        snapshot = inspect_lock(path)

        assert snapshot.exists
        assert snapshot.details["run_id"] == "run-1"
        assert snapshot.details["schema_version"] == 2

    assert not path.exists()


def test_heartbeat_refreshes_lock(
    tmp_path: Path,
) -> None:
    path = tmp_path / "pipeline.lock"

    with PipelineLock(
        path,
        "run-heartbeat",
        3600,
        heartbeat_seconds=0.05,
        install_signal_handlers=False,
    ):
        first = inspect_lock(path)
        first_heartbeat = float(
            first.details["heartbeat_at_epoch"]
        )
        time.sleep(0.15)
        second = inspect_lock(path)

        assert float(
            second.details["heartbeat_at_epoch"]
        ) > first_heartbeat
        assert second.age_seconds is not None
        assert second.age_seconds < 1


def test_second_lock_is_rejected(
    tmp_path: Path,
) -> None:
    path = tmp_path / "pipeline.lock"

    with PipelineLock(
        path,
        "run-owner",
        3600,
        install_signal_handlers=False,
    ):
        with pytest.raises(
            RuntimeError,
            match="Another Jira pipeline run",
        ):
            with PipelineLock(
                path,
                "run-second",
                3600,
                install_signal_handlers=False,
            ):
                pass


def test_stale_lock_is_archived_on_acquire(
    tmp_path: Path,
) -> None:
    path = tmp_path / "pipeline.lock"
    path.write_text(
        json.dumps(
            {
                "run_id": "old-run",
                "token": "old-token",
                "created_at_epoch": (
                    time.time() - 7200
                ),
                "heartbeat_at_epoch": (
                    time.time() - 7200
                ),
            }
        ),
        encoding="utf-8",
    )

    with PipelineLock(
        path,
        "new-run",
        60,
        install_signal_handlers=False,
    ) as lock:
        assert lock.stale_archive_path is not None
        assert lock.stale_archive_path.exists()
        assert (
            inspect_lock(path).details["run_id"]
            == "new-run"
        )

    assert not path.exists()


def test_clear_requires_matching_run_id(
    tmp_path: Path,
) -> None:
    path = tmp_path / "pipeline.lock"
    path.write_text(
        json.dumps(
            {
                "run_id": "expected-run",
                "token": "token",
                "heartbeat_at_epoch": (
                    time.time() - 3600
                ),
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        RuntimeError,
        match="does not match",
    ):
        clear_lock(
            path,
            expected_run_id="wrong-run",
            minimum_age_seconds=60,
        )

    assert path.exists()


def test_clear_archives_expected_stale_lock(
    tmp_path: Path,
) -> None:
    path = tmp_path / "pipeline.lock"
    path.write_text(
        json.dumps(
            {
                "run_id": "expected-run",
                "token": "expected-token",
                "heartbeat_at_epoch": (
                    time.time() - 3600
                ),
            }
        ),
        encoding="utf-8",
    )

    archived = clear_lock(
        path,
        expected_run_id="expected-run",
        expected_token="expected-token",
        minimum_age_seconds=60,
    )

    assert archived is not None
    assert archived.exists()
    assert not path.exists()


def test_clear_rejects_recent_lock_without_force(
    tmp_path: Path,
) -> None:
    path = tmp_path / "pipeline.lock"
    path.write_text(
        json.dumps(
            {
                "run_id": "active-run",
                "token": "token",
                "heartbeat_at_epoch": time.time(),
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        RuntimeError,
        match="too recent",
    ):
        clear_lock(
            path,
            expected_run_id="active-run",
            minimum_age_seconds=900,
        )

    assert path.exists()


def test_pipeline_uses_durable_lock() -> None:
    assert issubclass(
        pipeline.PipelineLock,
        PipelineLock,
    )


def test_helm_templates_include_lock_support() -> None:
    root = Path(__file__).resolve().parents[1]
    chart = (
        root
        / "deploy"
        / "charts"
        / "blackduck-wintermute-jira"
    )
    main_template = (
        chart / "templates" / "cronjob.yaml"
    ).read_text(encoding="utf-8")
    maintenance = (
        chart
        / "templates"
        / "lock-maintenance-cronjob.yaml"
    ).read_text(encoding="utf-8")

    assert "--lock-stale-seconds" in main_template
    assert "pipeline.lockStaleSeconds" in main_template
    assert "fieldPath: metadata.name" in main_template
    assert "fieldPath: metadata.uid" in main_template

    assert "suspend: true" in maintenance
    assert "wintermute.jira.pipeline_lock" in maintenance
    assert "- inspect" in maintenance
    assert "persistentVolumeClaim:" in maintenance
