from __future__ import annotations

import json
from pathlib import Path

from wintermute.scm.coverage.snapshot import (
    prune_coverage_snapshots,
)


def snapshot(
    root: Path,
    snapshot_id: str,
    created_at: str,
    *,
    complete: bool,
) -> Path:
    directory = root / snapshot_id
    directory.mkdir(
        parents=True
    )
    (
        directory / "metadata.json"
    ).write_text(
        json.dumps(
            {
                "snapshot_id": snapshot_id,
                "created_at": created_at,
            }
        ),
        encoding="utf-8",
    )
    (
        directory / "READY"
    ).write_text(
        "{}",
        encoding="utf-8",
    )

    if complete:
        (
            directory / "COMPLETE"
        ).write_text(
            "{}",
            encoding="utf-8",
        )

    return directory


def test_retention_removes_old_complete_snapshots(
    tmp_path: Path,
) -> None:
    old = snapshot(
        tmp_path,
        "old",
        "2026-01-01T00:00:00Z",
        complete=True,
    )
    new = snapshot(
        tmp_path,
        "new",
        "2026-02-01T00:00:00Z",
        complete=True,
    )

    removed = prune_coverage_snapshots(
        tmp_path,
        retain_count=1,
    )

    assert removed == ("old",)
    assert not old.exists()
    assert new.exists()


def test_retention_protects_incomplete_snapshots(
    tmp_path: Path,
) -> None:
    incomplete = snapshot(
        tmp_path,
        "incomplete",
        "2025-01-01T00:00:00Z",
        complete=False,
    )
    snapshot(
        tmp_path,
        "complete",
        "2026-01-01T00:00:00Z",
        complete=True,
    )

    removed = prune_coverage_snapshots(
        tmp_path,
        retain_count=1,
        require_complete=True,
    )

    assert removed == ()
    assert incomplete.exists()
