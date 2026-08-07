from __future__ import annotations

import json
from pathlib import Path

from wintermute.blackduck.cohort import (
    mark_cohort_complete,
    prune_cohorts,
)


def create_cohort(
    root: Path,
    cohort_id: str,
    created_at: str,
    *,
    complete: bool,
) -> Path:
    directory = root / cohort_id
    directory.mkdir(parents=True)
    (directory / "READY").write_text(
        "{}\n",
        encoding="utf-8",
    )
    (directory / "metadata.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "cohort_id": cohort_id,
                "created_at": created_at,
            }
        ),
        encoding="utf-8",
    )
    (directory / "checksums.json").write_text(
        json.dumps({"sha256": {}}),
        encoding="utf-8",
    )

    if complete:
        (directory / "COMPLETE").write_text(
            "{}\n",
            encoding="utf-8",
        )

    return directory


def test_incomplete_cohorts_are_never_pruned(
    tmp_path: Path,
) -> None:
    root = tmp_path / "cohorts"
    create_cohort(
        root,
        "cohort-incomplete",
        "2026-01-01T00:00:00Z",
        complete=False,
    )
    create_cohort(
        root,
        "cohort-complete-old",
        "2026-01-02T00:00:00Z",
        complete=True,
    )
    create_cohort(
        root,
        "cohort-complete-new",
        "2026-01-03T00:00:00Z",
        complete=True,
    )

    removed = prune_cohorts(
        root,
        retain_count=1,
    )

    assert removed == (
        "cohort-complete-old",
    )
    assert (
        root / "cohort-incomplete"
    ).exists()


def test_complete_marker_is_written_after_consumers(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from types import SimpleNamespace

    directory = tmp_path / "cohort"
    directory.mkdir()
    loaded = SimpleNamespace(
        cohort_id="cohort-001",
        directory=directory,
    )

    monkeypatch.setattr(
        "wintermute.blackduck.cohort.load_cohort",
        lambda value: loaded,
    )

    marker = mark_cohort_complete(
        directory,
        destination_statuses={
            "jira": "terminal",
            "datadog": "terminal",
        },
    )
    payload = json.loads(
        marker.read_text(encoding="utf-8")
    )

    assert payload["cohort_id"] == "cohort-001"
    assert payload["destination_statuses"] == {
        "jira": "terminal",
        "datadog": "terminal",
    }


def test_enabled_destination_cannot_be_finalized_when_omitted() -> None:
    import pytest

    from wintermute.blackduck.cohort_finalize import (
        destination_status,
    )

    with pytest.raises(
        RuntimeError,
        match="did not reach a terminal state",
    ):
        destination_status(
            "dry-run",
            "Omitted",
        )


def test_disabled_destination_accepts_omitted_task() -> None:
    from wintermute.blackduck.cohort_finalize import (
        destination_status,
    )

    assert destination_status(
        "disabled",
        "Omitted",
    ) == "disabled"
