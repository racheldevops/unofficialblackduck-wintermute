from __future__ import annotations

import importlib.util
from pathlib import Path

from wintermute.blackduck.cohort import (
    prune_cohorts,
)


ROOT = Path(__file__).resolve().parents[1]
PARITY_SCRIPT = (
    ROOT
    / "scripts"
    / "validate_datadog_parity.py"
)
SPEC = importlib.util.spec_from_file_location(
    "validate_datadog_parity",
    PARITY_SCRIPT,
)
assert SPEC is not None
assert SPEC.loader is not None
parity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(parity)


def create_ready_cohort(
    root: Path,
    cohort_id: str,
    created_at: str,
) -> None:
    directory = root / cohort_id
    directory.mkdir(parents=True)
    (directory / "READY").write_text(
        "{}\n",
        encoding="utf-8",
    )
    (directory / "COMPLETE").write_text(
        "{}\n",
        encoding="utf-8",
    )
    (directory / "metadata.json").write_text(
        (
            "{"
            f'"cohort_id":"{cohort_id}",'
            f'"created_at":"{created_at}"'
            "}\n"
        ),
        encoding="utf-8",
    )


def test_cohort_retention_preserves_newest_and_protected(
    tmp_path: Path,
) -> None:
    root = tmp_path / "cohorts"
    root.mkdir()

    create_ready_cohort(
        root,
        "cohort-001",
        "2026-01-01T00:00:00Z",
    )
    create_ready_cohort(
        root,
        "cohort-002",
        "2026-01-02T00:00:00Z",
    )
    create_ready_cohort(
        root,
        "cohort-003",
        "2026-01-03T00:00:00Z",
    )

    removed = prune_cohorts(
        root,
        retain_count=1,
        protected_ids={"cohort-001"},
    )

    assert removed == ("cohort-002",)
    assert (root / "cohort-001").exists()
    assert (root / "cohort-003").exists()
    assert not (root / "cohort-002").exists()


def test_datadog_parity_compares_stable_ids() -> None:
    cohort_rows = [
        {
            "finding_external_id": "a",
        },
        {
            "finding_external_id": "b",
        },
    ]
    direct_rows = list(
        reversed(cohort_rows)
    )

    assert parity.compare_rows(
        cohort_rows,
        direct_rows,
    ) == {
        "ok": True,
        "cohort_count": 2,
        "direct_count": 2,
        "missing_from_cohort": [],
        "extra_in_cohort": [],
    }


def test_workflow_is_failure_independent_and_storage_isolated() -> None:
    text = (
        ROOT
        / "deploy"
        / "cohort"
        / "workflow-template.yaml"
    ).read_text(encoding="utf-8")

    assert "failFast: false" in text
    assert "jira.Succeeded || jira.Failed || jira.Errored" in text
    assert "claimName: blackduck-wintermute-cohorts" in text
    assert "claimName: blackduck-wintermute-source-data" in text
    assert "claimName: blackduck-wintermute-jira-data" in text
    assert "claimName: blackduck-wintermute-datadog-data" in text
    assert text.count(
        "mountPath: /var/lib/blackduck-wintermute/cohorts"
    ) == 4
    assert text.count("readOnly: true") >= 3
