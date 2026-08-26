from __future__ import annotations

from pathlib import Path

import pytest

from wintermute.scm.coverage.models import (
    BlackDuckInventoryObservation,
    BlackDuckProjectObservation,
    BlackDuckVersionObservation,
)
from wintermute.scm.coverage.scan_evidence import (
    apply_scan_evidence,
)
from wintermute.scm.coverage.snapshot import (
    load_coverage_snapshot,
    mark_coverage_complete,
    write_coverage_snapshot,
)


def blackduck() -> BlackDuckInventoryObservation:
    return BlackDuckInventoryObservation(
        projects=(
            BlackDuckProjectObservation(
                instance_url="https://bd.example",
                project_id="project-a",
                name="Service",
                href=(
                    "https://bd.example/api/"
                    "projects/project-a"
                ),
                versions=(
                    BlackDuckVersionObservation(
                        project_id="project-a",
                        version_id="version-a",
                        name="1.0",
                        href=(
                            "https://bd.example/api/"
                            "projects/project-a/"
                            "versions/version-a"
                        ),
                    ),
                ),
            ),
        )
    )


def test_complete_scan_evidence_requires_every_version() -> None:
    with pytest.raises(
        ValueError,
        match="omitted",
    ):
        apply_scan_evidence(
            blackduck(),
            {
                "schema_version": 1,
                "complete": True,
                "observations": [],
            },
        )


def test_scan_evidence_enriches_exact_version() -> None:
    result = apply_scan_evidence(
        blackduck(),
        {
            "schema_version": 1,
            "complete": True,
            "observations": [
                {
                    "project_id": "project-a",
                    "version_id": "version-a",
                    "bom_exists": True,
                    "code_location_count": 1,
                    "last_successful_scan_at": (
                        "2026-08-15T00:00:00Z"
                    ),
                    "scan_source": "blackduck-api",
                    "scanner_type": "detect",
                    "receipt_id": "receipt-a",
                }
            ],
        },
    )
    version = (
        result.projects[0].versions[0]
    )

    assert version.scan_evidence_complete is True
    assert version.successful_scan_known is True
    assert version.code_location_count == 1


def test_unknown_scan_identity_is_rejected() -> None:
    with pytest.raises(
        ValueError,
        match="unknown",
    ):
        apply_scan_evidence(
            blackduck(),
            {
                "schema_version": 1,
                "complete": False,
                "observations": [
                    {
                        "project_id": "missing",
                        "version_id": "missing",
                    }
                ],
            },
        )


def test_coverage_snapshot_round_trip(
    tmp_path: Path,
) -> None:
    from tests.test_scm_coverage_reconciliation import (
        NOW,
        controls,
        inventory,
        mapping,
        project,
        repository,
    )
    from wintermute.scm.coverage.pipeline import (
        CoverageExecution,
    )
    from wintermute.scm.coverage.reconciliation import (
        reconcile_coverage,
    )
    from wintermute.scm.snapshots import (
        load_inventory_snapshot,
        write_inventory_snapshot,
    )
    from wintermute.scm.models import ScmTenant

    value = repository()
    scm_directory = write_inventory_snapshot(
        tmp_path / "scm",
        ScmTenant(
            provider="github",
            provider_instance="github.example",
            tenant_id="O_acme",
            namespace="acme",
        ),
        inventory(value),
        snapshot_id="scm-source",
    )
    source = load_inventory_snapshot(
        scm_directory
    )
    blackduck_inventory = (
        BlackDuckInventoryObservation(
            projects=(
                project(
                    scan_at=(
                        "2026-08-15T00:00:00Z"
                    )
                ),
            )
        )
    )
    mappings = mapping(value)
    report = reconcile_coverage(
        source.inventory,
        controls(value),
        blackduck_inventory,
        mappings,
        now=NOW,
    )
    execution = CoverageExecution(
        source_snapshot=source,
        blackduck=blackduck_inventory,
        mappings=mappings,
        report=report,
    )
    directory = write_coverage_snapshot(
        tmp_path / "coverage",
        execution,
        snapshot_id="coverage-1",
    )
    mark_coverage_complete(directory)
    loaded = load_coverage_snapshot(
        directory
    )

    assert loaded.snapshot_id == "coverage-1"
    assert (
        loaded.coverage_report[
            "repository_count"
        ]
        == 1
    )
    assert (
        loaded.scan_gaps["gap_count"]
        == 0
    )
    assert (
        directory / "COMPLETE"
    ).is_file()
