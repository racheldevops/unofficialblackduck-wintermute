from __future__ import annotations

from pathlib import Path

import pytest

from wintermute.blackduck.cohort import (
    CohortError,
    load_cohort,
    write_cohort,
)
from wintermute.blackduck.collector import (
    CollectionRunResult,
    TargetCollectionResult,
)
from wintermute.blackduck.criteria import (
    jira_parent_rollup_criteria,
)
from wintermute.blackduck.manifest import (
    CollectionManifest,
)
from wintermute.blackduck.models import (
    CollectionTarget,
    LineageContext,
    NormalizedFinding,
    ProjectVersionRef,
)
from wintermute.blackduck.pull import (
    PullExecution,
    PullRequest,
)
from wintermute.blackduck.scopes import (
    CollectionScope,
)


def execution() -> PullExecution:
    child = ProjectVersionRef(
        instance_url="https://bd.example",
        project="Service",
        version="1",
        version_href=(
            "https://bd.example/projects/s/"
            "versions/1"
        ),
    )
    parent = ProjectVersionRef(
        instance_url="https://bd.example",
        project="Product",
        version="2",
        version_href=(
            "https://bd.example/products/p/"
            "versions/2"
        ),
    )
    context = LineageContext(
        parent=parent,
        child=child,
        detection_method="api-href",
    )
    target = CollectionTarget(
        project_version=child,
        lineage_contexts=(context,),
    )
    finding = NormalizedFinding(
        project_version=child,
        component="openssl",
        component_version="3.0.1",
        vulnerability="CVE-2026-0001",
        severity="CRITICAL",
        score=9.8,
        exploit_available=True,
        lineage_contexts=(context,),
        attributes={"example": "value"},
    )
    target_result = TargetCollectionResult(
        target=target,
        findings=(finding,),
        failures=(),
        elapsed_seconds=1.2,
    )
    request = PullRequest(
        scope=CollectionScope.PARENT_ROLLUP,
        criteria=jira_parent_rollup_criteria(),
        workers=4,
        component_workers=2,
    )
    manifest = CollectionManifest(
        scope=CollectionScope.PARENT_ROLLUP,
        targets=(target,),
        generated_at="2026-08-06T00:00:00Z",
    )

    return PullExecution(
        request=request,
        manifest=manifest,
        collection=CollectionRunResult(
            target_results=(target_result,)
        ),
    )


def test_cohort_round_trip(tmp_path: Path) -> None:
    directory = write_cohort(
        tmp_path / "cohorts",
        execution(),
        cohort_id="cohort-001",
    )
    loaded = load_cohort(directory)

    assert directory.name == "cohort-001"
    assert (directory / "READY").is_file()
    assert loaded.cohort_id == "cohort-001"
    assert len(loaded.findings) == 1
    assert loaded.findings[0].external_id == (
        execution().collection.findings[0]
        .external_id
    )
    assert (
        loaded.findings[0]
        .lineage_contexts[0]
        .parent.project
        == "Product"
    )


def test_unready_cohort_is_rejected(
    tmp_path: Path,
) -> None:
    directory = write_cohort(
        tmp_path / "cohorts",
        execution(),
        cohort_id="cohort-002",
    )
    (directory / "READY").unlink()

    with pytest.raises(
        CohortError,
        match="not ready",
    ):
        load_cohort(directory)


def test_tampered_cohort_is_rejected(
    tmp_path: Path,
) -> None:
    directory = write_cohort(
        tmp_path / "cohorts",
        execution(),
        cohort_id="cohort-003",
    )
    findings_path = (
        directory
        / "normalized-findings.json"
    )
    findings_path.write_text(
        "{}\n",
        encoding="utf-8",
    )

    with pytest.raises(
        CohortError,
        match="Checksum mismatch",
    ):
        load_cohort(directory)


def test_existing_cohort_is_not_overwritten(
    tmp_path: Path,
) -> None:
    root = tmp_path / "cohorts"
    write_cohort(
        root,
        execution(),
        cohort_id="cohort-004",
    )

    with pytest.raises(
        CohortError,
        match="already exists",
    ):
        write_cohort(
            root,
            execution(),
            cohort_id="cohort-004",
        )
