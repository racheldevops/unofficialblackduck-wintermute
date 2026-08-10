from __future__ import annotations

from datetime import datetime, timezone

from wintermute.scm.controls import (
    ControlFailure,
    ControlInventory,
    ControlKind,
    ControlObservation,
    ControlState,
)
from wintermute.scm.coverage.models import (
    BlackDuckInventoryObservation,
    BlackDuckProjectObservation,
    BlackDuckVersionObservation,
    CoverageClassification,
    MappingConfidence,
    MappingMethod,
    MappingProjectRef,
    MappingResult,
    RepositoryProjectMapping,
)
from wintermute.scm.coverage.reconciliation import (
    reconcile_coverage,
)
from wintermute.scm.models import (
    Repository,
    RepositoryExclusion,
    RepositoryInventory,
)


NOW = datetime(
    2026,
    8,
    31,
    tzinfo=timezone.utc,
)


def repository(
    name: str = "service",
) -> Repository:
    return Repository(
        provider="github",
        provider_instance="github.example",
        tenant_id="O_acme",
        repository_id=f"R_{name}",
        namespace="acme",
        name=name,
        canonical_url=(
            f"https://github.example/acme/{name}"
        ),
        visibility="private",
        activity_status="active",
        languages=("python",),
    )


def inventory(
    value: Repository,
    *,
    excluded: bool = False,
) -> RepositoryInventory:
    return RepositoryInventory(
        repositories=(
            ()
            if excluded
            else (value,)
        ),
        exclusions=(
            (
                RepositoryExclusion(
                    repository=value,
                    reason="archived",
                ),
            )
            if excluded
            else ()
        ),
        failures=(),
        discovered_count=1,
    )


def controls(
    value: Repository,
    *,
    policy: ControlState = (
        ControlState.COMPLIANT
    ),
    workflow: ControlState = (
        ControlState.COMPLIANT
    ),
    failed: bool = False,
) -> ControlInventory:
    return ControlInventory(
        observations=(
            ControlObservation(
                provider="github",
                provider_instance=(
                    "github.example"
                ),
                tenant_id="O_acme",
                repository_external_id=(
                    value.external_id
                ),
                name_with_owner=(
                    value.name_with_owner
                ),
                control=(
                    ControlKind
                    .ONBOARDING_POLICY
                ),
                state=policy,
                source="test",
            ),
            ControlObservation(
                provider="github",
                provider_instance=(
                    "github.example"
                ),
                tenant_id="O_acme",
                repository_external_id=(
                    value.external_id
                ),
                name_with_owner=(
                    value.name_with_owner
                ),
                control=(
                    ControlKind
                    .REQUIRED_SCAN_WORKFLOW
                ),
                state=(
                    ControlState.FAILED
                    if failed
                    else workflow
                ),
                source="test",
            ),
        ),
        failures=(
            (
                ControlFailure(
                    provider="github",
                    provider_instance=(
                        "github.example"
                    ),
                    tenant_id="O_acme",
                    stage="read-rulesets",
                    error="temporary failure",
                ),
            )
            if failed
            else ()
        ),
    )


def project(
    *,
    scan_at: str = "",
    receipt_id: str = "",
    evidence_complete: bool = True,
) -> BlackDuckProjectObservation:
    return BlackDuckProjectObservation(
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
                last_successful_scan_at=(
                    scan_at
                ),
                receipt_id=receipt_id,
                scan_evidence_complete=(
                    evidence_complete
                ),
            ),
        ),
    )


def mapping(
    value: Repository,
    *,
    authoritative: bool = True,
    conflict: bool = False,
) -> MappingResult:
    project_reference = MappingProjectRef(
        project_id="project-a",
        name="Service",
        href=(
            "https://bd.example/api/"
            "projects/project-a"
        ),
    )
    decision = RepositoryProjectMapping(
        repository_external_id=(
            value.external_id
        ),
        name_with_owner=(
            value.name_with_owner
        ),
        method=(
            MappingMethod.EXPLICIT
            if authoritative
            else MappingMethod
            .EXACT_NAMESPACE_NAME
        ),
        confidence=(
            MappingConfidence.AMBIGUOUS
            if conflict
            else (
                MappingConfidence
                .AUTHORITATIVE
                if authoritative
                else MappingConfidence.HIGH
            )
        ),
        authoritative=(
            authoritative
            and not conflict
        ),
        candidates=(
            (project_reference,)
        ),
        conflicts=(
            (
                "conflicting mapping signals",
            )
            if conflict
            else ()
        ),
    )

    return MappingResult(
        mappings=(decision,)
    )


def classification(
    value: Repository,
    *,
    repository_inventory: (
        RepositoryInventory | None
    ) = None,
    control_inventory: (
        ControlInventory | None
    ) = None,
    blackduck: (
        BlackDuckInventoryObservation
        | None
    ) = None,
    mapping_result: (
        MappingResult | None
    ) = None,
) -> CoverageClassification:
    result = reconcile_coverage(
        (
            repository_inventory
            or inventory(value)
        ),
        (
            control_inventory
            or controls(value)
        ),
        (
            blackduck
            or BlackDuckInventoryObservation(
                projects=(project(),)
            )
        ),
        (
            mapping_result
            or mapping(value)
        ),
        now=NOW,
        freshness_sla_days=30,
    )

    return (
        result.repositories[0]
        .classification
    )


def test_excluded_repository_is_separate() -> None:
    value = repository()

    assert classification(
        value,
        repository_inventory=inventory(
            value,
            excluded=True,
        ),
    ) == CoverageClassification.EXCLUDED


def test_not_onboarded_is_separate_from_mapping() -> None:
    value = repository()

    assert classification(
        value,
        control_inventory=controls(
            value,
            policy=(
                ControlState.NONCOMPLIANT
            ),
        ),
    ) == (
        CoverageClassification
        .NOT_ONBOARDED
    )


def test_inferred_mapping_is_not_accepted() -> None:
    value = repository()

    assert classification(
        value,
        mapping_result=mapping(
            value,
            authoritative=False,
        ),
    ) == (
        CoverageClassification
        .ONBOARDED_NOT_MAPPED
    )


def test_project_registration_is_not_a_scan() -> None:
    value = repository()

    assert classification(
        value,
    ) == (
        CoverageClassification
        .MAPPED_NEVER_SCANNED
    )


def test_fresh_successful_scan_is_current() -> None:
    value = repository()

    assert classification(
        value,
        blackduck=(
            BlackDuckInventoryObservation(
                projects=(
                    project(
                        scan_at=(
                            "2026-08-15T00:00:00Z"
                        )
                    ),
                )
            )
        ),
    ) == (
        CoverageClassification
        .SCANNED_CURRENT
    )


def test_freshness_boundary_is_inclusive() -> None:
    value = repository()

    assert classification(
        value,
        blackduck=(
            BlackDuckInventoryObservation(
                projects=(
                    project(
                        scan_at=(
                            "2026-08-01T00:00:00Z"
                        )
                    ),
                )
            )
        ),
    ) == (
        CoverageClassification
        .SCANNED_CURRENT
    )


def test_old_successful_scan_is_stale() -> None:
    value = repository()

    assert classification(
        value,
        blackduck=(
            BlackDuckInventoryObservation(
                projects=(
                    project(
                        scan_at=(
                            "2026-07-31T23:59:59Z"
                        )
                    ),
                )
            )
        ),
    ) == (
        CoverageClassification
        .SCANNED_STALE
    )


def test_receipt_without_time_is_scanned_but_not_fresh() -> None:
    value = repository()
    result = reconcile_coverage(
        inventory(value),
        controls(value),
        BlackDuckInventoryObservation(
            projects=(
                project(
                    receipt_id="receipt-a"
                ),
            )
        ),
        mapping(value),
        now=NOW,
    )
    row = result.repositories[0]

    assert row.successful_scan is True
    assert row.fresh_scan is False
    assert row.classification == (
        CoverageClassification
        .SCANNED_STALE
    )


def test_mapping_conflict_is_not_silently_accepted() -> None:
    value = repository()

    assert classification(
        value,
        mapping_result=mapping(
            value,
            conflict=True,
        ),
    ) == (
        CoverageClassification
        .MAPPING_CONFLICT
    )


def test_control_failure_is_provider_error() -> None:
    value = repository()

    assert classification(
        value,
        control_inventory=controls(
            value,
            failed=True,
        ),
    ) == (
        CoverageClassification
        .PROVIDER_ERROR
    )


def test_missing_scan_evidence_is_unknown() -> None:
    value = repository()

    assert classification(
        value,
        blackduck=(
            BlackDuckInventoryObservation(
                projects=(
                    project(
                        evidence_complete=False
                    ),
                )
            )
        ),
    ) == CoverageClassification.UNKNOWN
