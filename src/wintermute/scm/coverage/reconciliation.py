from __future__ import annotations

from datetime import datetime, timedelta, timezone

from wintermute.scm.controls import (
    ControlInventory,
    ControlKind,
    ControlObservation,
    ControlState,
)
from wintermute.scm.coverage.models import (
    BlackDuckInventoryObservation,
    BlackDuckProjectObservation,
    CoverageClassification,
    CoverageReport,
    MappingConfidence,
    MappingMethod,
    MappingProjectRef,
    MappingResult,
    RepositoryCoverage,
    RepositoryProjectMapping,
)
from wintermute.scm.models import (
    Repository,
    RepositoryInventory,
)


def parse_timestamp(
    value: str,
) -> datetime | None:
    selected = str(
        value or ""
    ).strip()

    if not selected:
        return None

    normalized = (
        selected[:-1] + "+00:00"
        if selected.endswith("Z")
        else selected
    )

    try:
        parsed = datetime.fromisoformat(
            normalized
        )
    except ValueError:
        return None

    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
    ):
        return None

    return parsed.astimezone(
        timezone.utc
    )


def all_repositories(
    inventory: RepositoryInventory,
) -> tuple[Repository, ...]:
    return tuple(
        sorted(
            [
                *inventory.repositories,
                *(
                    exclusion.repository
                    for exclusion
                    in inventory.exclusions
                ),
            ],
            key=lambda value: (
                value.provider,
                value.provider_instance,
                value.name_with_owner.casefold(),
                value.repository_id,
            ),
        )
    )


def controls_by_repository(
    controls: ControlInventory,
) -> dict[
    str,
    tuple[ControlObservation, ...],
]:
    grouped: dict[
        str,
        list[ControlObservation],
    ] = {}

    for observation in controls.observations:
        grouped.setdefault(
            observation.repository_external_id,
            [],
        ).append(observation)

    return {
        key: tuple(values)
        for key, values in grouped.items()
    }


def control_for_kind(
    observations: tuple[
        ControlObservation,
        ...
    ],
    kind: ControlKind,
) -> ControlObservation | None:
    matches = [
        observation
        for observation in observations
        if observation.control == kind
    ]

    if len(matches) > 1:
        raise ValueError(
            f"Repository contains duplicate "
            f"{kind.value} controls"
        )

    return (
        matches[0]
        if matches
        else None
    )


def onboarding_state(
    observations: tuple[
        ControlObservation,
        ...
    ],
    *,
    provider_failed: bool,
) -> tuple[
    bool | None,
    bool,
    tuple[str, ...],
]:
    reasons: list[str] = []

    if provider_failed or any(
        observation.state
        == ControlState.FAILED
        for observation in observations
    ):
        return (
            None,
            True,
            (
                "SCM control collection failed",
            ),
        )

    policy = control_for_kind(
        observations,
        ControlKind.ONBOARDING_POLICY,
    )
    workflow = control_for_kind(
        observations,
        ControlKind.REQUIRED_SCAN_WORKFLOW,
    )

    if policy is None:
        return (
            None,
            False,
            (
                "Onboarding policy observation is missing",
            ),
        )

    if (
        policy.state
        == ControlState.NONCOMPLIANT
    ):
        return (
            False,
            False,
            (
                "Repository is not selected "
                "for onboarding",
            ),
        )

    if (
        policy.state
        != ControlState.COMPLIANT
    ):
        return (
            None,
            False,
            (
                "Onboarding policy state is "
                f"{policy.state.value}",
            ),
        )

    if workflow is None:
        return (
            None,
            False,
            (
                "Required scan workflow "
                "observation is missing",
            ),
        )

    if (
        workflow.state
        == ControlState.COMPLIANT
    ):
        reasons.append(
            "Repository is selected and an "
            "active scan workflow is required"
        )

        return (
            True,
            False,
            tuple(reasons),
        )

    if (
        workflow.state
        == ControlState.NONCOMPLIANT
    ):
        return (
            False,
            False,
            (
                "Repository is selected but no "
                "active scan workflow applies",
            ),
        )

    return (
        None,
        False,
        (
            "Required scan workflow state is "
            f"{workflow.state.value}",
        ),
    )


def empty_mapping(
    repository: Repository,
) -> RepositoryProjectMapping:
    return RepositoryProjectMapping(
        repository_external_id=(
            repository.external_id
        ),
        name_with_owner=(
            repository.name_with_owner
        ),
        method=MappingMethod.NONE,
        confidence=(
            MappingConfidence.INFERRED
        ),
        authoritative=False,
    )


def project_ref(
    project: BlackDuckProjectObservation,
) -> MappingProjectRef:
    return MappingProjectRef(
        project_id=project.project_id,
        name=project.name,
        href=project.href,
    )


def successful_scan_state(
    project: (
        BlackDuckProjectObservation | None
    ),
    *,
    now: datetime,
    freshness_sla_days: int,
) -> tuple[
    int,
    bool,
    str,
    bool,
    tuple[str, ...],
]:
    if project is None:
        return (
            0,
            False,
            False,
            "",
            False,
            (),
        )

    evidence_complete = (
        not project.versions
        or all(
            version.scan_evidence_complete
            for version in project.versions
        )
    )
    successful = [
        version
        for version in project.versions
        if version.successful_scan_known
    ]

    if not successful:
        return (
            len(project.versions),
            evidence_complete,
            False,
            "",
            False,
            (
                (
                    "Complete scan evidence confirms no "
                    "successful scan"
                )
                if evidence_complete
                else (
                    "Successful scan evidence is unavailable"
                )
            ),
        )

    timestamped = [
        (
            parsed,
            version.last_successful_scan_at,
        )
        for version in successful
        if (
            parsed := parse_timestamp(
                version.last_successful_scan_at
            )
        )
        is not None
    ]

    if not timestamped:
        return (
            len(project.versions),
            evidence_complete,
            True,
            "",
            False,
            (
                "Successful scan evidence has no "
                "valid completion timestamp",
            ),
        )

    latest, latest_text = max(
        timestamped,
        key=lambda value: value[0],
    )
    freshness_boundary = (
        now
        - timedelta(
            days=freshness_sla_days
        )
    )
    fresh = (
        latest >= freshness_boundary
    )

    return (
        len(project.versions),
        evidence_complete,
        True,
        latest_text,
        fresh,
        (
            (
                "Latest successful scan is "
                "within the freshness SLA"
            )
            if fresh
            else (
                "Latest successful scan is "
                "outside the freshness SLA"
            ),
        ),
    )


def reconcile_coverage(
    repositories: RepositoryInventory,
    controls: ControlInventory,
    blackduck: BlackDuckInventoryObservation,
    mappings: MappingResult,
    *,
    freshness_sla_days: int = 30,
    now: datetime | None = None,
) -> CoverageReport:
    if (
        type(freshness_sla_days) is not int
        or freshness_sla_days < 1
    ):
        raise ValueError(
            "freshness_sla_days must be positive"
        )

    selected_now = (
        now
        or datetime.now(
            timezone.utc
        )
    )

    if (
        selected_now.tzinfo is None
        or selected_now.utcoffset() is None
    ):
        raise ValueError(
            "Coverage reconciliation time "
            "must include a timezone"
        )

    selected_now = (
        selected_now.astimezone(
            timezone.utc
        )
    )
    excluded = {
        value.repository.external_id: (
            value.reason
        )
        for value in repositories.exclusions
    }
    controls_by_id = (
        controls_by_repository(
            controls
        )
    )
    mappings_by_id = {
        value.repository_external_id: value
        for value in mappings.mappings
    }

    if len(mappings_by_id) != len(
        mappings.mappings
    ):
        raise ValueError(
            "Mapping result contains duplicate "
            "repository decisions"
        )

    projects_by_id = {
        value.project_id: value
        for value in blackduck.projects
    }
    provider_failed = bool(
        controls.failures
    )
    results: list[
        RepositoryCoverage
    ] = []

    for repository in all_repositories(
        repositories
    ):
        reasons: list[str] = []
        exclusion_reason = excluded.get(
            repository.external_id,
            "",
        )
        eligible = not bool(
            exclusion_reason
        )
        mapping = mappings_by_id.get(
            repository.external_id,
            empty_mapping(repository),
        )
        repository_controls = (
            controls_by_id.get(
                repository.external_id,
                (),
            )
        )
        (
            onboarded,
            repository_provider_error,
            onboarding_reasons,
        ) = onboarding_state(
            repository_controls,
            provider_failed=provider_failed,
        )
        reasons.extend(
            onboarding_reasons
        )
        accepted_project = (
            projects_by_id.get(
                mapping.accepted_project_id
            )
            if mapping.accepted_project_id
            else None
        )

        if (
            mapping.accepted_project_id
            and accepted_project is None
        ):
            repository_provider_error = True
            reasons.append(
                "Accepted Black Duck project "
                "is absent from inventory"
            )

        (
            project_version_count,
            scan_evidence_complete,
            successful_scan,
            last_successful_scan_at,
            fresh_scan,
            scan_reasons,
        ) = successful_scan_state(
            accepted_project,
            now=selected_now,
            freshness_sla_days=(
                freshness_sla_days
            ),
        )
        reasons.extend(
            scan_reasons
        )
        mapping_conflict = (
            mapping.confidence
            in {
                MappingConfidence.AMBIGUOUS,
                MappingConfidence.REJECTED,
            }
            or bool(mapping.conflicts)
        )

        if exclusion_reason:
            classification = (
                CoverageClassification.EXCLUDED
            )
            reasons.append(
                f"Repository excluded: "
                f"{exclusion_reason}"
            )
        elif repository_provider_error:
            classification = (
                CoverageClassification
                .PROVIDER_ERROR
            )
        elif mapping_conflict:
            classification = (
                CoverageClassification
                .MAPPING_CONFLICT
            )
            reasons.extend(
                mapping.conflicts
            )
        elif onboarded is False:
            classification = (
                CoverageClassification
                .NOT_ONBOARDED
            )
        elif onboarded is None:
            classification = (
                CoverageClassification.UNKNOWN
            )
        elif not mapping.authoritative:
            if blackduck.failures:
                classification = (
                    CoverageClassification.UNKNOWN
                )
                reasons.append(
                    "Black Duck inventory is partial; "
                    "absence of a mapping is inconclusive"
                )
            else:
                classification = (
                    CoverageClassification
                    .ONBOARDED_NOT_MAPPED
                )
                reasons.append(
                    "No authoritative Black Duck "
                    "mapping exists"
                )
        elif not successful_scan:
            classification = (
                CoverageClassification
                .MAPPED_NEVER_SCANNED
                if scan_evidence_complete
                else CoverageClassification.UNKNOWN
            )
        elif fresh_scan:
            classification = (
                CoverageClassification
                .SCANNED_CURRENT
            )
        else:
            classification = (
                CoverageClassification
                .SCANNED_STALE
            )

        results.append(
            RepositoryCoverage(
                repository=repository,
                eligible=eligible,
                onboarded=onboarded,
                mapping=mapping,
                classification=(
                    classification
                ),
                blackduck_project=(
                    project_ref(
                        accepted_project
                    )
                    if accepted_project
                    is not None
                    else None
                ),
                exclusion_reason=(
                    exclusion_reason
                ),
                project_version_count=(
                    project_version_count
                ),
                scan_evidence_complete=(
                    scan_evidence_complete
                ),
                successful_scan=(
                    successful_scan
                ),
                last_successful_scan_at=(
                    last_successful_scan_at
                ),
                fresh_scan=fresh_scan,
                freshness_sla_days=(
                    freshness_sla_days
                ),
                reasons=tuple(reasons),
            )
        )

    return CoverageReport(
        repositories=tuple(results),
        orphaned_blackduck_projects=(
            mappings
            .orphaned_blackduck_projects
        ),
        provider_failure_count=(
            len(repositories.failures)
            + len(controls.failures)
        ),
        blackduck_failure_count=(
            len(blackduck.failures)
        ),
    )
