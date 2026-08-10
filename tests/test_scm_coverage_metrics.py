from __future__ import annotations

from wintermute.scm.coverage.metrics import (
    coverage_breakdowns,
    coverage_metrics,
)
from wintermute.scm.coverage.models import (
    CoverageClassification,
    CoverageReport,
    MappingConfidence,
    MappingMethod,
    RepositoryCoverage,
    RepositoryProjectMapping,
)
from wintermute.scm.coverage.reporting import (
    coverage_report_payload,
)
from wintermute.scm.models import (
    Repository,
)


def row(
    name: str,
    *,
    eligible: bool = True,
    onboarded: bool | None = True,
    mapped: bool = True,
    scanned: bool = True,
    fresh: bool = True,
) -> RepositoryCoverage:
    repository = Repository(
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
        archived=not eligible,
        activity_status="active",
        languages=("python",),
    )
    mapping = (
        RepositoryProjectMapping(
            repository_external_id=(
                repository.external_id
            ),
            name_with_owner=(
                repository.name_with_owner
            ),
            method=MappingMethod.EXPLICIT,
            confidence=(
                MappingConfidence.AUTHORITATIVE
            ),
            authoritative=True,
            candidates=(
                # Accepted candidate details are not
                # needed by metric calculations.
                __import__(
                    "wintermute.scm.coverage.models",
                    fromlist=["MappingProjectRef"],
                ).MappingProjectRef(
                    project_id=f"P_{name}",
                    name=name,
                    href=(
                        "https://bd.example/api/"
                        f"projects/P_{name}"
                    ),
                ),
            ),
        )
        if mapped
        else RepositoryProjectMapping(
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
    )

    if not eligible:
        classification = (
            CoverageClassification.EXCLUDED
        )
    elif not onboarded:
        classification = (
            CoverageClassification
            .NOT_ONBOARDED
        )
    elif not mapped:
        classification = (
            CoverageClassification
            .ONBOARDED_NOT_MAPPED
        )
    elif not scanned:
        classification = (
            CoverageClassification
            .MAPPED_NEVER_SCANNED
        )
    elif fresh:
        classification = (
            CoverageClassification
            .SCANNED_CURRENT
        )
    else:
        classification = (
            CoverageClassification
            .SCANNED_STALE
        )

    return RepositoryCoverage(
        repository=repository,
        eligible=eligible,
        onboarded=onboarded,
        mapping=mapping,
        classification=classification,
        exclusion_reason=(
            "archived"
            if not eligible
            else ""
        ),
        successful_scan=scanned,
        fresh_scan=fresh and scanned,
    )


def test_coverage_metrics_use_eligible_denominator() -> None:
    rows = (
        row("current"),
        row(
            "stale",
            fresh=False,
        ),
        row(
            "not-mapped",
            mapped=False,
            scanned=False,
            fresh=False,
        ),
        row(
            "not-onboarded",
            onboarded=False,
            mapped=False,
            scanned=False,
            fresh=False,
        ),
        row(
            "excluded",
            eligible=False,
            scanned=False,
            fresh=False,
        ),
    )
    metrics = coverage_metrics(rows)

    assert metrics.onboarding.as_dict() == {
        "numerator": 3,
        "denominator": 4,
        "percentage": 75.0,
    }
    assert metrics.mapping.as_dict() == {
        "numerator": 2,
        "denominator": 4,
        "percentage": 50.0,
    }
    assert metrics.scan.as_dict() == {
        "numerator": 2,
        "denominator": 4,
        "percentage": 50.0,
    }
    assert metrics.fresh_scan.as_dict() == {
        "numerator": 1,
        "denominator": 4,
        "percentage": 25.0,
    }


def test_zero_denominator_is_not_fabricated() -> None:
    metrics = coverage_metrics(
        [
            row(
                "excluded",
                eligible=False,
                scanned=False,
                fresh=False,
            )
        ]
    )

    assert (
        metrics.onboarding.denominator
        == 0
    )
    assert (
        metrics.onboarding.percentage
        is None
    )


def test_breakdowns_include_provider_and_classification() -> None:
    rows = (
        row("current"),
        row(
            "not-mapped",
            mapped=False,
            scanned=False,
            fresh=False,
        ),
    )
    breakdowns = coverage_breakdowns(
        rows
    )

    assert (
        breakdowns["provider"]["github"][
            "eligible_repository_count"
        ]
        == 2
    )
    assert (
        "scanned-current"
        in breakdowns["classification"]
    )
    assert (
        "onboarded-not-mapped"
        in breakdowns["classification"]
    )


def test_report_payload_is_deterministic() -> None:
    report = CoverageReport(
        repositories=(
            row("z-service"),
            row(
                "a-service",
                mapped=False,
                scanned=False,
                fresh=False,
            ),
        )
    )
    payload = coverage_report_payload(
        report
    )

    assert [
        value["name"]
        for value in payload[
            "repositories"
        ]
    ] == [
        "a-service",
        "z-service",
    ]
    assert payload[
        "metrics"
    ]["mapping_coverage"][
        "percentage"
    ] == 50.0
    assert payload[
        "classification_counts"
    ] == {
        "onboarded-not-mapped": 1,
        "scanned-current": 1,
    }
