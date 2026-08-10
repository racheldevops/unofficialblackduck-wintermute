from __future__ import annotations

from collections.abc import (
    Callable,
    Iterable,
)
from dataclasses import dataclass
from typing import Any

from wintermute.scm.coverage.models import (
    CoverageClassification,
    RepositoryCoverage,
)


@dataclass(frozen=True)
class CoverageMetric:
    numerator: int
    denominator: int

    def __post_init__(self) -> None:
        if (
            type(self.numerator) is not int
            or type(self.denominator) is not int
            or self.numerator < 0
            or self.denominator < 0
            or self.numerator
            > self.denominator
        ):
            raise ValueError(
                "Coverage metric counts are invalid"
            )

    @property
    def percentage(self) -> float | None:
        if self.denominator == 0:
            return None

        return round(
            (
                self.numerator
                / self.denominator
            )
            * 100,
            2,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "numerator": self.numerator,
            "denominator": self.denominator,
            "percentage": self.percentage,
        }


@dataclass(frozen=True)
class CoverageMetrics:
    onboarding: CoverageMetric
    mapping: CoverageMetric
    scan: CoverageMetric
    fresh_scan: CoverageMetric

    def as_dict(self) -> dict[str, Any]:
        return {
            "onboarding_coverage": (
                self.onboarding.as_dict()
            ),
            "mapping_coverage": (
                self.mapping.as_dict()
            ),
            "scan_coverage": (
                self.scan.as_dict()
            ),
            "fresh_scan_coverage": (
                self.fresh_scan.as_dict()
            ),
        }


def coverage_metrics(
    rows: Iterable[
        RepositoryCoverage
    ],
) -> CoverageMetrics:
    eligible = [
        row
        for row in rows
        if row.eligible
    ]
    eligible_count = len(eligible)
    scan_known = [
        row
        for row in eligible
        if (
            row.scan_evidence_complete
            or row.successful_scan
        )
    ]
    freshness_known = list(scan_known)

    return CoverageMetrics(
        onboarding=CoverageMetric(
            numerator=sum(
                row.onboarded is True
                for row in eligible
            ),
            denominator=eligible_count,
        ),
        mapping=CoverageMetric(
            numerator=sum(
                row.mapping.authoritative
                for row in eligible
            ),
            denominator=eligible_count,
        ),
        scan=CoverageMetric(
            numerator=sum(
                row.successful_scan
                for row in scan_known
            ),
            denominator=len(scan_known),
        ),
        fresh_scan=CoverageMetric(
            numerator=sum(
                row.fresh_scan
                for row in freshness_known
            ),
            denominator=len(
                freshness_known
            ),
        ),
    )

def primary_language(
    row: RepositoryCoverage,
) -> str:
    return (
        row.repository.languages[0]
        if row.repository.languages
        else "unknown"
    )


def onboarding_group(
    row: RepositoryCoverage,
) -> str:
    if row.onboarded is True:
        return "onboarded"

    if row.onboarded is False:
        return "not-onboarded"

    return "unknown"


def scan_freshness_group(
    row: RepositoryCoverage,
) -> str:
    if row.fresh_scan:
        return "current"

    if row.successful_scan:
        return "stale-or-undated"

    return "never-scanned"


BREAKDOWN_DIMENSIONS: dict[
    str,
    Callable[
        [RepositoryCoverage],
        str,
    ],
] = {
    "provider": (
        lambda row: row.repository.provider
    ),
    "provider_instance": (
        lambda row: (
            row.repository.provider_instance
        )
    ),
    "organization": (
        lambda row: row.repository.namespace
    ),
    "visibility": (
        lambda row: row.repository.visibility
    ),
    "archived": (
        lambda row: str(
            row.repository.archived
        ).lower()
    ),
    "primary_language": (
        primary_language
    ),
    "onboarding": (
        onboarding_group
    ),
    "mapping_confidence": (
        lambda row: (
            row.mapping.confidence.value
        )
    ),
    "classification": (
        lambda row: (
            row.classification.value
        )
    ),
    "scan_freshness": (
        scan_freshness_group
    ),
}


def coverage_breakdowns(
    rows: Iterable[
        RepositoryCoverage
    ],
) -> dict[
    str,
    dict[
        str,
        dict[str, Any],
    ],
]:
    values = list(rows)
    breakdowns: dict[
        str,
        dict[
            str,
            dict[str, Any],
        ],
    ] = {}

    for dimension, selector in (
        BREAKDOWN_DIMENSIONS.items()
    ):
        grouped: dict[
            str,
            list[RepositoryCoverage],
        ] = {}

        for row in values:
            group = str(
                selector(row) or "unknown"
            )
            grouped.setdefault(
                group,
                [],
            ).append(row)

        breakdowns[dimension] = {
            group: {
                "repository_count": (
                    len(group_rows)
                ),
                "eligible_repository_count": (
                    sum(
                        row.eligible
                        for row in group_rows
                    )
                ),
                **coverage_metrics(
                    group_rows
                ).as_dict(),
            }
            for group, group_rows
            in sorted(grouped.items())
        }

    return breakdowns


def classification_counts(
    rows: Iterable[
        RepositoryCoverage
    ],
) -> dict[str, int]:
    values = list(rows)

    return {
        classification.value: sum(
            row.classification
            == classification
            for row in values
        )
        for classification
        in CoverageClassification
        if any(
            row.classification
            == classification
            for row in values
        )
    }
