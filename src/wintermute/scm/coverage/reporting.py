from __future__ import annotations

from typing import Any

from wintermute.scm.coverage.mapping import (
    mapping_payload,
)
from wintermute.scm.coverage.metrics import (
    classification_counts,
    coverage_breakdowns,
    coverage_metrics,
)
from wintermute.scm.coverage.models import (
    CoverageReport,
    RepositoryCoverage,
)


COVERAGE_REPORT_SCHEMA_VERSION = 1


def repository_coverage_payload(
    value: RepositoryCoverage,
) -> dict[str, Any]:
    repository = value.repository

    return {
        "repository_external_id": (
            repository.external_id
        ),
        "provider": repository.provider,
        "provider_instance": (
            repository.provider_instance
        ),
        "tenant_id": repository.tenant_id,
        "repository_id": (
            repository.repository_id
        ),
        "namespace": repository.namespace,
        "name": repository.name,
        "name_with_owner": (
            repository.name_with_owner
        ),
        "canonical_url": (
            repository.canonical_url
        ),
        "visibility": repository.visibility,
        "archived": repository.archived,
        "languages": list(
            repository.languages
        ),
        "eligible": value.eligible,
        "exclusion_reason": (
            value.exclusion_reason
        ),
        "onboarded": value.onboarded,
        "classification": (
            value.classification.value
        ),
        "mapping": mapping_payload(
            value.mapping
        ),
        "blackduck_project": (
            {
                "project_id": (
                    value.blackduck_project
                    .project_id
                ),
                "name": (
                    value.blackduck_project.name
                ),
                "href": (
                    value.blackduck_project.href
                ),
            }
            if value.blackduck_project
            is not None
            else None
        ),
        "project_version_count": (
            value.project_version_count
        ),
        "scan_evidence_complete": (
            value.scan_evidence_complete
        ),
        "successful_scan": (
            value.successful_scan
        ),
        "last_successful_scan_at": (
            value.last_successful_scan_at
        ),
        "fresh_scan": value.fresh_scan,
        "freshness_sla_days": (
            value.freshness_sla_days
        ),
        "reasons": list(value.reasons),
    }


def coverage_report_payload(
    report: CoverageReport,
) -> dict[str, Any]:
    repositories = sorted(
        report.repositories,
        key=lambda value: (
            value.repository.provider,
            value.repository.provider_instance,
            value.repository
            .name_with_owner
            .casefold(),
            value.repository.repository_id,
        ),
    )

    return {
        "schema_version": (
            COVERAGE_REPORT_SCHEMA_VERSION
        ),
        "repository_count": (
            report.repository_count
        ),
        "eligible_repository_count": (
            report.eligible_repository_count
        ),
        "provider_failure_count": (
            report.provider_failure_count
        ),
        "blackduck_failure_count": (
            report.blackduck_failure_count
        ),
        "classification_counts": (
            classification_counts(
                repositories
            )
        ),
        "metrics": coverage_metrics(
            repositories
        ).as_dict(),
        "breakdowns": coverage_breakdowns(
            repositories
        ),
        "repositories": [
            repository_coverage_payload(
                value
            )
            for value in repositories
        ],
        "orphaned_blackduck_projects": [
            {
                "project_id": value.project_id,
                "name": value.name,
                "href": value.href,
            }
            for value in sorted(
                report
                .orphaned_blackduck_projects,
                key=lambda item: (
                    item.name.casefold(),
                    item.project_id,
                ),
            )
        ],
    }
