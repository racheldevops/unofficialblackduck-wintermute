from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping

from wintermute.blackduck.criteria import (
    CollectionCriteria,
    ScoreOperator,
)
from wintermute.blackduck.models import (
    CollectionTarget,
    NormalizedFinding,
    ProjectVersionRef,
)
from wintermute.blackduck.pull import (
    PullRequest,
    pull_rows,
)
from wintermute.blackduck.scopes import CollectionScope
from wintermute.blackduck.projections import (
    datadog_finding_rows,
)
from wintermute.blackduck.resources import (
    canonical_href,
    sha256_hex,
)


def candidate_key(
    candidate: Mapping[str, Any],
) -> str:
    explicit = str(
        candidate.get("candidate_key") or ""
    ).strip()

    if explicit:
        return explicit

    return "|".join(
        [
            str(candidate.get("project") or ""),
            str(
                candidate.get("project_version")
                or ""
            ),
            canonical_href(
                candidate.get(
                    "project_version_href",
                    "",
                )
            ),
        ]
    )


def candidate_external_id(
    candidate: Mapping[str, Any],
) -> str:
    explicit = str(
        candidate.get(
            "candidate_external_id",
            "",
        )
        or ""
    ).strip()

    if explicit:
        return explicit

    return sha256_hex(candidate_key(candidate))


def criteria_from_pull_settings(
    settings: Any,
) -> CollectionCriteria:
    return CollectionCriteria(
        score_field=str(
            settings.score_field or "overallScore"
        ),
        score_operator=ScoreOperator(
            str(settings.score_operator)
        ),
        threshold=float(settings.threshold),
        require_exploit_available=bool(
            settings.require_exploit_available
        ),
        require_reachable=bool(
            settings.require_reachable
        ),
        reachability_mode=str(
            settings.reachability_mode or "none"
        ),
        policy_name=str(
            settings.policy_name or ""
        ),
        policy_rule_id=str(
            settings.policy_rule_id or ""
        ),
        skip_policy_rules=bool(
            settings.skip_policy_rules
        ),
        include_policy_rule_details=bool(
            settings.include_policy_rule_details
        ),
    )


def target_from_candidate(
    client: Any,
    candidate: Mapping[str, Any],
) -> CollectionTarget:
    return CollectionTarget(
        project_version=ProjectVersionRef(
            instance_url=str(
                getattr(client, "base_url", "")
            ),
            project=str(
                candidate.get("project") or ""
            ),
            version=str(
                candidate.get(
                    "project_version",
                    "",
                )
                or ""
            ),
            project_href=str(
                candidate.get("project_href") or ""
            ),
            version_href=str(
                candidate.get(
                    "project_version_href",
                    "",
                )
                or ""
            ),
            phase=str(
                candidate.get("project_phase") or ""
            ),
            updated=str(
                candidate.get(
                    "project_updated",
                    "",
                )
                or ""
            ),
        )
    )


def enrich_candidate_attributes(
    finding: NormalizedFinding,
    candidate: Mapping[str, Any],
) -> NormalizedFinding:
    attributes = dict(finding.attributes)
    attributes.update(
        {
            "candidate_key": (
                candidate_key(candidate)
            ),
            "candidate_external_id": (
                candidate_external_id(candidate)
            ),
        }
    )

    return replace(
        finding,
        attributes=attributes,
    )


def failure_row(
    candidate: Mapping[str, Any],
    *,
    stage: str,
    error: str,
    component: str = "",
) -> dict[str, str]:
    message = str(error)

    if component:
        message = f"{component}: {message}"

    return {
        "project": str(
            candidate.get("project") or ""
        ),
        "project_version": str(
            candidate.get("project_version") or ""
        ),
        "project_version_href": canonical_href(
            candidate.get(
                "project_version_href",
                "",
            )
        ),
        "candidate_external_id": (
            candidate_external_id(candidate)
        ),
        "stage": stage,
        "error": message,
    }


def collect_candidate_findings(
    client: Any,
    candidate: Mapping[str, Any],
    settings: Any,
) -> tuple[
    list[dict[str, str]],
    list[dict[str, str]],
]:
    execution = pull_rows(
        client,
        [candidate],
        PullRequest(
            scope=(
                CollectionScope.CANDIDATE_PROJECTS
            ),
            criteria=(
                criteria_from_pull_settings(
                    settings
                )
            ),
            workers=1,
            component_workers=int(
                settings.component_workers
            ),
        ),
    )
    findings = [
        enrich_candidate_attributes(
            finding,
            candidate,
        )
        for finding in execution.collection.findings
    ]
    rows = datadog_finding_rows(
        findings,
        group_by=str(settings.group_by),
        first_seen_source=(
            "blackduck-policy-vuln-pull"
        ),
    )
    failures = [
        failure_row(
            candidate,
            stage=failure.stage,
            error=failure.error,
            component=failure.component,
        )
        for failure
        in execution.collection.failures
    ]

    return rows, failures
