from __future__ import annotations

from collections.abc import Iterable

from wintermute.blackduck.criteria import (
    CollectionCriteria,
    ScoreOperator,
)
from wintermute.blackduck.models import (
    NormalizedFinding,
)


def broad_collection_criteria(
    *,
    score_field: str = "overallScore",
    minimum_score: float = 0.0,
    include_policy_rule_details: bool = True,
    entity_custom_field: str = "",
    require_entity: bool = False,
) -> CollectionCriteria:
    return CollectionCriteria(
        score_field=score_field,
        score_operator=(
            ScoreOperator.GREATER_THAN_OR_EQUAL
        ),
        threshold=minimum_score,
        require_exploit_available=False,
        require_reachable=False,
        reachability_mode="none",
        include_policy_rule_details=(
            include_policy_rule_details
        ),
        entity_custom_field=entity_custom_field,
        require_entity=require_entity,
    )


def finding_matches_criteria(
    finding: NormalizedFinding,
    criteria: CollectionCriteria,
) -> bool:
    if not criteria.score_passes(finding.score):
        return False

    if (
        criteria.require_exploit_available
        and not finding.exploit_available
    ):
        return False

    if (
        criteria.require_reachable
        and not finding.reachable
    ):
        return False

    if criteria.policy_name:
        names = {
            value.strip()
            for value in finding.policy_name.split(";")
            if value.strip()
        }

        if criteria.policy_name not in names:
            return False

    if criteria.policy_rule_id:
        hrefs = {
            value.strip()
            for value
            in finding.policy_rule_href.split(";")
            if value.strip()
        }

        if not any(
            criteria.policy_rule_id in href
            for href in hrefs
        ):
            return False

    if criteria.require_entity and not finding.entity:
        return False

    return True


def filter_findings(
    findings: Iterable[NormalizedFinding],
    criteria: CollectionCriteria,
) -> list[NormalizedFinding]:
    return [
        finding
        for finding in findings
        if finding_matches_criteria(
            finding,
            criteria,
        )
    ]
