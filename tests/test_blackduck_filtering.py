from __future__ import annotations

from wintermute.blackduck.criteria import (
    CollectionCriteria,
    ScoreOperator,
    datadog_high_risk_criteria,
    jira_parent_rollup_criteria,
)
from wintermute.blackduck.filtering import (
    broad_collection_criteria,
    filter_findings,
    finding_matches_criteria,
)
from wintermute.blackduck.models import (
    NormalizedFinding,
    ProjectVersionRef,
)


def finding(
    *,
    score: float = 9.8,
    exploit_available: bool = True,
    reachable: bool = True,
    policy_name: str = "Security",
    entity: str = "Team A",
) -> NormalizedFinding:
    return NormalizedFinding(
        project_version=ProjectVersionRef(
            instance_url="https://bd.example",
            project="Service",
            version="1",
            version_href=(
                "https://bd.example/projects/s/"
                "versions/1"
            ),
        ),
        component="openssl",
        component_version="3.0.1",
        vulnerability="CVE-2026-0001",
        score=score,
        exploit_available=exploit_available,
        reachable=reachable,
        policy_name=policy_name,
        policy_rule_href=(
            "https://bd.example/policies/rule-1"
        ),
        entity=entity,
    )


def test_broad_profile_keeps_destination_superset() -> None:
    criteria = broad_collection_criteria()

    assert criteria.score_passes(0.0)
    assert not criteria.require_exploit_available
    assert not criteria.require_reachable
    assert criteria.include_policy_rule_details


def test_jira_and_datadog_apply_different_filters() -> None:
    rows = [
        finding(score=7.0, exploit_available=False),
        finding(score=9.8, exploit_available=True),
    ]

    assert len(
        filter_findings(
            rows,
            jira_parent_rollup_criteria(),
        )
    ) == 2
    assert len(
        filter_findings(
            rows,
            datadog_high_risk_criteria(),
        )
    ) == 1


def test_policy_and_entity_filters_are_applied() -> None:
    criteria = CollectionCriteria(
        threshold=7,
        score_operator=(
            ScoreOperator.GREATER_THAN_OR_EQUAL
        ),
        policy_name="Security",
        require_entity=True,
        entity_custom_field="Entity",
    )

    assert finding_matches_criteria(
        finding(),
        criteria,
    )
    assert not finding_matches_criteria(
        finding(policy_name="Other"),
        criteria,
    )
    assert not finding_matches_criteria(
        finding(entity=""),
        criteria,
    )
