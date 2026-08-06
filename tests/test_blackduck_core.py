from __future__ import annotations

from wintermute.blackduck.criteria import (
    ScoreOperator,
    datadog_high_risk_criteria,
    jira_parent_rollup_criteria,
)
from wintermute.blackduck.models import (
    LineageContext,
    NormalizedFinding,
    ProjectVersionRef,
)
from wintermute.blackduck.resources import (
    canonical_href,
    first_value_by_key,
    get_link,
)
from wintermute.blackduck.scopes import (
    CollectionScope,
    normalize_scope,
    targets_from_candidates,
    targets_from_parent_relationships,
)
from wintermute.blackduck.vulnerabilities import (
    extract_exploit_available,
    extract_reachability,
    extract_vulnerability_candidates,
)


def test_resource_helpers_normalize_blackduck_data() -> None:
    resource = {
        "nested": {
            "UpdatedAt": "2026-08-06T00:00:00Z",
        },
        "_meta": {
            "href": "https://bd.example/resource/1/",
            "links": [
                {
                    "rel": "vulnerabilities",
                    "href": "https://bd.example/vulnerabilities",
                }
            ],
        },
    }

    assert canonical_href(
        "https://bd.example/resource/1/?ignored=true"
    ) == "https://bd.example/resource/1"
    assert first_value_by_key(
        resource,
        ["updatedAt"],
    ) == "2026-08-06T00:00:00Z"
    assert get_link(
        resource,
        ("vulnerabilities",),
    ) == "https://bd.example/vulnerabilities"


def test_collection_profiles_keep_destination_defaults_separate() -> None:
    jira = jira_parent_rollup_criteria()
    datadog = datadog_high_risk_criteria()

    assert jira.threshold == 7.0
    assert jira.score_operator == (
        ScoreOperator.GREATER_THAN_OR_EQUAL
    )
    assert jira.require_exploit_available is False
    assert jira.score_passes(7.0) is True

    assert datadog.threshold == 8.9
    assert datadog.score_operator == ScoreOperator.GREATER_THAN
    assert datadog.require_exploit_available is True
    assert datadog.score_passes(8.9) is False
    assert datadog.score_passes(9.0) is True


def test_parent_rollup_scope_deduplicates_child_collection() -> None:
    rows = [
        {
            "parent_project": "Product A",
            "parent_version": "1",
            "parent_version_href": "https://bd.example/parents/a/1",
            "child_project": "Service",
            "child_version": "2",
            "child_version_href": "https://bd.example/children/s/2",
            "detection_method": "api-href",
        },
        {
            "parent_project": "Product B",
            "parent_version": "3",
            "parent_version_href": "https://bd.example/parents/b/3",
            "child_project": "Service",
            "child_version": "2",
            "child_version_href": "https://bd.example/children/s/2",
            "detection_method": "bom-component-name-version",
        },
    ]

    targets = targets_from_parent_relationships(
        rows,
        instance_url="https://bd.example",
    )

    assert len(targets) == 1
    assert targets[0].project_version.project == "Service"
    assert len(targets[0].lineage_contexts) == 2
    assert {
        context.parent.project
        for context in targets[0].lineage_contexts
    } == {"Product A", "Product B"}


def test_candidate_scope_produces_direct_targets() -> None:
    targets = targets_from_candidates(
        [
            {
                "project": "Service",
                "project_version": "2",
                "project_version_href": (
                    "https://bd.example/projects/s/versions/2"
                ),
            }
        ],
        instance_url="https://bd.example",
    )

    assert len(targets) == 1
    assert targets[0].lineage_contexts == ()
    assert normalize_scope("candidates") == (
        CollectionScope.CANDIDATE_PROJECTS
    )


def test_parent_context_does_not_change_direct_finding_identity() -> None:
    project_version = ProjectVersionRef(
        instance_url="https://bd.example",
        project="Service",
        version="2",
        version_href="https://bd.example/projects/s/versions/2",
    )
    parent_a = ProjectVersionRef(
        instance_url="https://bd.example",
        project="Product A",
        version="1",
        version_href="https://bd.example/projects/a/versions/1",
    )
    parent_b = ProjectVersionRef(
        instance_url="https://bd.example",
        project="Product B",
        version="1",
        version_href="https://bd.example/projects/b/versions/1",
    )
    context_a = LineageContext(
        parent=parent_a,
        child=project_version,
    )
    context_b = LineageContext(
        parent=parent_b,
        child=project_version,
    )

    first = NormalizedFinding(
        project_version=project_version,
        component="openssl",
        component_version="3.0.1",
        vulnerability="CVE-2026-0001",
        lineage_contexts=(context_a,),
    )
    second = NormalizedFinding(
        project_version=project_version,
        component="openssl",
        component_version="3.0.1",
        vulnerability="CVE-2026-0001",
        lineage_contexts=(context_b,),
    )

    assert first.external_id == second.external_id


def test_shared_vulnerability_parser_handles_enrichment() -> None:
    payload = {
        "wrapper": {
            "vulnerability": {
                "vulnerabilityName": "CVE-2026-0001",
                "overallScore": 9.8,
                "severity": "CRITICAL",
                "exploitAvailable": True,
                "reachabilityStatus": "reachable",
            }
        }
    }

    candidates = extract_vulnerability_candidates(
        payload,
        score_fields=("overallScore",),
    )

    assert len(candidates) == 1
    assert extract_exploit_available(
        candidates[0]
    ) == (True, "True")
    assert extract_reachability(
        candidates[0]
    ) == (True, "reachable", "field")
