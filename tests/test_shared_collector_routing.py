from __future__ import annotations

from wintermute.datadog import policy_vuln_pull
from wintermute.jira import subp_vuln_rollup


def test_jira_uses_shared_collection_path() -> None:
    assert callable(
        subp_vuln_rollup
        .collect_parent_rollup_findings
    )

    for removed_name in (
        "collect_findings_for_subproject",
        "collect_findings_for_subprojects",
        "collect_one_relationship",
        "RelationshipCollectionResult",
    ):
        assert not hasattr(
            subp_vuln_rollup,
            removed_name,
        )


def test_datadog_uses_shared_collection_path() -> None:
    assert callable(
        policy_vuln_pull.collect_for_candidate
    )

    for removed_name in (
        "collect_for_component",
        "ComponentPullResult",
        "score_passes",
    ):
        assert not hasattr(
            policy_vuln_pull,
            removed_name,
        )
