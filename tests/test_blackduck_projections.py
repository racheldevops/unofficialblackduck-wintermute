from __future__ import annotations

from wintermute.blackduck.models import (
    LineageContext,
    NormalizedFinding,
    ProjectVersionRef,
)
from wintermute.blackduck.projections import (
    datadog_finding_rows,
    jira_parent_rollup_rows,
)
from wintermute.blackduck.resources import (
    sha256_hex,
)


def normalized_finding() -> NormalizedFinding:
    child = ProjectVersionRef(
        instance_url="https://bd.example",
        project="Service",
        version="1.0",
        project_href=(
            "https://bd.example/projects/service"
        ),
        version_href=(
            "https://bd.example/projects/service/"
            "versions/1"
        ),
    )
    parent = ProjectVersionRef(
        instance_url="https://bd.example",
        project="Product",
        version="2.0",
        version_href=(
            "https://bd.example/projects/product/"
            "versions/2"
        ),
    )

    return NormalizedFinding(
        project_version=child,
        component="openssl",
        component_version="3.0.1",
        component_href=(
            "https://bd.example/api/components/"
            "openssl/versions/3"
        ),
        vulnerability="CVE-2026-0001",
        severity="CRITICAL",
        score_field="overallScore",
        score=9.8,
        vulnerability_href=(
            "https://bd.example/vulnerabilities/"
            "CVE-2026-0001"
        ),
        cvss_vector="CVSS:3.1/AV:N",
        exploit_available=True,
        exploitable="True",
        reachable=True,
        reachability="reachable",
        reachability_source="field",
        policy_name="Security Policy",
        policy_rule_href=(
            "https://bd.example/policies/rule"
        ),
        entity="Team A",
        lineage_contexts=(
            LineageContext(
                parent=parent,
                child=child,
                detection_method="api-href",
            ),
        ),
        attributes={
            "component_version_href": (
                "https://bd.example/api/components/"
                "openssl/versions/3"
            ),
            "bom_component_url": (
                "https://bd.example/bom/openssl"
            ),
            "component_origin_id": "origin-a",
            "candidate_key": "candidate-key",
            "candidate_external_id": (
                "candidate-id"
            ),
            "policy_matched": True,
        },
    )


def test_jira_projection_preserves_rollup_identity() -> None:
    rows = jira_parent_rollup_rows(
        [normalized_finding()]
    )

    assert len(rows) == 1
    row = rows[0]

    assert row["parent_project"] == "Product"
    assert row["subproject"] == "Service"
    assert row["component"] == "openssl"
    assert row["vulnerability"] == (
        "CVE-2026-0001"
    )
    assert row["entity"] == "Team A"
    assert row["rollup_key"] == (
        "Product|2.0|Service|1.0|openssl|"
        "3.0.1|CVE-2026-0001"
    )


def test_datadog_projection_preserves_ids() -> None:
    rows = datadog_finding_rows(
        [normalized_finding()],
        group_by="project",
    )

    assert len(rows) == 1
    row = rows[0]
    finding_key = (
        "Service|1.0|openssl|3.0.1|"
        "CVE-2026-0001"
    )

    assert row["project_group_key"] == "Service"
    assert row["project_group_external_id"] == (
        sha256_hex("Service")
    )
    assert row["finding_key"] == finding_key
    assert row["finding_external_id"] == (
        sha256_hex(finding_key)
    )
    assert row["exploit_available"] == "true"
    assert row["reachable"] == "true"
    assert row["candidate_external_id"] == (
        "candidate-id"
    )


def test_datadog_project_version_grouping() -> None:
    row = datadog_finding_rows(
        [normalized_finding()],
        group_by="project-version",
    )[0]

    assert row["project_group_key"] == (
        "Service|1.0"
    )
