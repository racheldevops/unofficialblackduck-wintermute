from __future__ import annotations

from wintermute.jira import findings_hierarchy_plan as hierarchy


def finding() -> dict[str, str]:
    return hierarchy.normalize_finding(
        {
            "parent_project": "Product",
            "parent_version": "1",
            "parent_version_href": (
                "https://bd.example/products/p/versions/1"
            ),
            "subproject_path": "Service/2",
            "subproject": "Service",
            "subproject_version": "2",
            "subproject_version_href": (
                "https://bd.example/services/s/versions/2"
            ),
            "relationship_detection_method": "api-href",
            "component": "openssl",
            "component_version": "3.0.1",
            "vulnerability": "CVE-2026-0001",
            "score_field": "overallScore",
            "score": "9.8",
            "severity": "CRITICAL",
            "blackduck_url": (
                "https://bd.example/cves/CVE-2026-0001"
            ),
            "rollup_key": (
                "Product|1|Service|2|openssl|3.0.1|"
                "CVE-2026-0001"
            ),
        }
    )


def test_old_mode_names_normalize_to_canonical_names() -> None:
    assert hierarchy.normalize_hierarchy_mode(
        "vulnerability-project"
    ) == "vulnerability-remediation"
    assert hierarchy.normalize_hierarchy_mode(
        "project-subproject-vulnerability"
    ) == "project-lineage"


def test_vulnerability_alias_preserves_nodes_and_ids() -> None:
    canonical = hierarchy.build_nodes(
        [finding()],
        hash_length=24,
        hierarchy_mode="vulnerability-remediation",
    )
    compatibility = hierarchy.build_nodes(
        [finding()],
        hash_length=24,
        hierarchy_mode="vulnerability-project",
    )

    assert canonical == compatibility
    assert all(
        node["hierarchy_mode"]
        == "vulnerability-remediation"
        for node in canonical
    )


def test_project_lineage_alias_preserves_nodes_and_ids() -> None:
    canonical = hierarchy.build_nodes(
        [finding()],
        hash_length=24,
        hierarchy_mode="project-lineage",
    )
    compatibility = hierarchy.build_nodes(
        [finding()],
        hash_length=24,
        hierarchy_mode=(
            "project-subproject-vulnerability"
        ),
    )

    assert canonical == compatibility
    assert all(
        node["hierarchy_mode"] == "project-lineage"
        for node in canonical
    )
    assert hierarchy.count_nodes(canonical) == {
        "epic_count": 1,
        "story_count": 1,
        "vulnerability_count": 1,
        "total_node_count": 3,
    }


def test_compatibility_builder_matches_project_lineage() -> None:
    canonical = hierarchy.build_project_lineage_nodes(
        [finding()],
        hash_length=24,
    )
    compatibility = (
        hierarchy
        .build_project_subproject_vulnerability_nodes(
            [finding()],
            hash_length=24,
        )
    )

    assert canonical == compatibility


def test_cli_accepts_canonical_vulnerability_mode(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        [
            "wintermute-hierarchy-plan",
            "--hierarchy-mode",
            "vulnerability-remediation",
        ],
    )

    args = hierarchy.parse_args()

    assert args.hierarchy_mode == (
        "vulnerability-remediation"
    )


def test_cli_accepts_canonical_project_lineage_mode(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        [
            "wintermute-hierarchy-plan",
            "--hierarchy-mode",
            "project-lineage",
        ],
    )

    args = hierarchy.parse_args()

    assert args.hierarchy_mode == "project-lineage"


def test_cli_retains_old_mode_aliases(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        [
            "wintermute-hierarchy-plan",
            "--hierarchy-mode",
            "vulnerability-project",
        ],
    )

    args = hierarchy.parse_args()

    assert args.hierarchy_mode == (
        "vulnerability-project"
    )
