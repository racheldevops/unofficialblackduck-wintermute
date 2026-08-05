from __future__ import annotations

import argparse
import csv
import json
from collections.abc import Callable
from pathlib import Path

import pytest

from harness.jira import findings_hierarchy_plan as hierarchy


def write_findings(
    path: Path,
    rows: list[dict[str, str]],
) -> None:
    fieldnames = (
        hierarchy.REQUIRED_FINDING_FIELDS
        + hierarchy.OPTIONAL_FINDING_FIELDS
    )
    with path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {field: row.get(field, "") for field in fieldnames}
            )


def test_normalize_finding_moves_resource_url_to_href(
    sample_finding_factory: Callable[..., dict[str, str]],
) -> None:
    resource_url = (
        "https://bd.example/api/components/component-a/"
        "versions/component-version-a"
    )
    finding = sample_finding_factory(
        component_version=resource_url,
        component_version_href="",
    )

    normalized = hierarchy.normalize_finding(finding)

    assert normalized["component_version"] == ""
    assert normalized["component_version_href"] == resource_url
    assert normalized["severity"] == "CRITICAL"


def test_normalize_finding_fills_unknown_and_rollup_key() -> None:
    normalized = hierarchy.normalize_finding(
        {
            "parent_project": "Parent",
            "parent_version": "1",
            "subproject": "Child",
            "subproject_version": "2",
            "component": "lib",
            "component_version": "3",
            "vulnerability": "",
            "severity": " high ",
        }
    )

    assert normalized["vulnerability"] == "UNKNOWN"
    assert normalized["severity"] == "HIGH"
    assert normalized["rollup_key"].endswith("|lib|3|UNKNOWN")


def test_compute_stats_aggregates_severity_scores_and_components(
    sample_finding_factory: Callable[..., dict[str, str]],
) -> None:
    findings = [
        sample_finding_factory(score="9.8", severity="CRITICAL"),
        sample_finding_factory(
            component="library-b",
            component_version="4.0",
            score="7.2",
            severity="MEDIUM",
        ),
    ]

    stats = hierarchy.compute_stats(findings)

    assert stats["finding_count"] == 2
    assert stats["component_count"] == 2
    assert stats["vulnerability_count"] == 1
    assert stats["affected_project_version_count"] == 1
    assert stats["critical_count"] == 1
    assert stats["medium_count"] == 1
    assert stats["max_score"] == 9.8
    assert stats["min_score"] == 7.2
    assert stats["average_score"] == 8.5
    assert hierarchy.highest_severity_from_stats(stats) == "CRITICAL"


def test_dedupe_findings_preserves_first_occurrence(
    sample_finding_factory: Callable[..., dict[str, str]],
) -> None:
    first = sample_finding_factory()
    duplicate = {**first, "entity": "Changed"}

    assert hierarchy.dedupe_findings([first, duplicate]) == [first]


def test_vulnerability_project_nodes_group_epics_and_tasks(
    sample_finding_factory: Callable[..., dict[str, str]],
) -> None:
    findings = [
        sample_finding_factory(),
        sample_finding_factory(
            component="library-b",
            component_version="2.0",
        ),
        sample_finding_factory(
            subproject="Child B",
            subproject_version="3.0",
            subproject_version_href="https://bd.example/child-b/3",
            component="library-c",
        ),
    ]

    nodes = hierarchy.build_vulnerability_project_nodes(
        findings,
        hash_length=24,
    )

    epics = [node for node in nodes if node["node_type"] == "epic"]
    tasks = [node for node in nodes if node["node_type"] == "story"]

    assert len(epics) == 1
    assert len(tasks) == 2
    assert epics[0]["stats"]["child_count"] == 2
    assert all(
        task["parent_external_id"] == epics[0]["external_id"]
        for task in tasks
    )

    child_task = next(
        task
        for task in tasks
        if task["context"]["affected_project"] == "Child"
    )
    assert child_task["stats"]["component_count"] == 2


def test_node_generation_is_deterministic_across_input_order(
    sample_finding_factory: Callable[..., dict[str, str]],
) -> None:
    findings = [
        sample_finding_factory(component="z-lib"),
        sample_finding_factory(
            component="a-lib",
            component_version="2",
        ),
    ]

    forward = hierarchy.build_vulnerability_project_nodes(
        findings,
        hash_length=24,
    )
    reverse = hierarchy.build_vulnerability_project_nodes(
        list(reversed(findings)),
        hash_length=24,
    )

    assert forward == reverse


def test_legacy_mode_builds_three_hierarchy_levels(
    sample_finding_factory: Callable[..., dict[str, str]],
) -> None:
    nodes = hierarchy.build_project_subproject_vulnerability_nodes(
        [sample_finding_factory()],
        hash_length=24,
    )
    counts = hierarchy.count_nodes(nodes)

    assert counts == {
        "epic_count": 1,
        "story_count": 1,
        "vulnerability_count": 1,
        "total_node_count": 3,
    }

    epic = next(node for node in nodes if node["node_type"] == "epic")
    story = next(node for node in nodes if node["node_type"] == "story")
    vulnerability = next(
        node for node in nodes if node["node_type"] == "vulnerability"
    )

    assert story["parent_external_id"] == epic["external_id"]
    assert vulnerability["parent_external_id"] == story["external_id"]


def test_filters_apply_before_limit(
    sample_finding_factory: Callable[..., dict[str, str]],
) -> None:
    findings = [
        sample_finding_factory(subproject="A"),
        sample_finding_factory(subproject="B"),
        sample_finding_factory(
            subproject="B",
            component="second",
        ),
    ]
    args = argparse.Namespace(
        only_parent_project=None,
        only_parent_version=None,
        only_subproject="B",
        only_vulnerability=None,
        limit=1,
    )

    filtered = hierarchy.apply_filters(findings, args)

    assert len(filtered) == 1
    assert filtered[0]["subproject"] == "B"


def test_process_writes_plan_and_csv_outputs(
    tmp_path: Path,
    sample_finding_factory: Callable[..., dict[str, str]],
) -> None:
    findings_path = tmp_path / "findings.csv"
    plan_path = tmp_path / "plan.json"
    summary_path = tmp_path / "summary.csv"
    nodes_path = tmp_path / "nodes.csv"

    write_findings(
        findings_path,
        [
            sample_finding_factory(),
            sample_finding_factory(
                subproject="Child B",
                subproject_version="3",
                subproject_version_href="https://bd.example/child-b/3",
            ),
        ],
    )

    args = argparse.Namespace(
        findings=str(findings_path),
        hierarchy_mode=hierarchy.HIERARCHY_MODE_VULNERABILITY_PROJECT,
        plan_out=str(plan_path),
        summary_out=str(summary_path),
        nodes_out=str(nodes_path),
        only_parent_project=None,
        only_parent_version=None,
        only_subproject=None,
        only_vulnerability=None,
        limit=None,
        hash_length=24,
        debug=False,
    )

    assert hierarchy.process(args) == 0

    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == hierarchy.SCHEMA_VERSION
    assert payload["source_counts"]["raw_finding_count"] == 2
    assert payload["node_counts"]["epic_count"] == 1
    assert payload["node_counts"]["story_count"] == 2
    assert payload["node_counts"]["total_node_count"] == 3

    with summary_path.open(newline="", encoding="utf-8") as input_file:
        assert len(list(csv.DictReader(input_file))) == 3

    with nodes_path.open(newline="", encoding="utf-8") as input_file:
        assert len(list(csv.DictReader(input_file))) == 3


def test_read_findings_rejects_missing_required_columns(
    tmp_path: Path,
) -> None:
    path = tmp_path / "invalid.csv"
    path.write_text("parent_project\nParent\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="missing required field"):
        hierarchy.read_findings(str(path))


@pytest.mark.parametrize(
    ("limit", "hash_length", "message"),
    [
        (0, 24, "--limit"),
        (None, 7, "--hash-length"),
        (None, 65, "--hash-length"),
    ],
)
def test_validate_args_rejects_invalid_limits(
    limit: int | None,
    hash_length: int,
    message: str,
) -> None:
    args = argparse.Namespace(limit=limit, hash_length=hash_length)

    with pytest.raises(RuntimeError, match=message):
        hierarchy.validate_args(args)
