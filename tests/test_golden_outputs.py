from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from wintermute.blackduck.models import (
    LineageContext,
    NormalizedFinding,
    ProjectVersionRef,
)
from wintermute.blackduck.projections import (
    datadog_finding_rows,
    jira_parent_rollup_rows,
)
from wintermute.jira import (
    findings_hierarchy_plan as hierarchy,
)


ROOT = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "golden"
)


def load_json(name: str) -> Any:
    return json.loads(
        (ROOT / name).read_text(
            encoding="utf-8"
        )
    )


def source_finding() -> NormalizedFinding:
    source = load_json(
        "projection-source.json"
    )
    child = ProjectVersionRef(
        **source["project_version"]
    )
    contexts = tuple(
        LineageContext(
            parent=ProjectVersionRef(
                **item["parent"]
            ),
            child=child,
            detection_method=item[
                "detection_method"
            ],
            bom_component_name=item[
                "bom_component_name"
            ],
            bom_component_version=item[
                "bom_component_version"
            ],
        )
        for item in source[
            "lineage_contexts"
        ]
    )

    return NormalizedFinding(
        project_version=child,
        lineage_contexts=contexts,
        **source["finding"],
    )


def test_jira_projection_matches_golden_output() -> None:
    actual = jira_parent_rollup_rows(
        [source_finding()]
    )
    expected = load_json(
        "jira-parent-rollup.json"
    )

    assert actual == expected


def test_datadog_projection_matches_golden_output() -> None:
    actual = datadog_finding_rows(
        [source_finding()],
        group_by="project",
    )
    expected = load_json(
        "datadog-findings.json"
    )

    assert actual == expected


def test_jira_hierarchy_matches_golden_output() -> None:
    rows = jira_parent_rollup_rows(
        [source_finding()]
    )
    findings = [
        hierarchy.normalize_finding(row)
        for row in rows
    ]
    actual = hierarchy.build_nodes(
        findings=findings,
        hash_length=24,
        hierarchy_mode=(
            "vulnerability-remediation"
        ),
    )
    expected = load_json(
        "jira-vulnerability-remediation.json"
    )

    assert actual == expected
