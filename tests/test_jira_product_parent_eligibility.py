from __future__ import annotations

import argparse
import copy

import pytest

from wintermute.blackduck.models import ProjectVersionRef
from wintermute.jira import product_reporting as product
from wintermute.jira.product_document import (
    render_product_create_description,
    render_product_description,
)

from test_jira_product_reporting import config, evidence, row


BASE = "https://bd.example.invalid"
PARENT = BASE + "/api/projects/parent"
CHILD = BASE + "/api/projects/child"


def ref(project, project_href, version):
    return ProjectVersionRef(
        instance_url=BASE,
        project=project,
        version=version,
        project_href=project_href,
        version_href=f"{project_href}/versions/{version}",
    )


class Lineage:
    reused = 0
    scanned = 0
    path = "fixture-lineage.json"

    def __init__(self, children):
        self.children = children
        self.loads = []

    def load(self, parent):
        self.loads.append(parent.version_href)
        return [
            type("Context", (), {"child": child})()
            for child in self.children.get(parent.version_href, [])
        ]


def selected(parent):
    return {
        "ref": parent,
        "project": parent.project,
        "display_name": parent.project,
        "version": parent.version,
        "href": parent.version_href,
        "phase": "RELEASED",
        "entity": "Example entity",
        "people": product.responsibility_metadata(""),
    }


def targets_for(parents, lineage, excluded=()):
    report = {"relationships": []}
    targets = product.collection_targets(
        lineage,
        [selected(parent) for parent in parents],
        argparse.Namespace(exclude_child_project=list(excluded)),
        product.settings_from(config()),
        report,
    )
    return targets, report


def test_standalone_product_is_not_eligible():
    parent = ref("cc-goat", PARENT, "v1")
    targets, report = targets_for([parent], Lineage({}))
    assert targets == []
    assert report["eligible_product_hrefs"] == []
    assert report["excluded_non_parent_versions"][0]["reason"] == (
        "no-distinct-added-project"
    )


def test_another_version_of_same_project_is_not_a_child_product():
    parent = ref("cc-goat", PARENT, "v1")
    sibling = ref("cc-goat", PARENT, "v2")
    targets, report = targets_for(
        [parent], Lineage({parent.version_href: [sibling]})
    )
    assert targets == []
    assert report["eligible_product_hrefs"] == []


def test_distinct_child_enables_parent_and_child_collection():
    parent = ref("Fieldgate_Product", PARENT, "1.0.2")
    child = ref("cc-goat", CHILD, "v1")
    lineage = Lineage({parent.version_href: [child]})
    targets, report = targets_for([parent], lineage)

    assert report["eligible_product_hrefs"] == [parent.version_href]
    assert {
        (item["source_project"], item["depth"])
        for item in report["relationships"]
    } == {("Fieldgate_Product", 0), ("cc-goat", 1)}
    assert {target.project_version.version_href for target in targets} == {
        parent.version_href, child.version_href,
    }
    assert lineage.loads.count(parent.version_href) == 1


def test_excluded_child_does_not_make_parent_eligible():
    parent = ref("Fieldgate_Product", PARENT, "1.0.2")
    child = ref("cc-goat", CHILD, "v1")
    targets, report = targets_for(
        [parent],
        Lineage({parent.version_href: [child]}),
        excluded=["cc-goat"],
    )
    assert targets == []
    assert report["eligible_product_hrefs"] == []


def test_direct_parent_occurrence_is_optional_without_losing_child():
    parent = ref("Fieldgate_Product", PARENT, "1.0.2")
    child = ref("cc-goat", CHILD, "v1")
    selected_parent = selected(parent)

    def finding(source, component):
        item = evidence(source.version_href, component=component)
        return type("Finding", (), {
            "vulnerability": item["vulnerability"],
            "project_version": source,
            "component": item["component"],
            "component_version": item["component_version"],
            "component_href": item["component_href"],
            "severity": item["severity"],
            "attributes": {
                "blackduck_occurrences": [copy.deepcopy(item["evidence"])]
            },
            "lineage_contexts": [
                type("Context", (), {"parent": parent})()
            ],
        })()

    direct = finding(parent, BASE + "/api/components/direct/versions/one")
    indirect = finding(child, BASE + "/api/components/indirect/versions/one")
    args = argparse.Namespace(only_vulnerability=None)
    enabled = product.settings_from(config())

    rows, _ = product.project_findings(
        [direct, indirect], [selected_parent], args, enabled, {}
    )
    assert {value["source_href"] for value in rows} == {
        parent.version_href, child.version_href,
    }

    disabled = dict(enabled, include_direct_product_findings=False)
    rows, _ = product.project_findings(
        [direct, indirect], [selected_parent], args, disabled, {}
    )
    assert [value["source_href"] for value in rows] == [child.version_href]
    task = next(
        node for node in product.build_nodes(rows, config())
        if node["node_type"] == "story"
    )
    assert task["summary"] == (
        "Black Duck: BLOCKER Alert - Fieldgate_Product - version 1.0.2"
    )
    assert task["context"]["parent_project"] == "Fieldgate_Product"
    assert task["product_report"]["rows"][0]["source_project"] == "cc-goat"
    header = render_product_create_description(
        task["product_report"], "adf"
    )["content"]
    assert header[1]["content"][1]["text"] == "Fieldgate_Product"
    assert header[2]["content"][1]["text"] == "1.0.2"


@pytest.mark.parametrize("format", ["adf", "wiki"])
def test_product_table_aggregates_score_and_vectors(format):
    first = row()
    first["score"] = 7.5
    first["evidence"]["cvss_vectors"] = {
        "cvss3.vector": "CVSS:3.1/AV:N"
    }
    second = row(component=BASE + "/api/components/other/versions/one")
    second["score"] = 9.8
    second["evidence"]["cvss_vectors"] = {
        "cvss4.vector": "CVSS:4.0/AV:L"
    }
    rendered = render_product_description(
        {"schema_version": 1, "rows": [first, second]}, format
    )
    if format == "adf":
        product_table = rendered["content"][1]
        cells = [
            [
                cell["content"][0]["content"][0]["text"]
                for cell in table_row["content"]
            ]
            for table_row in product_table["content"]
        ]
        assert ["CVSS Score (maximum overallScore)", "9.8"] in cells
        assert [
            "CVSS Vector (reported)",
            "CVSS:3.1/AV:N; CVSS:4.0/AV:L",
        ] in cells
    else:
        assert "|CVSS Score (maximum overallScore)|9.8|" in rendered
        assert (
            "|CVSS Vector (reported)|CVSS:3.1/AV:N; CVSS:4.0/AV:L|"
            in rendered
        )


def test_direct_option_requires_boolean():
    value = config()
    value["product_reporting"]["include_direct_product_findings"] = "false"
    with pytest.raises(RuntimeError, match="include_direct_product_findings"):
        product.settings_from(value)


def test_parent_rollup_requires_positive_depth():
    value = config()
    value["product_reporting"]["added_project_depth"] = 0
    with pytest.raises(RuntimeError, match="added_project_depth"):
        product.settings_from(value)
