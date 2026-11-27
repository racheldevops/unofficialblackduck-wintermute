from __future__ import annotations

import copy
import json

import pytest

from wintermute.jira import product_reporting as product
from wintermute.jira.product_document import (
    render_product_create_description,
    render_product_epic_create_description,
)

from test_jira_product_reporting import (
    BASE,
    FakeJira,
    config,
    publish_with_fake,
    row,
)


def child_row(vulnerability="BDSA-2025-2867"):
    item = row()
    source = BASE + "/api/projects/juicy/versions/0.5"
    item["source_project"] = "juicy_cam.juiced"
    item["source_version"] = "0.5"
    item["source_href"] = source
    item["vulnerability"] = vulnerability
    item["severity"] = "MEDIUM"
    item["score"] = 6.6
    item["evidence"]["vulnerability"] = vulnerability
    item["evidence"]["project_version_href"] = source
    item["evidence"]["occurrence_href"] = (
        source + "/occurrences/one/" + vulnerability
    )
    item["evidence"]["advisory_href"] = (
        BASE + "/api/vulnerabilities/" + vulnerability
    )
    item["evidence"]["cvss_vectors"] = {
        "cvss4.vector": "CVSS:4.0/AV:N",
        "cvss3.vector": "CVSS:3.1/AV:N",
    }
    return item


def nodes_for(item):
    nodes = product.build_nodes([item], config())
    epic = next(node for node in nodes if node["node_type"] == "epic")
    task = next(node for node in nodes if node["node_type"] == "story")
    return nodes, epic, task


@pytest.mark.parametrize("format", ["adf", "wiki"])
def test_task_identifies_parent_and_qualifying_subproject(format):
    item = child_row()
    _, _, task = nodes_for(item)
    description = render_product_create_description(
        task["product_report"], format
    )
    if format == "adf":
        assert description["content"][0]["content"][0]["text"] == "Job name: "
        assert description["content"][4]["content"][0]["text"] == (
            "Affected parent product"
        )
        table = description["content"][5]
        cells = [
            [
                cell["content"][0]["content"][0]["text"]
                for cell in table_row["content"]
            ]
            for table_row in table["content"]
        ]
        assert ["Parent project", "Example Product"] in cells
        assert [
            "Affected subproject versions", "juicy_cam.juiced / 0.5"
        ] in cells
    else:
        assert description.startswith("*Job name:*")
        assert "h2. Affected parent product" in description
        assert "|Parent project|Example Product|" in description
        assert (
            "|Affected subproject versions|juicy_cam.juiced / 0.5|"
            in description
        )


@pytest.mark.parametrize("format", ["adf", "wiki"])
def test_bdsa_epic_has_evidence_but_no_unverified_nvd_link(format):
    item = child_row()
    _, epic, _ = nodes_for(item)
    rendered = render_product_epic_create_description(epic, [item], format)
    text = json.dumps(rendered) if isinstance(rendered, dict) else rendered
    assert "BDSA-2025-2867" in text
    assert "MEDIUM" in text
    assert "6.6" in text
    assert "CVSS:3.1/AV:N" in text
    assert "CVSS:4.0/AV:N" in text
    assert "Not available" in text
    assert item["evidence"]["advisory_href"] in text
    assert "nvd.nist.gov" not in text


@pytest.mark.parametrize("format", ["adf", "wiki"])
def test_cve_epic_links_to_its_own_nvd_record(format):
    item = child_row("CVE-2026-12345")
    _, epic, _ = nodes_for(item)
    rendered = render_product_epic_create_description(epic, [item], format)
    text = json.dumps(rendered) if isinstance(rendered, dict) else rendered
    url = "https://nvd.nist.gov/vuln/detail/CVE-2026-12345"
    assert url in text
    if format == "adf":
        assert any(
            mark.get("attrs", {}).get("href") == url
            for block in rendered["content"]
            for part in block.get("content", [])
            if isinstance(part, dict)
            for mark in part.get("marks", [])
        )
    else:
        assert f"[NVD record|{url}]" in rendered


def test_epic_aggregates_multiple_parent_tasks():
    first = child_row("CVE-2026-12345")
    second = copy.deepcopy(first)
    second["product_href"] = BASE + "/api/projects/other/versions/2"
    second["product"] = "Other Parent"
    second["product_display_name"] = "Other Parent"
    second["product_version"] = "2"
    second["score"] = 9.8
    second["severity"] = "CRITICAL"
    nodes = product.build_nodes([first, second], config())
    epic = next(node for node in nodes if node["node_type"] == "epic")
    assert sum(node["node_type"] == "story" for node in nodes) == 2
    rendered = render_product_epic_create_description(
        epic, [first, second], "wiki"
    )
    assert "|Severity (highest reported)|CRITICAL|" in rendered
    assert "|CVSS Score (maximum overallScore)|9.8|" in rendered
    assert "fieldgate / 1.1.0" in rendered
    assert "Other Parent / 2" in rendered


def test_existing_epic_is_not_rewritten(tmp_path, monkeypatch):
    nodes, _, _ = nodes_for(child_row())
    jira = FakeJira()
    publish_with_fake(monkeypatch, jira, nodes, tmp_path, "create")
    epic = next(
        issue for issue in jira.issues
        if issue["fields"]["issuetype"]["name"] == "Epic"
    )
    assert "Vulnerability overview" in json.dumps(
        epic["fields"]["description"]
    )
    before = copy.deepcopy(epic["fields"]["description"])
    publish_with_fake(
        monkeypatch, jira, nodes, tmp_path, "again", sync=True
    )
    assert epic["fields"]["description"] == before
    assert all(
        "description" not in fields
        for key, fields in jira.updates
        if key == epic["key"]
    )
