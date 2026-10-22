from __future__ import annotations

import copy
import json

import pytest

from wintermute.jira import findings_to_jira as publisher
from wintermute.jira import product_reporting as product
from wintermute.jira.product_document import render_product_create_description

from test_jira_product_reporting import (
    FakeJira,
    config,
    publish_with_fake,
    row,
)


def task_node():
    return next(
        node
        for node in product.build_nodes([row()], config())
        if node["node_type"] == "story"
    )


def test_cloud_create_header_has_bold_job_and_linked_project_version():
    task = task_node()
    report = task["product_report"]
    description = render_product_create_description(report, "adf")
    header = description["content"][:4]
    texts = [
        "".join(part["text"] for part in item["content"])
        for item in header
    ]
    assert texts == [
        "Job name: Vulnerability_Management_JIRA",
        "Project: Example Product",
        "Project Version: 1.1.0",
        "---------------------------",
    ]
    assert header[0]["content"][0]["marks"] == [{"type": "strong"}]
    assert header[0]["content"][1]["marks"] == [{"type": "strong"}]
    assert header[1]["content"][0]["marks"] == [{"type": "strong"}]
    assert header[2]["content"][0]["marks"] == [{"type": "strong"}]
    assert header[1]["content"][1]["marks"] == [{
        "type": "link",
        "attrs": {"href": "https://bd.example.invalid/api/projects/product"},
    }]
    assert header[2]["content"][1]["marks"] == [{
        "type": "link",
        "attrs": {"href": report["rows"][0]["product_href"]},
    }]


def test_datacenter_create_header_is_first_and_linked():
    report = task_node()["product_report"]
    description = render_product_create_description(report, "wiki")
    assert description.splitlines()[:4] == [
        "*Job name:* *Vulnerability_Management_JIRA*",
        "*Project:* [Example Product|https://bd.example.invalid/api/projects/product]",
        "*Project Version:* [1.1.0|https://bd.example.invalid/api/projects/product/versions/1.1.0]",
        "---------------------------",
    ]


@pytest.mark.parametrize(
    "href",
    [
        "https://foreign.example.invalid/other",
        "https://bd.example.invalid/api/projects/product/versions/1?bad=1",
        "https://bd.example.invalid/api/projects/product/versions/1#fragment",
        "https://bd.example.invalid/api/projects/product",
    ],
)
def test_bad_version_link_cannot_generate_create_header(href):
    report = copy.deepcopy(task_node()["product_report"])
    report["rows"][0]["product_href"] = href
    with pytest.raises(RuntimeError, match="project-version URL"):
        render_product_create_description(report, "adf")


def test_create_only_header_and_bdalert_without_sync_trigger(tmp_path, monkeypatch):
    jira = FakeJira()
    nodes = product.build_nodes([row()], config())
    results = publish_with_fake(
        monkeypatch, jira, nodes, tmp_path, "create"
    )
    assert [item["action"] for item in results] == ["created", "created"]
    epic = next(
        issue for issue in jira.issues
        if issue["fields"]["issuetype"]["name"] == "Epic"
    )
    task = next(
        issue for issue in jira.issues
        if issue["fields"]["issuetype"]["name"] == "Task"
    )
    assert "BDAlert" in task["fields"]["labels"]
    assert "Job name:" not in json.dumps(epic["fields"]["description"])
    assert task["fields"]["description"]["content"][0]["content"][0]["text"] == "Job name: "

    publish_with_fake(
        monkeypatch, jira, nodes, tmp_path, "sync", sync=True
    )
    assert len(jira.updates) == 1
    assert "Job name:" not in json.dumps(jira.updates[0][1]["description"])


def test_dry_run_previews_header_without_creating_issue(tmp_path, monkeypatch):
    jira = FakeJira()
    results = publish_with_fake(
        monkeypatch, jira, product.build_nodes([row()], config()),
        tmp_path, "preview", dry_run=True,
    )
    task_result = next(item for item in results if item["node_type"] == "story")
    payload = json.loads(task_result["message"])
    assert "BDAlert" in payload["fields"]["labels"]
    assert payload["fields"]["description"]["content"][0]["content"][1]["text"] == (
        "Vulnerability_Management_JIRA"
    )
    assert jira.creations == 0
