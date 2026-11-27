from __future__ import annotations

import copy
import json
from argparse import Namespace

import pytest

from wintermute.jira import findings_to_jira as publisher
from wintermute.jira import product_publishing
from wintermute.jira import product_reporting as product

from test_jira_product_datacenter_reconciliation import DatacenterJira
from test_jira_product_reporting import config, row


def two_advisories():
    first = row()
    second = copy.deepcopy(first)
    second["vulnerability"] = "CVE-2026-99999"
    second["evidence"]["vulnerability"] = second["vulnerability"]
    second["evidence"]["occurrence_href"] = (
        second["source_href"] + "/occurrences/other/CVE-2026-99999"
    )
    second["evidence"]["advisory_href"] = (
        "https://bd.example.invalid/api/vulnerabilities/CVE-2026-99999"
    )
    return product.build_nodes([first, second], config())


def run(monkeypatch, jira, nodes, root, name, max_create, *, recover=False):
    monkeypatch.setattr(
        publisher, "build_jira_client", lambda *args, **kwargs: jira
    )
    monkeypatch.setattr(
        publisher, "prepare_datacenter_hierarchy",
        lambda client, prepared, selected_nodes, description_format: prepared,
    )
    selected = product.settings_from(config())
    selected["reconcile_missing_jira_issues"] = recover
    options = Namespace(
        apply=True,
        dry_run=False,
        max_create=max_create,
        timeout=30,
        retries=2,
        retry_delay=1,
        debug=False,
        description_format="wiki",
        sync_existing_fields=False,
    )
    return product_publishing.publish(
        options, config(), nodes, root / "state.json", root / name, [],
        selected,
    )


def test_other_epic_conflict_precedes_missing_task_recovery(
    tmp_path, monkeypatch,
):
    jira = DatacenterJira()
    nodes = two_advisories()

    # Epics sort before Tasks; these two runs create all four issues.
    run(monkeypatch, jira, nodes, tmp_path, "epics", 2)
    run(monkeypatch, jira, nodes, tmp_path, "tasks", 2)
    assert jira.creations == 4

    state_path = tmp_path / "state.json"
    original = state_path.read_bytes()
    state = json.loads(original)

    tasks = [node for node in nodes if node["node_type"] == "story"]
    epics = [node for node in nodes if node["node_type"] == "epic"]
    missing_task = state["issues_by_external_id"][tasks[0]["external_id"]]["issue_key"]
    conflicting_epic = state["issues_by_external_id"][epics[1]["external_id"]]["issue_key"]

    jira.issues = [
        issue for issue in jira.issues if issue["key"] != missing_task
    ]
    next(
        issue for issue in jira.issues
        if issue["key"] == conflicting_epic
    )["key"] = "SEC-88"

    with pytest.raises(RuntimeError, match="identities disagree"):
        run(monkeypatch, jira, nodes, tmp_path, "conflict", 2, recover=True)

    assert state_path.read_bytes() == original
    assert jira.creations == 4
    assert not list(tmp_path.glob("state.json.before-reconciliation-*.bak"))


def test_other_epic_get_failure_precedes_missing_task_recovery(
    tmp_path, monkeypatch,
):
    jira = DatacenterJira()
    nodes = two_advisories()
    run(monkeypatch, jira, nodes, tmp_path, "epics", 2)
    run(monkeypatch, jira, nodes, tmp_path, "tasks", 2)

    state_path = tmp_path / "state.json"
    original = state_path.read_bytes()
    state = json.loads(original)
    tasks = [node for node in nodes if node["node_type"] == "story"]
    epics = [node for node in nodes if node["node_type"] == "epic"]
    missing_task = state["issues_by_external_id"][tasks[0]["external_id"]]["issue_key"]
    jira.issues = [
        issue for issue in jira.issues if issue["key"] != missing_task
    ]
    jira.fail_issue_key = state["issues_by_external_id"][
        epics[1]["external_id"]
    ]["issue_key"]

    with pytest.raises(RuntimeError, match="HTTP 404"):
        run(monkeypatch, jira, nodes, tmp_path, "get-failure", 2, recover=True)

    assert state_path.read_bytes() == original
    assert jira.creations == 4
    assert not list(tmp_path.glob("state.json.before-reconciliation-*.bak"))
