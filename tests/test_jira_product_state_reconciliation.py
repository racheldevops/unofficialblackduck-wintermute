from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

import pytest

from wintermute.jira import findings_to_jira as publisher
from wintermute.jira import product_publishing
from wintermute.jira import product_reporting as product

from test_jira_product_reporting import (
    FakeJira,
    config,
    publish_with_fake,
    row,
)


class ReconciliationJira(FakeJira):
    def __init__(self):
        super().__init__()
        self.fail_search = False

    def request_json(self, method, path, query=None, **kwargs):
        if path == "/rest/api/2/project/SEC":
            return {"key": "SEC"}
        if path == "/rest/api/3/search/jql" and self.fail_search:
            raise RuntimeError("Jira search unavailable")
        return super().request_json(method, path, query=query, **kwargs)


def nodes():
    return product.build_nodes([row()], config())


def test_deleted_issue_stops_before_any_write_by_default(
    tmp_path, monkeypatch,
):
    jira = ReconciliationJira()
    planned = nodes()
    publish_with_fake(monkeypatch, jira, planned, tmp_path, "first")
    state_path = tmp_path / "state.json"
    before = state_path.read_bytes()
    deleted = jira.issues.pop()
    assert deleted["fields"]["issuetype"]["name"] == "Task"

    with pytest.raises(RuntimeError, match="jira-missing-issue-review"):
        publish_with_fake(monkeypatch, jira, planned, tmp_path, "second")

    assert jira.creations == 2
    assert jira.updates == []
    assert state_path.read_bytes() == before
    review = json.loads(
        (tmp_path / "second" / "jira-missing-issue-review.json").read_text()
    )
    assert review["state_changed"] is False
    assert review["missing_from_label_search"][0]["issue_key"] == deleted["key"]


def test_explicit_recovery_preserves_unrelated_mapping_and_backup(
    tmp_path, monkeypatch,
):
    jira = ReconciliationJira()
    planned = nodes()
    publish_with_fake(monkeypatch, jira, planned, tmp_path, "first")
    state_path = tmp_path / "state.json"
    before = state_path.read_bytes()
    deleted = jira.issues.pop()

    selected = product.settings_from(config())
    selected["reconcile_missing_jira_issues"] = True
    monkeypatch.setattr(
        publisher, "build_jira_client", lambda *args, **kwargs: jira
    )
    args = Namespace(
        apply=True, dry_run=False, max_create=1,
        timeout=30, retries=2, retry_delay=1, debug=False,
        description_format="wiki", sync_existing_fields=False,
    )
    results = product_publishing.publish(
        args, config(), planned, state_path, tmp_path / "second", [], selected
    )

    assert [item["action"] for item in results] == [
        "skip_existing_jira", "created",
    ]
    assert jira.creations == 3
    assert results[1]["issue_key"] != deleted["key"]
    review = json.loads(
        (tmp_path / "second" / "jira-missing-issue-review.json").read_text()
    )
    assert review["state_changed"] is True
    assert Path(review["backup_path"]).read_bytes() == before
    saved = json.loads(state_path.read_text())
    assert saved["issues_by_external_id"][planned[0]["external_id"]]["issue_key"] == (
        jira.issues[0]["key"]
    )


def test_pending_creation_blocks_opt_in_without_changing_state(tmp_path):
    jira = ReconciliationJira()
    planned = nodes()
    state_path = tmp_path / "state.json"
    state = {
        "schema_version": 1,
        "issues_by_external_id": {
            planned[0]["external_id"]: {
                "issue_key": "SEC-OLD",
                "rollup_label": planned[0]["lookup_label"],
            },
        },
        "links_by_key": {},
        "product_pending_creates": {
            planned[1]["external_id"]: {
                "lookup_label": planned[1]["lookup_label"],
            },
        },
    }
    product_publishing.save(state_path, state)
    before = state_path.read_bytes()
    with pytest.raises(RuntimeError, match="pending"):
        product_publishing.reconcile_missing_state(
            jira, "SEC", planned, {}, state, state_path, tmp_path,
            state["product_pending_creates"], apply=True, enabled=True,
        )
    assert state_path.read_bytes() == before
    assert jira.creations == 0


def test_search_error_cannot_be_interpreted_as_deletion(
    tmp_path, monkeypatch,
):
    jira = ReconciliationJira()
    planned = nodes()
    publish_with_fake(monkeypatch, jira, planned, tmp_path, "first")
    before = (tmp_path / "state.json").read_bytes()
    jira.fail_search = True
    with pytest.raises(RuntimeError, match="search unavailable"):
        publish_with_fake(monkeypatch, jira, planned, tmp_path, "second")
    assert (tmp_path / "state.json").read_bytes() == before
    assert jira.creations == 2
