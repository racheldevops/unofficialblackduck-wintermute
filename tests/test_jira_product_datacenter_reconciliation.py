from __future__ import annotations

import copy
import io
import json
from pathlib import Path
from urllib.error import HTTPError

import pytest

from wintermute.jira import findings_to_jira as publisher
from wintermute.jira import product_publishing
from wintermute.jira import product_reporting as product

from test_jira_product_reporting import FakeJira, config, row


class DatacenterJira(FakeJira):
    def __init__(self):
        super().__init__(deployment="datacenter")
        self.fail_search = False
        self.fail_issue_key = ""

    def request_json(self, method, path, query=None, **kwargs):
        if path == "/rest/api/2/search":
            if self.fail_search:
                raise RuntimeError("Jira Data Center search unavailable")
            assert method == "GET"
            offset = query["startAt"]
            issues = copy.deepcopy(self.issues)
            return {
                "issues": issues[offset:offset + query["maxResults"]],
                "startAt": offset,
                "total": len(issues),
            }
        if path == "/rest/api/2/project/SEC":
            assert method == "GET"
            return {"key": "SEC"}
        if path.startswith("/rest/api/2/issue/SEC-"):
            key = path.rsplit("/", 1)[-1]
            if key == self.fail_issue_key or not any(
                issue["key"] == key for issue in self.issues
            ):
                raise RuntimeError(
                    f"GET https://jira.example.invalid{path} failed: HTTP 404 "
                    '{"errorMessages":["Issue Does Not Exist"],"errors":{}}'
                )
        return super().request_json(method, path, query=query, **kwargs)

    def create_issue(self, payload):
        assert self.retries == 0
        assert self.api_version == "2"
        self.creations += 1
        key = f"SEC-{self.creations}"
        fields = copy.deepcopy(payload["fields"])
        fields["status"] = {"name": "Open"}
        self.issues.append({"key": key, "fields": fields})
        return {"key": key}


def planned_nodes():
    return product.build_nodes([row()], config())


def publish(monkeypatch, jira, nodes, tmp_path, run, *, recover=False):
    monkeypatch.setattr(
        publisher, "build_jira_client", lambda *args, **kwargs: jira
    )
    # The separate DC create-metadata preflight has its own test coverage.
    # Here we exercise product state reconciliation against DC search and GET.
    monkeypatch.setattr(
        publisher, "prepare_datacenter_hierarchy",
        lambda client, prepared, selected_nodes, description_format: prepared,
    )
    options = type("Options", (), {
        "apply": True,
        "dry_run": False,
        "max_create": 2,
        "timeout": 30,
        "retries": 2,
        "retry_delay": 1,
        "debug": False,
        "description_format": "wiki",
        "sync_existing_fields": False,
    })()
    settings = product.settings_from(config())
    settings["reconcile_missing_jira_issues"] = recover
    return product_publishing.publish(
        options, config(), nodes, tmp_path / "state.json",
        tmp_path / run, [], settings,
    )


def test_real_jira_transport_reports_datacenter_404(monkeypatch):
    calls = []

    def not_found(request, **kwargs):
        calls.append(request.full_url)
        raise HTTPError(
            request.full_url,
            404,
            "Not Found",
            {},
            io.BytesIO(
                b'{"errorMessages":["Issue Does Not Exist"],"errors":{}}'
            ),
        )

    monkeypatch.setattr(publisher, "urlopen", not_found)
    client = publisher.JiraClient(
        base_url="https://jira.example.invalid",
        api_version="2",
        auth_mode="bearer",
        username=None,
        api_token=None,
        pat="test-token",
        verify_tls=True,
        timeout=2,
        retries=2,
        retry_delay=0,
        debug=False,
    )

    with pytest.raises(RuntimeError) as caught:
        client.request_json(
            "GET",
            "/rest/api/2/issue/SEC-64",
            query={"fields": "project,issuetype,labels,parent,status"},
        )
    assert "HTTP 404" in str(caught.value)
    assert "Issue Does Not Exist" in str(caught.value)
    assert len(calls) == 1


def test_datacenter_deleted_task_fails_closed(tmp_path, monkeypatch):
    jira = DatacenterJira()
    nodes = planned_nodes()
    publish(monkeypatch, jira, nodes, tmp_path, "first")
    state_path = tmp_path / "state.json"
    original = state_path.read_bytes()
    deleted = jira.issues.pop()
    assert deleted["fields"]["issuetype"]["name"] == "Task"

    with pytest.raises(RuntimeError, match="jira-missing-issue-review"):
        publish(monkeypatch, jira, nodes, tmp_path, "review")

    assert jira.creations == 2
    assert state_path.read_bytes() == original
    review = json.loads(
        (tmp_path / "review" / "jira-missing-issue-review.json")
        .read_text(encoding="utf-8")
    )
    assert review["state_changed"] is False
    assert [
        item["issue_key"] for item in review["missing_from_label_search"]
    ] == [deleted["key"]]


def test_datacenter_opt_in_recovers_only_deleted_task(tmp_path, monkeypatch):
    jira = DatacenterJira()
    nodes = planned_nodes()
    publish(monkeypatch, jira, nodes, tmp_path, "first")
    state_path = tmp_path / "state.json"
    original = state_path.read_bytes()
    old_task = jira.issues.pop()

    results = publish(
        monkeypatch, jira, nodes, tmp_path, "recover", recover=True
    )

    assert [item["action"] for item in results] == [
        "skip_existing_jira", "created",
    ]
    assert results[0]["issue_key"] == jira.issues[0]["key"]
    assert results[1]["issue_key"] != old_task["key"]
    assert jira.creations == 3
    review = json.loads(
        (tmp_path / "recover" / "jira-missing-issue-review.json")
        .read_text(encoding="utf-8")
    )
    assert review["state_changed"] is True
    assert Path(review["backup_path"]).read_bytes() == original


def test_datacenter_key_disagreement_blocks_all_writes(tmp_path, monkeypatch):
    jira = DatacenterJira()
    nodes = planned_nodes()
    publish(monkeypatch, jira, nodes, tmp_path, "first")
    state_path = tmp_path / "state.json"
    original = state_path.read_bytes()

    # The label still belongs to an issue, but not to the saved key.
    jira.issues[0]["key"] = "SEC-88"
    with pytest.raises(RuntimeError, match="identities disagree"):
        publish(
            monkeypatch, jira, nodes, tmp_path, "disagree", recover=True
        )

    assert state_path.read_bytes() == original
    assert jira.creations == 2


def test_datacenter_get_404_after_successful_search_never_resets_state(
    tmp_path, monkeypatch,
):
    jira = DatacenterJira()
    nodes = planned_nodes()
    publish(monkeypatch, jira, nodes, tmp_path, "first")
    state_path = tmp_path / "state.json"
    original = state_path.read_bytes()
    jira.fail_issue_key = jira.issues[0]["key"]

    with pytest.raises(RuntimeError, match="HTTP 404"):
        publish(
            monkeypatch, jira, nodes, tmp_path, "get-404", recover=True
        )

    assert state_path.read_bytes() == original
    assert jira.creations == 2


def test_datacenter_search_failure_never_resets_state(
    tmp_path, monkeypatch,
):
    jira = DatacenterJira()
    nodes = planned_nodes()
    publish(monkeypatch, jira, nodes, tmp_path, "first")
    state_path = tmp_path / "state.json"
    original = state_path.read_bytes()
    jira.fail_search = True

    with pytest.raises(RuntimeError, match="search unavailable"):
        publish(
            monkeypatch, jira, nodes, tmp_path, "search-error", recover=True
        )

    assert state_path.read_bytes() == original
    assert jira.creations == 2
