from __future__ import annotations

import argparse
import copy
import csv
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from harness.jira import findings_to_jira as publisher


def config_with_project() -> dict[str, Any]:
    return publisher.deep_merge(
        copy.deepcopy(publisher.DEFAULT_CONFIG),
        {
            "jira": {
                "url": "",
                "project_key": "SEC",
                "issue_type": "Task",
            }
        },
    )


def test_deep_merge_preserves_nested_defaults() -> None:
    merged = publisher.deep_merge(
        {
            "jira": {"url": "", "project_key": "", "api_version": "2"},
            "issue": {"labels": ["base"]},
        },
        {
            "jira": {"project_key": "SEC"},
        },
    )

    assert merged["jira"] == {
        "url": "",
        "project_key": "SEC",
        "api_version": "2",
    }
    assert merged["issue"]["labels"] == ["base"]


def test_load_state_creates_required_sections(tmp_path: Path) -> None:
    state = publisher.load_state(str(tmp_path / "missing.json"))

    assert state["schema_version"] == 1
    assert state["issues_by_external_id"] == {}
    assert state["links_by_key"] == {}


def test_load_state_rejects_invalid_sections(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    state_path.write_text(
        json.dumps(
            {
                "issues_by_external_id": [],
                "links_by_key": {},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="issues_by_external_id"):
        publisher.load_state(str(state_path))


def test_rollup_external_id_and_label_are_deterministic() -> None:
    config = {
        "dedupe": {
            "label_prefix": "bd_",
            "hash_length": 12,
        }
    }

    first_id = publisher.rollup_external_id("a|b|c")
    second_id = publisher.rollup_external_id("a|b|c")

    assert first_id == second_id
    assert len(first_id) == 64
    assert publisher.rollup_label("a|b|c", config) == (
        f"bd_{first_id[:12]}"
    )


def test_validate_rollup_key_hash_normalizes_case() -> None:
    value = "A" * 64
    assert publisher.validate_rollup_key_hash(value) == value.lower()

    with pytest.raises(RuntimeError, match="64-character"):
        publisher.validate_rollup_key_hash("abc")


def test_normalize_finding_moves_component_resource_url(
    sample_finding_factory: Callable[..., dict[str, str]],
) -> None:
    url = "https://bd.example/api/components/a/versions/b"
    normalized = publisher.normalize_finding(
        sample_finding_factory(
            component_version=url,
            component_version_href="",
            severity="critical",
        )
    )

    assert normalized["component_version"] == ""
    assert normalized["component_version_href"] == url
    assert normalized["severity"] == "CRITICAL"


def test_build_issue_payload_applies_summary_labels_and_priority(
    sample_finding_factory: Callable[..., dict[str, str]],
) -> None:
    config = publisher.deep_merge(
        config_with_project(),
        {
            "issue": {
                "additional_fields": {
                    "customfield_team": "{entity}",
                }
            }
        },
    )
    finding = publisher.normalize_finding(sample_finding_factory())

    payload, lookup_label = publisher.build_issue_payload(
        finding,
        config,
        description_format="wiki",
        timeout=1,
        debug=False,
    )
    fields = payload["fields"]

    assert fields["project"] == {"key": "SEC"}
    assert fields["issuetype"] == {"name": "Task"}
    assert fields["summary"].startswith(
        "Black Duck: BLOCKER Alert - Child - version 2.0"
    )
    assert fields["priority"] == {"name": "Highest"}
    assert fields["customfield_team"] == "Team A"
    assert lookup_label in fields["labels"]
    assert "BDAlert" in fields["labels"]
    assert "CVE-2026-0001" in fields["labels"]
    assert "bd_sev_critical" in fields["labels"]
    assert isinstance(fields["description"], str)


def test_build_issue_payload_supports_adf(
    sample_finding_factory: Callable[..., dict[str, str]],
) -> None:
    payload, _ = publisher.build_issue_payload(
        publisher.normalize_finding(sample_finding_factory()),
        config_with_project(),
        description_format="adf",
        timeout=1,
        debug=False,
    )

    assert payload["fields"]["description"]["type"] == "doc"
    assert payload["fields"]["description"]["version"] == 1
    assert payload["fields"]["description"]["content"]


def test_filter_hierarchy_nodes_preserves_ancestors() -> None:
    nodes = [
        {
            "node_type": "epic",
            "external_id": "epic-1",
            "parent_external_id": "",
            "context": {},
        },
        {
            "node_type": "story",
            "external_id": "story-1",
            "parent_external_id": "epic-1",
            "context": {
                "subproject": "Selected",
                "vulnerability": "CVE-1",
            },
        },
        {
            "node_type": "story",
            "external_id": "story-2",
            "parent_external_id": "epic-1",
            "context": {
                "subproject": "Other",
                "vulnerability": "CVE-1",
            },
        },
    ]
    args = argparse.Namespace(
        only_parent_project=None,
        only_parent_version=None,
        only_subproject="Selected",
        only_vulnerability=None,
        limit=None,
    )

    filtered = publisher.filter_hierarchy_nodes(nodes, args)

    assert [
        node["external_id"]
        for node in filtered
    ] == ["epic-1", "story-1"]


def test_hierarchy_managed_fields_support_value_types() -> None:
    node = {
        "node_type": "story",
        "context": {
            "name": "Project A",
            "severity_option": "Critical",
            "tags": "one;two",
        },
        "stats": {
            "max_score": "9.8",
        },
    }
    config = {
        "hierarchy": {
            "field_mappings": {
                "name": {
                    "field_id": "customfield_text",
                    "source": "name",
                    "node_types": ["story"],
                    "value_type": "text",
                },
                "score": {
                    "field_id": "customfield_number",
                    "source": "stats.max_score",
                    "node_types": ["story"],
                    "value_type": "number",
                },
                "option": {
                    "field_id": "customfield_option",
                    "source": "severity_option",
                    "node_types": ["story"],
                    "value_type": "option",
                },
                "tags": {
                    "field_id": "customfield_array",
                    "source": "tags",
                    "node_types": ["story"],
                    "value_type": "array",
                },
            }
        }
    }

    fields = publisher.hierarchy_managed_fields_for_node(node, config)

    assert fields == {
        "customfield_text": "Project A",
        "customfield_number": 9.8,
        "customfield_option": {"value": "Critical"},
        "customfield_array": ["one", "two"],
    }


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("jira_parent", {"parent": {"key": "SEC-1"}}),
        ("issue_link", {}),
        (
            "epic_link_field",
            {"customfield_epic": "SEC-1"},
        ),
    ],
)
def test_apply_parent_supports_configured_modes(
    mode: str,
    expected: dict[str, Any],
) -> None:
    payload: dict[str, Any] = {"fields": {}}
    node = {
        "node_type": "story",
        "external_id": "story",
    }
    config = {
        "hierarchy": {
            "story_parent_mode": mode,
            "epic_link_field": "customfield_epic",
        }
    }

    publisher.apply_parent_to_hierarchy_payload(
        payload,
        node,
        "SEC-1",
        config,
    )

    assert payload["fields"] == expected


def test_apply_parent_rejects_missing_epic_link_field() -> None:
    with pytest.raises(RuntimeError, match="epic_link_field"):
        publisher.apply_parent_to_hierarchy_payload(
            {"fields": {}},
            {"node_type": "story"},
            "SEC-1",
            {
                "hierarchy": {
                    "story_parent_mode": "epic_link_field",
                    "epic_link_field": "",
                }
            },
        )


def test_hierarchy_summary_uses_component_aggregation() -> None:
    config = config_with_project()
    single = {
        "node_type": "story",
        "summary": "fallback",
        "external_id": "story-1",
        "lookup_label": "story-1",
        "parent_external_id": "epic-1",
        "context": {
            "severity": "CRITICAL",
            "affected_project": "Service",
            "affected_version": "1.0",
            "components": ["openssl"],
            "component_versions": ["3.0.1"],
        },
        "stats": {
            "component_count": 1,
        },
    }
    multiple = copy.deepcopy(single)
    multiple["stats"]["component_count"] = 3

    assert publisher.hierarchy_summary_for_node(
        single,
        config,
    ).endswith("openssl version 3.0.1")
    assert publisher.hierarchy_summary_for_node(
        multiple,
        config,
    ).endswith("3 affected components")


def test_build_hierarchy_payload_requires_project_key() -> None:
    node = {
        "node_type": "epic",
        "external_id": "epic",
        "summary": "Epic",
        "context": {},
        "stats": {},
    }

    with pytest.raises(RuntimeError, match="project_key"):
        publisher.build_hierarchy_issue_payload(
            node,
            {"jira": {"project_key": ""}},
            "wiki",
        )


def test_jira_client_auth_modes() -> None:
    basic = publisher.JiraClient(
        base_url="https://jira.example",
        api_version="2",
        auth_mode="basic",
        username="user",
        api_token="token",
        pat=None,
        verify_tls=True,
        timeout=1,
        retries=0,
        retry_delay=0,
        debug=False,
    )
    bearer = publisher.JiraClient(
        base_url="https://jira.example",
        api_version="2",
        auth_mode="bearer",
        username=None,
        api_token=None,
        pat="pat-token",
        verify_tls=True,
        timeout=1,
        retries=0,
        retry_delay=0,
        debug=False,
    )

    assert basic.enabled() is True
    assert basic.auth_headers()["Authorization"].startswith("Basic ")
    assert bearer.enabled() is True
    assert bearer.auth_headers() == {
        "Authorization": "Bearer pat-token"
    }


def test_search_by_labels_handles_pagination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = publisher.JiraClient(
        base_url="https://jira.example",
        api_version="3",
        auth_mode="basic",
        username="user",
        api_token="token",
        pat=None,
        verify_tls=True,
        timeout=1,
        retries=0,
        retry_delay=0,
        debug=False,
    )
    queries: list[dict[str, Any]] = []

    def fake_request(
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        query: dict[str, Any] | None = None,
        expected_statuses: set[int] | None = None,
    ) -> dict[str, Any]:
        del payload, expected_statuses
        assert method == "GET"
        assert path == "/rest/api/3/search/jql"
        current_query = dict(query or {})
        queries.append(current_query)

        if "nextPageToken" not in current_query:
            return {
                "issues": [
                    {
                        "key": "SEC-1",
                        "fields": {
                            "summary": "First",
                            "labels": ["label-a"],
                            "status": {"name": "Open"},
                        },
                    }
                ],
                "isLast": False,
                "nextPageToken": "next",
            }

        return {
            "issues": [
                {
                    "key": "SEC-2",
                    "fields": {
                        "summary": "Second",
                        "labels": ["label-b"],
                        "status": {"name": "Done"},
                    },
                }
            ],
            "isLast": True,
        }

    monkeypatch.setattr(client, "request_json", fake_request)

    found = client.search_by_labels(
        "SEC",
        ["label-a", "label-b"],
        batch_size=2,
    )

    assert found["label-a"]["key"] == "SEC-1"
    assert found["label-b"]["key"] == "SEC-2"
    assert queries[1]["nextPageToken"] == "next"


def test_transition_issue_uses_matching_transition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = publisher.JiraClient(
        base_url="https://jira.example",
        api_version="2",
        auth_mode="basic",
        username="user",
        api_token="token",
        pat=None,
        verify_tls=True,
        timeout=1,
        retries=0,
        retry_delay=0,
        debug=False,
    )
    statuses = iter(["Open", "Done"])
    requests: list[tuple[str, str, dict[str, Any] | None]] = []

    monkeypatch.setattr(
        client,
        "get_issue_status",
        lambda _: next(statuses),
    )
    monkeypatch.setattr(
        client,
        "get_issue_transitions",
        lambda _: [
            {"id": "10", "to": {"name": "In Progress"}},
            {"id": "20", "to": {"name": "Done"}},
        ],
    )

    def fake_request(
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        query: dict[str, Any] | None = None,
        expected_statuses: set[int] | None = None,
    ) -> dict[str, Any]:
        del query, expected_statuses
        requests.append((method, path, payload))
        return {}

    monkeypatch.setattr(client, "request_json", fake_request)

    assert client.transition_issue_to_status("SEC-1", "done") == "Done"
    assert requests == [
        (
            "POST",
            "/rest/api/2/issue/SEC-1/transitions",
            {"transition": {"id": "20"}},
        )
    ]


def test_transition_issue_reports_available_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = publisher.JiraClient(
        base_url="https://jira.example",
        api_version="2",
        auth_mode="basic",
        username="user",
        api_token="token",
        pat=None,
        verify_tls=True,
        timeout=1,
        retries=0,
        retry_delay=0,
        debug=False,
    )
    monkeypatch.setattr(
        client,
        "get_issue_status",
        lambda _: "Open",
    )
    monkeypatch.setattr(
        client,
        "get_issue_transitions",
        lambda _: [{"id": "1", "to": {"name": "In Progress"}}],
    )

    with pytest.raises(RuntimeError, match="In Progress"):
        client.transition_issue_to_status("SEC-1", "Done")


def test_update_state_preserves_first_seen_timestamp() -> None:
    state: dict[str, Any] = {
        "issues_by_external_id": {},
        "links_by_key": {},
    }

    publisher.update_state_issue(
        state,
        external_id="external",
        rollup_key="rollup",
        rollup_label_value="label",
        issue_key="SEC-1",
        status="Open",
        action="created",
    )
    first_seen = state["issues_by_external_id"]["external"][
        "first_seen_at"
    ]

    publisher.update_state_issue(
        state,
        external_id="external",
        rollup_key="rollup",
        rollup_label_value="label",
        issue_key="SEC-1",
        status="Done",
        action="updated",
    )

    assert (
        state["issues_by_external_id"]["external"]["first_seen_at"]
        == first_seen
    )
    assert (
        state["issues_by_external_id"]["external"]["last_action"]
        == "updated"
    )


def test_process_hierarchy_plan_dry_run_is_end_to_end(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "JIRA_URL",
        "JIRA_USER",
        "JIRA_API_TOKEN",
        "JIRA_PAT",
    ):
        monkeypatch.delenv(name, raising=False)

    plan_path = tmp_path / "hierarchy.json"
    config_path = tmp_path / "config.json"
    state_path = tmp_path / "state.json"
    results_path = tmp_path / "results.csv"
    publish_plan_path = tmp_path / "publish-plan.json"

    plan_path.write_text(
        json.dumps(
            {
                "nodes": [
                    {
                        "node_type": "epic",
                        "external_id": "epic-1",
                        "lookup_label": "epic-lookup",
                        "parent_external_id": "",
                        "summary": "CVE Epic",
                        "description": "Epic description",
                        "labels": ["epic-label"],
                        "context": {
                            "vulnerability": "CVE-1",
                            "severity": "HIGH",
                        },
                        "stats": {"high_count": 1},
                    },
                    {
                        "node_type": "story",
                        "external_id": "story-1",
                        "lookup_label": "story-lookup",
                        "parent_external_id": "epic-1",
                        "summary": "Project task",
                        "description": "Task description",
                        "labels": ["story-label"],
                        "context": {
                            "vulnerability": "CVE-1",
                            "severity": "HIGH",
                            "affected_project": "Service",
                            "affected_version": "1.0",
                            "components": ["library"],
                            "component_versions": ["2.0"],
                        },
                        "stats": {
                            "component_count": 1,
                            "high_count": 1,
                        },
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    config_path.write_text(
        json.dumps(
            {
                "jira": {
                    "url": "",
                    "project_key": "SEC",
                    "auth_mode": "basic",
                },
                "hierarchy": {
                    "story_parent_mode": "jira_parent",
                },
            }
        ),
        encoding="utf-8",
    )

    args = argparse.Namespace(
        config=str(config_path),
        state=str(state_path),
        hierarchy_plan=str(plan_path),
        sync_existing_fields=False,
        only_parent_project=None,
        only_parent_version=None,
        only_subproject=None,
        only_vulnerability=None,
        limit=None,
        timeout=1,
        retries=0,
        retry_delay=0,
        debug=False,
        dry_run=True,
        apply=False,
        refresh_existing=False,
        jql_label_batch_size=50,
        description_format="wiki",
        max_create=None,
        plan_out=str(publish_plan_path),
        results_out=str(results_path),
    )

    assert publisher.process_hierarchy_plan(args) == 0

    output = json.loads(publish_plan_path.read_text(encoding="utf-8"))
    assert output["dry_run"] is True
    assert output["processed_node_count"] == 2
    assert [result["action"] for result in output["results"]] == [
        "would_create",
        "would_create",
    ]

    story_result = next(
        result
        for result in output["results"]
        if result["node_type"] == "story"
    )
    story_message = json.loads(story_result["message"])
    assert story_message["fields"]["parent"]["key"].startswith("DRY-")
    assert not state_path.exists()

    with results_path.open(newline="", encoding="utf-8") as input_file:
        assert len(list(csv.DictReader(input_file))) == 2


def test_load_hierarchy_plan_rejects_invalid_node(
    tmp_path: Path,
) -> None:
    path = tmp_path / "invalid-plan.json"
    path.write_text(
        json.dumps(
            {
                "nodes": [
                    {
                        "external_id": "node",
                        "node_type": "unsupported",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="unsupported node_type"):
        publisher.load_hierarchy_plan(str(path))
