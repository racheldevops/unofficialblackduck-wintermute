from __future__ import annotations

import copy

import pytest

from wintermute.jira import findings_to_jira as publisher


NAME_FIELD = "customfield_12345"
LINK_FIELD = "customfield_67890"


def configuration():
    return publisher.deep_merge(
        copy.deepcopy(publisher.DEFAULT_CONFIG),
        {"jira": {"project_key": "SEC", "api_version": "2"}},
    )


def nodes():
    return [
        {
            "node_type": "epic",
            "external_id": "epic-one",
            "parent_external_id": "",
            "lookup_label": "epic-one",
            "summary": "CVE example",
            "description": "Epic description",
            "context": {},
            "stats": {},
        },
        {
            "node_type": "story",
            "external_id": "task-one",
            "parent_external_id": "epic-one",
            "lookup_label": "task-one",
            "summary": "Affected project",
            "description": "Task description",
            "context": {},
            "stats": {},
        },
    ]


class Client:
    def __init__(self, deployment="Server"):
        self.base_url = "https://jira.example.invalid/jira"
        self.api_version = "2"
        self.debug = False
        self.deployment = deployment
        self.calls = []
        self.fields = [
            {
                "id": NAME_FIELD,
                "schema": {"custom": "com.pyxis.greenhopper.jira:gh-epic-label"},
            },
            {
                "id": LINK_FIELD,
                "schema": {"custom": "com.pyxis.greenhopper.jira:gh-epic-link"},
            },
        ]
        common = [
            {"fieldId": "project", "required": True},
            {"fieldId": "issuetype", "required": True},
            {"fieldId": "summary", "required": True},
            {"fieldId": "description", "required": False},
            {"fieldId": "labels", "required": False},
        ]
        self.metadata = {
            "1": common + [{"fieldId": NAME_FIELD, "required": True}],
            "2": common + [{"fieldId": LINK_FIELD, "required": False}],
        }

    def request_json(self, method, path, query=None, **kwargs):
        assert method == "GET", "Preflight must never mutate Jira"
        self.calls.append((path, dict(query or {})))
        if path == "/rest/api/2/serverInfo":
            return {"deploymentType": self.deployment, "version": "9.12.35"}
        if path == "/rest/api/2/field":
            return copy.deepcopy(self.fields)
        root = "/rest/api/2/issue/createmeta/SEC/issuetypes"
        if path == root:
            values = [
                {"id": "1", "name": "Epic", "subtask": False},
                {"id": "2", "name": "Task", "subtask": False},
            ]
        elif path.startswith(root + "/"):
            values = self.metadata[path.rsplit("/", 1)[-1]]
        else:
            raise AssertionError(f"Unexpected endpoint: {path}")

        # Deliberately cap responses to one entry to test pagination.
        offset = query["startAt"]
        return {
            "startAt": offset,
            "maxResults": 1,
            "total": len(values),
            "isLast": offset + 1 >= len(values),
            "values": copy.deepcopy(values[offset:offset + 1]),
        }


@pytest.mark.parametrize("deployment", ["Server", "Data Center"])
def test_discovers_epic_fields_and_builds_datacenter_payloads(deployment):
    client = Client(deployment)
    original = configuration()
    planned_nodes = nodes()

    selected = publisher.prepare_datacenter_hierarchy(
        client, original, planned_nodes, "wiki",
    )
    assert selected["hierarchy"]["story_parent_mode"] == "epic_link_field"
    assert selected["hierarchy"]["epic_link_field"] == LINK_FIELD
    assert original["hierarchy"]["story_parent_mode"] == "jira_parent"
    assert original["hierarchy"]["additional_fields"]["epic"] == {}

    epic = publisher.build_hierarchy_issue_payload(planned_nodes[0], selected, "wiki")
    task = publisher.build_hierarchy_issue_payload(planned_nodes[1], selected, "wiki")
    publisher.apply_parent_to_hierarchy_payload(
        task, planned_nodes[1], "SEC-101", selected,
    )
    assert epic["fields"][NAME_FIELD] == "CVE example"
    assert task["fields"][LINK_FIELD] == "SEC-101"
    assert "parent" not in task["fields"]
    assert "PREFLIGHT-1" not in str(task)
    assert client.api_version == "2"
    assert sum(path == "/rest/api/2/field" for path, _ in client.calls) == 1


def test_cloud_payload_configuration_is_unchanged():
    client = Client("Cloud")
    config = configuration()
    result = publisher.prepare_datacenter_hierarchy(client, config, nodes(), "adf")
    assert result is config
    assert client.calls == [("/rest/api/2/serverInfo", {})]


def test_explicit_epic_name_is_preserved():
    config = configuration()
    config["hierarchy"]["additional_fields"]["epic"][NAME_FIELD] = "Custom name"
    selected = publisher.prepare_datacenter_hierarchy(Client(), config, nodes(), "wiki")
    payload = publisher.build_hierarchy_issue_payload(nodes()[0], selected, "wiki")
    assert payload["fields"][NAME_FIELD] == "Custom name"


def test_explicit_issue_link_mode_is_preserved():
    config = configuration()
    config["hierarchy"]["story_parent_mode"] = "issue_link"
    selected = publisher.prepare_datacenter_hierarchy(Client(), config, nodes(), "wiki")
    assert selected["hierarchy"]["story_parent_mode"] == "issue_link"


def test_conflicting_explicit_epic_link_is_rejected():
    config = configuration()
    config["hierarchy"]["epic_link_field"] = "customfield_99999"
    with pytest.raises(RuntimeError, match="does not match"):
        publisher.prepare_datacenter_hierarchy(Client(), config, nodes(), "wiki")


def test_missing_required_field_is_rejected():
    client = Client()
    client.metadata["2"].append({
        "fieldId": "customfield_90000",
        "required": True,
        "hasDefaultValue": False,
    })
    with pytest.raises(RuntimeError, match="customfield_90000"):
        publisher.prepare_datacenter_hierarchy(client, configuration(), nodes(), "wiki")


def test_server_default_satisfies_required_field():
    client = Client()
    client.metadata["2"].append({
        "fieldId": "customfield_90000",
        "required": True,
        "hasDefaultValue": True,
    })
    publisher.prepare_datacenter_hierarchy(client, configuration(), nodes(), "wiki")


def test_missing_epic_link_on_create_screen_is_rejected():
    client = Client()
    client.metadata["2"] = [
        field for field in client.metadata["2"] if field["fieldId"] != LINK_FIELD
    ]
    with pytest.raises(RuntimeError, match="unavailable for creation"):
        publisher.prepare_datacenter_hierarchy(client, configuration(), nodes(), "wiki")


def test_ambiguous_schema_is_rejected():
    client = Client()
    client.fields.append({
        "id": "customfield_55555",
        "schema": {"custom": "com.pyxis.greenhopper.jira:gh-epic-link"},
    })
    with pytest.raises(RuntimeError, match="ambiguous"):
        publisher.prepare_datacenter_hierarchy(client, configuration(), nodes(), "wiki")


def test_invalid_priority_is_rejected():
    client = Client()
    client.metadata["2"].append({
        "fieldId": "priority",
        "required": False,
        "allowedValues": [{"name": "Major"}, {"name": "Minor"}],
    })
    planned_nodes = nodes()
    planned_nodes[1]["context"]["severity"] = "HIGH"
    with pytest.raises(RuntimeError, match="priority"):
        publisher.prepare_datacenter_hierarchy(
            client, configuration(), planned_nodes, "wiki",
        )


def test_cached_detection_avoids_extra_server_info_request():
    client = Client()
    assert publisher.detect_jira_deployment(client) == "datacenter"
    assert publisher.detect_jira_deployment(client) == "datacenter"
    assert client.calls == [("/rest/api/2/serverInfo", {})]


def test_metadata_authentication_error_propagates():
    client = Client()
    def denied(*args, **kwargs):
        raise RuntimeError("HTTP 403")
    client.request_json = denied
    with pytest.raises(RuntimeError, match="403"):
        publisher.prepare_datacenter_hierarchy(client, configuration(), nodes(), "wiki")
