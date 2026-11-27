from __future__ import annotations

import copy
from pathlib import Path

import pytest

from wintermute.jira.entity_mapping import resolve_entity_mapping
from wintermute.jira.findings_to_jira import (
    build_hierarchy_issue_payload,
    hierarchy_managed_fields_for_node,
)


SQL_FEED = (
    "com.valiantys.jira.plugins.SQLFeed:"
    "nfeed-standard-customfield-type"
)


def configuration():
    return {
        "jira": {"project_key": "SEC"},
        "hierarchy": {
            "story_issue_type": "Task",
            "field_mappings": {
                "entity": {
                    "field_id": "",
                    "source": "entity",
                    "node_types": ["story"],
                    "value_type": "array",
                },
            },
        },
    }


def task():
    return {
        "node_type": "story",
        "external_id": "task-one",
        "summary": "Affected project",
        "description": "Test description",
        "context": {"entity": "Example entity"},
        "stats": {},
    }


class Jira:
    def __init__(self, schema, *, operations=None):
        self.schema = schema
        self.operations = ["set"] if operations is None else operations
        self.calls = []

    def request_json(self, method, path, *, query, expected_statuses):
        assert method == "GET"
        assert expected_statuses == {200}
        self.calls.append(path)

        root = "/rest/api/2/issue/createmeta/SEC/issuetypes"
        if path == root:
            return {
                "values": [{"id": "10001", "name": "Task"}],
                "startAt": 0,
                "total": 1,
                "isLast": True,
            }
        if path == root + "/10001":
            return {
                "values": [{
                    "fieldId": "customfield_14313",
                    "name": "Entity",
                    "schema": self.schema,
                    "operations": self.operations,
                }],
                "startAt": 0,
                "total": 1,
                "isLast": True,
            }
        raise AssertionError(f"Unexpected Jira request: {path}")


def test_sql_feed_entity_is_discovered_and_rendered_as_array():
    original = configuration()
    before = copy.deepcopy(original)
    node = task()
    client = Jira({
        "type": "array",
        "items": "string",
        "custom": SQL_FEED,
        "customId": 14313,
    })

    prepared = resolve_entity_mapping(
        client, original, [node], "datacenter"
    )
    mapping = prepared["hierarchy"]["field_mappings"]["entity"]
    fields = build_hierarchy_issue_payload(node, prepared, "wiki")["fields"]

    assert mapping["field_id"] == "customfield_14313"
    assert mapping["value_type"] == "array"
    assert fields["customfield_14313"] == ["Example entity"]
    assert original == before
    assert all(path.startswith("/rest/api/2/issue/createmeta/") for path in client.calls)


@pytest.mark.parametrize("schema", [
    {"type": "array", "items": "string", "custom": "another.plugin:field"},
    {"type": "array", "items": "number", "custom": SQL_FEED},
])
def test_other_array_fields_are_not_silently_accepted(schema):
    with pytest.raises(RuntimeError, match="not a supported"):
        resolve_entity_mapping(
            Jira(schema), configuration(), [task()], "datacenter"
        )


def test_sql_feed_entity_must_be_settable():
    with pytest.raises(RuntimeError, match="cannot be set"):
        resolve_entity_mapping(
            Jira(
                {"type": "array", "items": "string", "custom": SQL_FEED},
                operations=["read"],
            ),
            configuration(),
            [task()],
            "datacenter",
        )


def test_chart_defaults_entity_to_array():
    root = Path(__file__).resolve().parents[1]
    text = (
        root / "deploy/charts/blackduck-wintermute-jira/values.yaml"
    ).read_text(encoding="utf-8")
    entity = text.rsplit("      entity:\n", 1)[1]

    assert "        value_type: array\n" in entity
    assert hierarchy_managed_fields_for_node(
        task(),
        resolve_entity_mapping(
            Jira({"type": "array", "items": "string", "custom": SQL_FEED}),
            configuration(),
            [task()],
            "datacenter",
        ),
    ) == {"customfield_14313": ["Example entity"]}
