from __future__ import annotations

import argparse
import copy
import json

import pytest

from wintermute.jira import findings_to_jira as publisher
from wintermute.jira import product_reporting as product
from wintermute.jira.lookup_identity import own_lookup_labels, search_by_labels


BASE = "https://bd.example.invalid"
PROJECT = BASE + "/api/projects/product"
VERSION = PROJECT + "/versions/release"
COMPONENT = BASE + "/api/components/library/versions/one"
EPIC_LABEL = "bd_cve_" + "a" * 24
TASK_LABEL = "bd_cve_product_" + "b" * 24


def config():
    return publisher.deep_merge(copy.deepcopy(publisher.DEFAULT_CONFIG), {
        "jira": {"project_key": "SEC"},
        "hierarchy": {"summary_templates": {"epic": "", "story": ""}},
        "product_reporting": {
            "enabled": True,
            "policy_custom_field": "Security Policy Active",
            "entity_custom_field": "Business Entity",
            "added_project_depth": 1,
        },
    })


def settings():
    return product.settings_from(config())


def selected_product(version="1.1.0"):
    return {
        "project": "Example Product",
        "display_name": "fieldgate",
        "version": version,
        "href": PROJECT + "/versions/" + version,
        "phase": "RELEASED",
        "entity": "Example entity",
        "people": product.responsibility_metadata(""),
    }


def evidence(source_href, status="NEW", component=COMPONENT, score=9.8, exploit=False):
    occurrence = {
        "vulnerability": "CVE-2026-12345",
        "project_version_href": source_href,
        "occurrence_href": source_href + "/occurrences/" + component.rsplit("/", 1)[-1]
            + "/CVE-2026-12345",
        "advisory_href": BASE + "/api/vulnerabilities/CVE-2026-12345",
        "origin_href": source_href + "/origins/test",
        "overall_score": {"status": "known", "value": score},
        "remediation_status": status,
        "remediation_evidence_status": "known" if status else "missing",
        "severity": "CRITICAL",
        "cvss_vectors": {},
        "exploit": {
            "status": "known" if type(exploit) is bool else "not-explicit",
            "available": exploit if type(exploit) is bool else None,
            "maturity_metrics": {},
        },
    }
    return {
        "vulnerability": occurrence["vulnerability"],
        "score": score,
        "severity": "CRITICAL",
        "exploit_available": exploit,
        "exploit_source": "explicit availability field",
        "remediation_status": status,
        "cvss_vector": "",
        "vulnerability_url": occurrence["advisory_href"],
        "component": "library",
        "component_version": "2.0",
        "component_href": component,
        "component_version_href": component,
        "source_project": "Source",
        "source_version": "1",
        "source_href": source_href,
        "evidence": occurrence,
    }


def row(version="1.1.0", component=COMPONENT):
    selected = selected_product(version)
    return {
        **evidence(selected["href"], component=component),
        "product": selected["project"],
        "product_display_name": selected["display_name"],
        "product_version": version,
        "product_href": selected["href"],
        "phase": selected["phase"],
        "entity": selected["entity"],
        "people": selected["people"],
    }


@pytest.mark.parametrize("score,exploit,expected", [
    (7.0, False, True),
    (6.99, False, False),
    (6.99, True, True),
    (4.0, True, True),
    (4.0, False, False),
    (3.99, True, False),
    (None, True, False),
    (float("nan"), True, False),
    (float("inf"), True, False),
    (5.0, "true", False),
])
def test_score_rules(score, exploit, expected):
    assert product.qualifies(score, exploit, settings()) is expected














def test_responsibility_metadata():
    assert product.responsibility_metadata("")["status"] == "missing"
    assert product.responsibility_metadata("{invalid")["status"] == "invalid-json"
    assert product.responsibility_metadata(
        '{"info":{"owner":"a","owner":"b"}}'
    )["status"] == "invalid-json"
    parsed = product.responsibility_metadata(
        '{"info":{"owner":"owner@example.invalid"}}'
    )
    assert parsed["status"] == "incomplete"
    assert "securitymanager" in parsed["missing_roles"]


def test_own_labels_exclude_inherited_epic():
    assert own_lookup_labels([EPIC_LABEL, TASK_LABEL]) == {TASK_LABEL}
    assert own_lookup_labels([EPIC_LABEL]) == {EPIC_LABEL}


class SearchClient:
    def __init__(self, deployment):
        self.deployment = deployment
        self.calls = []

    def request_json(self, method, path, query=None, **kwargs):
        assert method == "GET"
        self.calls.append((path, dict(query)))
        second = (
            "nextPageToken" in query
            if self.deployment == "cloud"
            else query["startAt"] == 1
        )
        issue = {
            "key": "SEC-1" if second else "SEC-2",
            "fields": {
                "labels": [EPIC_LABEL] if second else [EPIC_LABEL, TASK_LABEL],
                "summary": "Example",
                "status": {"name": "Open"},
            },
        }
        if self.deployment == "cloud":
            assert path == "/rest/api/3/search/jql"
            return {
                "issues": [issue],
                "isLast": second,
                **({} if second else {"nextPageToken": "next"}),
            }
        assert path == "/rest/api/2/search"
        return {"issues": [issue], "startAt": int(second), "total": 2}


@pytest.mark.parametrize("deployment", ["cloud", "datacenter"])
def test_identity_search_across_pages(deployment):
    client = SearchClient(deployment)
    found = search_by_labels(client, deployment, "SEC", [EPIC_LABEL, TASK_LABEL])
    assert found[EPIC_LABEL]["key"] == "SEC-1"
    assert found[TASK_LABEL]["key"] == "SEC-2"


def test_genuine_duplicate_epics_are_rejected():
    class DuplicateClient:
        def request_json(self, *args, **kwargs):
            return {
                "isLast": True,
                "issues": [{
                    "key": key,
                    "fields": {
                        "labels": [EPIC_LABEL],
                        "summary": key,
                        "status": {"name": "Open"},
                    },
                } for key in ("SEC-1", "SEC-2")],
            }

    with pytest.raises(RuntimeError, match="Multiple Jira issues"):
        search_by_labels(DuplicateClient(), "cloud", "SEC", [EPIC_LABEL])


def test_release_selection_four_releases_two_development_versions():
    selected, report = select_inventory(
        ["RELEASED"] * 4 + ["DEVELOPMENT"] * 2
    )
    assert [item["version"] for item in selected] == [
        "1.1.0", "1.1.1", "1.1.2", "1.1.3",
    ]
    assert len(report["excluded_versions"]) == 2


def test_product_titles_and_component_aggregation():
    a = row()
    b = row(component=BASE + "/api/components/another/versions/one")
    b["component"] = "another-library"
    nodes = product.build_nodes([a, b, row("1.1.1")], config())
    assert len(nodes) == 3
    assert nodes[0]["summary"] == "[Black Duck] CVE-2026-12345"
    task = next(
        node for node in nodes
        if node["context"].get("affected_version") == "1.1.0"
    )
    assert task["summary"] == "Black Duck: BLOCKER Alert - fieldgate - version 1.1.0"
    assert task["stats"]["component_count"] == 2
    assert "another-library" in task["description"]
    assert "another-library" not in task["summary"]


def test_second_publish_reuses_epic_and_tasks(tmp_path, monkeypatch):
    jira = FakeJira()
    nodes = product.build_nodes([row(), row("1.1.1")], config())
    first = publish_with_fake(monkeypatch, jira, nodes, tmp_path, "first")
    before = copy.deepcopy(jira.issues)
    second = publish_with_fake(monkeypatch, jira, nodes, tmp_path, "second")

    assert jira.creations == 3
    assert all(item["action"] == "created" for item in first)
    assert all(item["action"] == "skip_existing_jira" for item in second)
    assert jira.issues == before
    assert jira.updates == []
    epic_key = next(
        issue["key"] for issue in jira.issues
        if issue["fields"]["issuetype"]["name"] == "Epic"
    )
    assert all(
        issue["fields"]["parent"]["key"] == epic_key
        for issue in jira.issues
        if issue["fields"]["issuetype"]["name"] == "Task"
    )
    saved = json.loads((tmp_path / "state.json").read_text())
    assert len(saved["issues_by_external_id"]) == 3
    assert saved["product_pending_creates"] == {}


def test_create_budget_caps_writes_and_next_run_resumes(tmp_path, monkeypatch):
    jira = FakeJira()
    nodes = product.build_nodes([row(), row("1.1.1")], config())

    first = publish_with_fake(
        monkeypatch, jira, nodes, tmp_path, "first", max_create=1
    )
    assert jira.creations == 1
    assert [item["action"] for item in first] == [
        "created", "skip_max_create_reached", "skip_max_create_reached",
    ]
    assert jira.issues[0]["fields"]["issuetype"]["name"] == "Epic"

    second = publish_with_fake(
        monkeypatch, jira, nodes, tmp_path, "second", max_create=2
    )
    assert jira.creations == 3
    assert sum(item["action"] == "created" for item in second) == 2
    assert second[0]["action"] == "skip_existing_jira"
    assert all(
        issue["fields"]["parent"]["key"] == jira.issues[0]["key"]
        for issue in jira.issues[1:]
    )


def test_product_mode_disabled_without_configuration():
    assert product.settings_from({}) is None

# Customer occurrence-based reporting contract

from types import SimpleNamespace
from wintermute.jira import product_publishing
from wintermute.jira.entity_mapping import resolve_entity_mapping


def select_inventory(phases, policy="True", entity="Example entity"):
    class Client:
        def get(self, path):
            assert path == PROJECT
            return {"name": "Example Product", "description": ""}

        def paged_get(self, path):
            assert path == PROJECT + "/custom-fields"
            return [
                {"name": "Security Policy Active", "value": policy},
                {"name": "Business Entity", "value": entity},
            ]

    inventory = SimpleNamespace(items=[
        SimpleNamespace(project_version=SimpleNamespace(
            project="Example Product",
            version=f"1.1.{index}",
            project_href=PROJECT,
            version_href=PROJECT + f"/versions/v{index}",
            phase=phase,
        ))
        for index, phase in enumerate(phases)
    ])
    args = argparse.Namespace(
        exclude_parent_project=[], only_parent_project=None,
        only_parent_version=None, project_name_contains=None,
    )
    report = {
        "excluded_products": [], "excluded_versions": [],
        "responsibility_metadata": [],
    }
    return product.select_products(Client(), inventory, args, settings(), report), report


@pytest.mark.parametrize("policy", ["True", "true", "TRUE", " True ", True])
def test_security_policy_true_values_are_accepted(policy):
    selected, _ = select_inventory(["RELEASED"], policy=policy)
    assert len(selected) == 1


@pytest.mark.parametrize("policy", ["False", "Active", "", False])
def test_security_policy_other_values_are_excluded(policy):
    selected, report = select_inventory(["RELEASED"], policy=policy)
    assert selected == []
    assert report["excluded_products"][0]["reason"] == "policy-not-active"


def test_empty_entity_is_excluded():
    selected, report = select_inventory(["RELEASED"], entity=" ")
    assert selected == []
    assert report["excluded_products"][0]["reason"] == "entity-missing"


def test_lts_phase_alias_is_accepted():
    selected, _ = select_inventory(["LTS", "LONG_TERM_SUPPORT"])
    assert len(selected) == 2
    assert all(item["phase"] == "LTS" for item in selected)


def test_customer_defaults_are_preserved():
    actual = settings()
    assert actual["remediation_statuses"] == ["NEW"]
    assert set(actual["phases"]) == {"RELEASED", "LTS"}
    assert actual["minimum_score"] == 7.0
    assert actual["exploit_minimum_score"] == 4.0
    assert actual["added_project_depth"] == 1


def finding_from(item, selected):
    return SimpleNamespace(
        vulnerability=item["vulnerability"],
        project_version=SimpleNamespace(
            project=item["source_project"],
            version=item["source_version"],
            version_href=item["source_href"],
        ),
        component=item["component"],
        component_version=item["component_version"],
        component_href=item["component_href"],
        severity=item["severity"],
        attributes={"blackduck_occurrences": [copy.deepcopy(item["evidence"])]},
        lineage_contexts=[
            SimpleNamespace(parent=SimpleNamespace(version_href=selected["href"]))
        ],
    )


def project_occurrences(items):
    selected = selected_product()
    report = {}
    findings = [finding_from(item, selected) for item in items]
    rows, _ = product.project_findings(
        findings, [selected], argparse.Namespace(only_vulnerability=None),
        settings(), report,
    )
    return rows, report


@pytest.mark.parametrize("parent_status", ["IGNORED", "PATCHED"])
def test_qualifying_child_is_included_independently_of_parent_status(parent_status):
    selected = selected_product()
    child_href = BASE + "/api/projects/child/versions/one"
    rows, report = project_occurrences([
        evidence(selected["href"], status=parent_status),
        evidence(child_href, status="NEW"),
    ])
    assert len(rows) == 1
    assert rows[0]["source_href"] == child_href
    assert rows[0]["product_href"] == selected["href"]
    assert rows[0]["remediation_status"] == "NEW"
    assert report["unresolved_product_evidence"] == []


@pytest.mark.parametrize("child_status", ["IGNORED", "PATCHED"])
def test_excluded_child_does_not_suppress_new_direct_occurrence(child_status):
    selected = selected_product()
    rows, report = project_occurrences([
        evidence(selected["href"], status="NEW"),
        evidence(BASE + "/api/projects/child/versions/one", status=child_status),
    ])
    assert len(rows) == 1
    assert rows[0]["source_href"] == selected["href"]
    assert report["unresolved_product_evidence"] == []


def test_child_requires_lineage_not_a_matching_direct_occurrence():
    child_href = BASE + "/api/projects/child/versions/one"
    rows, report = project_occurrences([evidence(child_href)])
    assert len(rows) == 1
    assert rows[0]["source_href"] == child_href
    assert report["unresolved_product_evidence"] == []


def test_finding_without_selected_product_lineage_is_not_promoted():
    selected = selected_product()
    finding = finding_from(evidence(VERSION), selected)
    finding.lineage_contexts = []
    rows, _ = product.project_findings(
        [finding], [selected], argparse.Namespace(only_vulnerability=None),
        settings(), {},
    )
    assert rows == []


def test_missing_status_is_not_borrowed_from_another_occurrence():
    selected = selected_product()
    child_href = BASE + "/api/projects/child/versions/one"
    rows, report = project_occurrences([
        evidence(selected["href"], status=""),
        evidence(child_href, status="NEW"),
    ])
    assert len(rows) == 1
    assert rows[0]["source_href"] == child_href
    assert len(report["unresolved_product_evidence"]) == 1
    assert report["unresolved_product_evidence"][0]["reason"] == "remediation-missing"


def test_component_versions_keep_separate_occurrence_decisions():
    selected = selected_product()
    other = BASE + "/api/components/library/versions/two"
    rows, report = project_occurrences([
        evidence(selected["href"], status="IGNORED"),
        evidence(selected["href"], component=other, status="NEW"),
    ])
    assert len(rows) == 1
    assert rows[0]["component_href"] == other
    assert report["unresolved_product_evidence"] == []


def test_conflicting_same_occurrence_evidence_is_rejected():
    first = evidence(selected_product()["href"], score=9.0)
    second = copy.deepcopy(first)
    second["evidence"]["overall_score"]["value"] = 8.0
    with pytest.raises(RuntimeError, match="Conflicting"):
        project_occurrences([first, second])


def test_unknown_exploit_at_lower_score_remains_unresolved():
    rows, report = project_occurrences([
        evidence(selected_product()["href"], score=5.0, exploit=None)
    ])
    assert rows == []
    assert report["unresolved_product_evidence"][0]["reason"] == (
        "exploit availability not provided"
    )


@pytest.mark.parametrize("status", [
    "UNDER_INVESTIGATION", "NEEDS_REVIEW", "KNOWN_AFFECTED",
    "REMEDIATION_REQUIRED", "IGNORED", "PATCHED",
])
def test_non_new_statuses_are_excluded_by_default(status):
    rows, report = project_occurrences([
        evidence(selected_product()["href"], status=status)
    ])
    assert rows == []
    assert report["unresolved_product_evidence"] == []
    assert report["excluded_occurrence_counts"]["remediation-not-selected"] == 1


class FakeJira:
    base_url = "https://jira.example.invalid"
    retries = 2
    api_version = "2"

    def __init__(self, deployment="cloud", entity_count=1):
        self.deployment = deployment
        self.issues = []
        self.creations = 0
        self.updates = []
        self.calls = []
        self.entity_fields = [{
            "fieldId": f"customfield_{12345 + index}",
            "name": "Entity",
            "schema": {
                "type": "string",
                "custom": "com.atlassian.jira.plugin.system.customfieldtypes:textfield",
            },
            "operations": ["set"],
        } for index in range(entity_count)]

    def enabled(self):
        return True

    def request_json(self, method, path, query=None, **kwargs):
        assert method == "GET", "Unexpected mutation through metadata/search"
        self.calls.append(path)
        if path == "/rest/api/2/serverInfo":
            return {"deploymentType": "Cloud" if self.deployment == "cloud" else "Data Center"}

        version = "3" if self.deployment == "cloud" else "2"
        root = f"/rest/api/{version}/issue/createmeta/SEC/issuetypes"
        if path == root:
            key = "issueTypes" if self.deployment == "cloud" else "values"
            return {key: [{"id": "10001", "name": "Task"}],
                    "startAt": 0, "total": 1, "isLast": True}
        if path == root + "/10001":
            key = "fields" if self.deployment == "cloud" else "values"
            return {key: copy.deepcopy(self.entity_fields), "startAt": 0,
                    "total": len(self.entity_fields), "isLast": True}
        if path == "/rest/api/3/search/jql":
            return {"issues": copy.deepcopy(self.issues), "isLast": True}
        if path.startswith(("/rest/api/2/issue/SEC-", "/rest/api/3/issue/SEC-")):
            key = path.rsplit("/", 1)[-1]
            return copy.deepcopy(next(issue for issue in self.issues if issue["key"] == key))
        raise AssertionError(f"Unexpected Jira endpoint: {path}")

    def create_issue(self, payload):
        assert self.retries == 0
        assert self.api_version == "3"
        self.creations += 1
        key = f"SEC-{self.creations}"
        fields = copy.deepcopy(payload["fields"])
        fields["status"] = {"name": "Open"}
        self.issues.append({"key": key, "fields": fields})
        return {"key": key}

    def update_issue_fields(self, key, fields):
        assert self.retries == 0
        self.updates.append((key, copy.deepcopy(fields)))
        issue = next(issue for issue in self.issues if issue["key"] == key)
        issue["fields"].update(copy.deepcopy(fields))
        return {}


def publish_with_fake(monkeypatch, jira, nodes, root, run, max_create=10,
                      dry_run=False, sync=False):
    monkeypatch.setattr(publisher, "build_jira_client", lambda *args, **kwargs: jira)
    options = argparse.Namespace(
        apply=not dry_run, dry_run=dry_run, max_create=max_create,
        timeout=30, retries=2, retry_delay=1, debug=False,
        description_format="wiki", sync_existing_fields=sync,
    )
    return product_publishing.publish(
        options, config(), nodes, root / "state.json", root / run, [], settings()
    )


@pytest.mark.parametrize("deployment", ["cloud", "datacenter"])
def test_entity_mapping_uses_project_metadata_without_mutating_config(deployment):
    jira = FakeJira(deployment)
    original = config()
    before = copy.deepcopy(original)
    nodes = product.build_nodes([row()], original)
    prepared = resolve_entity_mapping(jira, original, nodes, deployment)
    assert prepared["hierarchy"]["field_mappings"]["entity"]["field_id"] == "customfield_12345"
    assert original == before


@pytest.mark.parametrize("count", [0, 2])
def test_missing_or_ambiguous_entity_blocks_all_creation(count, tmp_path, monkeypatch):
    jira = FakeJira(entity_count=count)
    with pytest.raises(RuntimeError, match="expected one available Entity field"):
        publish_with_fake(
            monkeypatch, jira, product.build_nodes([row()], config()), tmp_path, "run"
        )
    assert jira.creations == 0
    assert jira.updates == []


@pytest.mark.parametrize("format", ["adf", "wiki"])
def test_product_payload_has_structured_content_and_preserves_links(format):
    data = row()
    prepared = config()
    prepared["hierarchy"]["field_mappings"]["entity"]["field_id"] = "customfield_12345"
    task = next(
        node for node in product.build_nodes([data], prepared)
        if node["node_type"] == "story"
    )
    fields = publisher.build_hierarchy_issue_payload(task, prepared, format)["fields"]
    assert fields["customfield_12345"] == "Example entity"
    description = fields["description"]
    serialized = json.dumps(description) if isinstance(description, dict) else description
    assert "Evidence interpretation" not in serialized
    assert "Example entity" not in serialized
    assert "1. Occurrence" not in serialized
    for url in (
        data["product_href"],
        data["evidence"]["occurrence_href"],
        data["evidence"]["advisory_href"],
        data["evidence"]["origin_href"],
    ):
        assert url in serialized
    if format == "adf":
        assert description["type"] == "doc"
        types = [item["type"] for item in description["content"]]
        assert "heading" in types
        assert types.count("table") == 2
        assert "bulletList" in types
    else:
        assert "h2. Affected components" in description
        assert "||" in description


def test_dry_run_creation_performs_no_writes(tmp_path, monkeypatch):
    jira = FakeJira()
    results = publish_with_fake(
        monkeypatch, jira, product.build_nodes([row()], config()),
        tmp_path, "dry", dry_run=True,
    )
    assert [item["action"] for item in results] == ["would_create", "would_create"]
    assert jira.creations == 0
    assert jira.updates == []
    assert not (tmp_path / "state.json").exists()


def test_description_sync_is_opt_in_and_dry_run_does_not_write(tmp_path, monkeypatch):
    jira = FakeJira()
    nodes = product.build_nodes([row()], config())
    publish_with_fake(monkeypatch, jira, nodes, tmp_path, "create")
    task = next(issue for issue in jira.issues if issue["fields"]["issuetype"]["name"] == "Task")
    task["fields"]["description"] = {"type": "doc", "version": 1, "content": []}

    publish_with_fake(monkeypatch, jira, nodes, tmp_path, "no-sync")
    assert jira.updates == []
    before = copy.deepcopy(jira.issues)
    state_before = (tmp_path / "state.json").read_bytes()

    planned = publish_with_fake(
        monkeypatch, jira, nodes, tmp_path, "dry-sync", dry_run=True, sync=True
    )
    assert any(item["action"] == "would_update_existing_fields" for item in planned)
    assert jira.issues == before
    assert jira.updates == []
    assert (tmp_path / "state.json").read_bytes() == state_before

    publish_with_fake(monkeypatch, jira, nodes, tmp_path, "apply-sync", sync=True)
    assert jira.creations == 2
    assert len(jira.updates) == 1
    assert set(jira.updates[0][1]) == {"description", "customfield_12345"}
    assert any(
        item["type"] == "table"
        for item in task["fields"]["description"]["content"]
    )
