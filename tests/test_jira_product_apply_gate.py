from __future__ import annotations

import argparse
import copy
from types import SimpleNamespace

import pytest

from wintermute.jira import product_reporting as product


BASE = "https://bd.example.invalid"
SOURCE = BASE + "/api/projects/source/versions/one"
PRODUCT = BASE + "/api/projects/product/versions/release"
GOOD = "CVE-2026-0001"
BAD = "CVE-2026-0002"


def finding(identifier, *, score_status="known", remediation_status="known"):
    evidence = {
        "vulnerability": identifier,
        "project_version_href": SOURCE,
        "occurrence_href": SOURCE + "/occurrences/" + identifier,
        "advisory_href": BASE + "/api/vulnerabilities/" + identifier,
        "origin_href": "",
        "overall_score": {
            "status": score_status,
            "value": 9.0 if score_status == "known" else None,
        },
        "remediation_status": "NEW" if remediation_status == "known" else "",
        "remediation_evidence_status": remediation_status,
        "severity": "HIGH",
        "cvss_vectors": {},
        "exploit": {
            "status": "known",
            "available": False,
            "maturity_metrics": {},
        },
    }
    return SimpleNamespace(
        vulnerability=identifier,
        project_version=SimpleNamespace(
            project="Source", version="one", version_href=SOURCE
        ),
        component="library",
        component_version="1.0",
        component_href=BASE + "/api/components/library/versions/one",
        severity="HIGH",
        attributes={"blackduck_occurrences": [evidence]},
        lineage_contexts=[
            SimpleNamespace(parent=SimpleNamespace(version_href=PRODUCT))
        ],
    )


def product_selection(entity=""):
    return [{
        "project": "Product",
        "display_name": "Product",
        "version": "release",
        "href": PRODUCT,
        "phase": "RELEASED",
        "entity": entity,
        "people": product.responsibility_metadata(""),
    }]


def settings():
    return {
        "remediation_statuses": ["NEW"],
        "exploit_minimum_score": 4.0,
        "minimum_score": 7.0,
        "exploit_maturity_field": "",
        "exploit_maturity_available_values": [],
        "exploit_maturity_unavailable_values": [],
    }


def config():
    return {
        "jira": {"project_key": "SEC"},
        "issue": {"alert_severity_by_severity": {"HIGH": "HIGH"}},
    }


def args(*, apply=True):
    return argparse.Namespace(
        apply=apply,
        dry_run=not apply,
        only_vulnerability=None,
    )


def qualified_plan(findings):
    report = {}
    rows, legacy_labels = product.project_findings(
        findings, product_selection(), args(), settings(), report
    )
    nodes = product.build_nodes(rows, config())
    return nodes, legacy_labels, report


def test_apply_publishes_only_fully_evidenced_occurrences(monkeypatch, tmp_path):
    nodes, legacy_labels, report = qualified_plan([
        finding(GOOD),
        finding(BAD, score_status="missing"),
    ])
    assert len(nodes) == 2
    assert all(node["context"]["vulnerability"] == GOOD for node in nodes)
    assert report["unresolved_product_evidence"] == [{
        "occurrence": SOURCE + "/occurrences/" + BAD,
        "reason": "overall-score-missing",
    }]

    calls = []

    def fake_publish(*arguments):
        calls.append(arguments)
        return [{"action": "created"}]

    monkeypatch.setattr(product, "publish", fake_publish)
    report["evidence_complete"] = False

    result = product.publish_qualified_nodes(
        args(), {}, nodes, tmp_path / "state.json",
        tmp_path, legacy_labels, settings(), report,
    )
    assert result == [{"action": "created"}]
    assert len(calls) == 1
    assert calls[0][2] == nodes
    assert all(
        row["vulnerability"] == GOOD
        for node in calls[0][2]
        if node["node_type"] == "story"
        for row in node["product_report"]["rows"]
    )
    assert product.publish_outcome(
        args(), unresolved=True, failures=False
    ) == ("partial", 2, False)


def test_missing_remediation_never_enters_published_task(monkeypatch, tmp_path):
    nodes, legacy_labels, report = qualified_plan([
        finding(GOOD),
        finding(BAD, remediation_status="missing"),
    ])
    assert report["unresolved_product_evidence"][0]["reason"] == (
        "remediation-missing"
    )
    assert all(
        row["vulnerability"] == GOOD
        for node in nodes
        if node["node_type"] == "story"
        for row in node["product_report"]["rows"]
    )

    seen = []
    monkeypatch.setattr(
        product, "publish",
        lambda *arguments: seen.append(copy.deepcopy(arguments[2])) or [],
    )
    product.publish_qualified_nodes(
        args(), {}, nodes, tmp_path / "state.json",
        tmp_path, legacy_labels, settings(), report,
    )
    assert seen == [nodes]


def test_unresolved_only_blocks_apply_before_publisher(monkeypatch, tmp_path):
    nodes, legacy_labels, report = qualified_plan([
        finding(BAD, score_status="missing"),
    ])
    assert nodes == []
    monkeypatch.setattr(
        product, "publish",
        lambda *arguments: pytest.fail("Publisher must not be called"),
    )

    with pytest.raises(RuntimeError, match="no fully evidenced"):
        product.publish_qualified_nodes(
            args(), {}, nodes, tmp_path / "state.json",
            tmp_path, legacy_labels, settings(), report,
        )


def test_defensive_gate_rejects_unresolved_row_even_if_manually_added(
    monkeypatch, tmp_path,
):
    nodes, legacy_labels, report = qualified_plan([finding(GOOD)])
    bad = copy.deepcopy(nodes)
    task = next(node for node in bad if node["node_type"] == "story")
    task["product_report"]["rows"][0]["evidence"][
        "remediation_evidence_status"
    ] = "missing"
    monkeypatch.setattr(
        product, "publish",
        lambda *arguments: pytest.fail("Publisher must not be called"),
    )

    with pytest.raises(RuntimeError, match="unresolved occurrence evidence"):
        product.publish_qualified_nodes(
            args(), {}, bad, tmp_path / "state.json",
            tmp_path, legacy_labels, settings(), report,
        )


def test_missing_entity_does_not_block_verified_task(monkeypatch, tmp_path):
    nodes, legacy_labels, report = qualified_plan([finding(GOOD)])
    task = next(node for node in nodes if node["node_type"] == "story")
    assert task["context"]["entity"] == ""
    monkeypatch.setattr(product, "publish", lambda *arguments: [])
    assert product.publish_qualified_nodes(
        args(), {}, nodes, tmp_path / "state.json",
        tmp_path, legacy_labels, settings(), report,
    ) == []


def test_incomplete_dry_run_remains_nonzero_and_not_promoted():
    assert product.publish_outcome(
        args(apply=False), unresolved=True, failures=False
    ) == ("planned-incomplete", 2, False)


def test_complete_apply_remains_successful():
    assert product.publish_outcome(
        args(), unresolved=False, failures=False
    ) == ("succeeded", 0, True)
