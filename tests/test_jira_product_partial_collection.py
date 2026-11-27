from __future__ import annotations

import argparse
from types import SimpleNamespace

import pytest

from wintermute.jira import product_reporting as product


PRODUCT_HREF = "https://bd.example.invalid/api/projects/product/versions/release"
SOURCE_HREF = "https://bd.example.invalid/api/projects/child/versions/one"
OTHER_HREF = "https://bd.example.invalid/api/projects/child/versions/two"


def finding(href):
    occurrence = {
        "vulnerability": "CVE-2025-14087",
        "project_version_href": href,
        "occurrence_href": href + "/occurrences/CVE-2025-14087",
        "advisory_href": "https://bd.example.invalid/api/vulnerabilities/CVE-2025-14087",
        "origin_href": "",
        "overall_score": {"status": "known", "value": 9.0},
        "remediation_status": "NEW",
        "remediation_evidence_status": "known",
        "severity": "HIGH",
        "cvss_vectors": {},
        "exploit": {
            "status": "known",
            "available": False,
            "maturity_metrics": {},
        },
    }
    return SimpleNamespace(
        vulnerability="CVE-2025-14087",
        project_version=SimpleNamespace(
            project="Child",
            version="1",
            version_href=href,
        ),
        component="verified library",
        component_version="1.0",
        component_href="https://bd.example.invalid/api/components/library/versions/one",
        severity="HIGH",
        attributes={"blackduck_occurrences": [occurrence]},
        lineage_contexts=[
            SimpleNamespace(parent=SimpleNamespace(version_href=PRODUCT_HREF))
        ],
    )


def targets(*hrefs):
    return [
        SimpleNamespace(project_version=SimpleNamespace(version_href=href))
        for href in hrefs
    ]


def product_selection():
    return [{
        "project": "Example Product",
        "display_name": "Example Product",
        "version": "release",
        "href": PRODUCT_HREF,
        "phase": "RELEASED",
        "entity": "",
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


def test_unrelated_component_failure_keeps_verified_occurrence():
    verified = finding(SOURCE_HREF)
    collection = SimpleNamespace(
        findings=(verified,),
        failures=(SimpleNamespace(
            project_version_href=SOURCE_HREF,
            stage="component-details",
        ),),
    )
    report = {}

    selected = product.select_collected_findings(
        collection, targets(SOURCE_HREF), report
    )
    rows, _ = product.project_findings(
        selected,
        product_selection(),
        argparse.Namespace(only_vulnerability="CVE-2025-14087"),
        settings(),
        {},
    )

    assert selected == [verified]
    assert len(rows) == 1
    assert rows[0]["source_href"] == SOURCE_HREF
    assert rows[0]["vulnerability"] == "CVE-2025-14087"
    assert report["partially_collected_source_versions"] == [SOURCE_HREF]
    assert report["excluded_failed_source_versions"] == []


def test_whole_version_failure_excludes_only_that_version():
    excluded = finding(SOURCE_HREF)
    retained = finding(OTHER_HREF)
    collection = SimpleNamespace(
        findings=(excluded, retained),
        failures=(SimpleNamespace(
            project_version_href=SOURCE_HREF,
            stage="load-vulnerable-components",
        ),),
    )
    report = {}

    selected = product.select_collected_findings(
        collection, targets(SOURCE_HREF, OTHER_HREF), report
    )

    assert selected == [retained]
    assert report["excluded_failed_source_versions"] == [SOURCE_HREF]
    assert report["partially_collected_source_versions"] == []


def test_whole_version_failure_takes_precedence_over_component_failure():
    collection = SimpleNamespace(
        findings=(finding(SOURCE_HREF),),
        failures=(
            SimpleNamespace(
                project_version_href=SOURCE_HREF,
                stage="component-details",
            ),
            SimpleNamespace(
                project_version_href=SOURCE_HREF,
                stage="load-vulnerable-components",
            ),
        ),
    )
    report = {}

    assert product.select_collected_findings(
        collection, targets(SOURCE_HREF), report
    ) == []
    assert report["excluded_failed_source_versions"] == [SOURCE_HREF]
    assert report["partially_collected_source_versions"] == []


def test_failure_with_unknown_source_is_not_silently_ignored():
    collection = SimpleNamespace(
        findings=(),
        failures=(SimpleNamespace(
            project_version_href="",
            stage="component-details",
        ),),
    )

    with pytest.raises(RuntimeError, match="valid project-version URLs"):
        product.select_collected_findings(
            collection, targets(SOURCE_HREF), {}
        )
