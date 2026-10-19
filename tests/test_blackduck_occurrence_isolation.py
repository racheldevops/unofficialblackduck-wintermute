from __future__ import annotations

import copy
from typing import Any

import pytest

from wintermute.blackduck.collector import collect_target
from wintermute.blackduck.criteria import jira_parent_rollup_criteria
from wintermute.blackduck.models import CollectionTarget, ProjectVersionRef
from wintermute.blackduck.occurrences import matched_occurrence_advisory


BASE = "https://bd.example"
VERSION = BASE + "/api/projects/product/versions/release"
COMPONENT = VERSION + "/components/library/versions/one/origins/source"
GOOD = "CVE-2026-0001"
BAD = "CVE-2026-0002"
RELATED_CVE = "CVE-2026-49844"
RELATED_BDSA = "BDSA-2026-22385"
CVE_URL = f"{BASE}/api/vulnerabilities/{RELATED_CVE}"
BDSA_URL = f"{BASE}/api/vulnerabilities/{RELATED_BDSA}"


def occurrence(identifier: str) -> dict[str, Any]:
    return {
        "componentName": "Same library",
        "componentVersionName": "1.0",
        "vulnerability": {
            "vulnerabilityId": identifier,
            "remediationStatus": "NEW",
        },
        "_meta": {
            "href": (
                f"{COMPONENT}/vulnerabilities/"
                f"{identifier}/remediation"
            ),
            "links": [{
                "rel": "vulnerabilities",
                "href": f"{BASE}/api/advisories/{identifier}",
            }],
        },
    }


class Client:
    base_url = BASE
    product_occurrence_evidence = True

    def __init__(self) -> None:
        self.advisory_requests: list[str] = []

    def paged_get(self, href: str) -> list[dict[str, Any]]:
        if href == VERSION + "/vulnerable-bom-components":
            return [occurrence(BAD), occurrence(GOOD)]

        self.advisory_requests.append(href)
        if href == f"{BASE}/api/advisories/{BAD}":
            return [{
                "vulnerabilityId": "CVE-2026-9999",
                "overallScore": 9.0,
            }]
        if href == f"{BASE}/api/advisories/{GOOD}":
            return [{
                "vulnerabilityId": GOOD,
                "overallScore": 9.0,
                "severity": "HIGH",
                "_meta": {
                    "href": f"{BASE}/api/vulnerabilities/{GOOD}",
                },
            }]
        raise AssertionError(f"Unexpected read: {href}")


class RelatedClient(Client):
    def __init__(self) -> None:
        super().__init__()
        self.direct_requests: list[str] = []
        self.cve = {
            "source": "NVD",
            "name": RELATED_CVE,
            "overallScore": 9.1,
            "severity": "HIGH",
            "_meta": {
                "href": CVE_URL,
                "links": [{
                    "rel": "related-bdsa-vulnerability",
                    "href": BDSA_URL,
                }],
            },
        }
        self.bdsa = {
            "source": "BDSA",
            "name": RELATED_BDSA,
            "overallScore": 4.2,
            "severity": "MEDIUM",
            "_meta": {
                "href": BDSA_URL,
                "links": [{
                    "rel": "related-nvd-vulnerability",
                    "href": CVE_URL,
                }],
            },
        }
        self.collection_candidates: list[dict[str, Any]] = [
            {
                "name": RELATED_BDSA,
                "overallScore": 4.2,
                "_meta": {"href": BDSA_URL},
            }
        ]

    def paged_get(self, href: str) -> list[dict[str, Any]]:
        if href == VERSION + "/vulnerable-bom-components":
            return [occurrence(RELATED_CVE), occurrence(GOOD)]
        if href == f"{BASE}/api/advisories/{RELATED_CVE}":
            self.advisory_requests.append(href)
            return copy.deepcopy(self.collection_candidates)
        return super().paged_get(href)

    def get(self, href: str) -> dict[str, Any]:
        self.direct_requests.append(href)
        if href == CVE_URL:
            return copy.deepcopy(self.cve)
        if href == BDSA_URL:
            return copy.deepcopy(self.bdsa)
        raise AssertionError(f"Unexpected direct read: {href}")


def target() -> CollectionTarget:
    return CollectionTarget(
        project_version=ProjectVersionRef(
            instance_url=BASE,
            project="Product",
            version="release",
            project_href=BASE + "/api/projects/product",
            version_href=VERSION,
        )
    )


def test_bad_advisory_does_not_discard_good_occurrence_on_same_component() -> None:
    client = Client()
    result = collect_target(
        client, target(), jira_parent_rollup_criteria()
    )

    assert result.status == "partial"
    assert [finding.vulnerability for finding in result.findings] == [GOOD]
    assert result.findings[0].component == "Same library"
    assert result.findings[0].attributes["blackduck_occurrences"][0][
        "remediation_evidence_status"
    ] == "known"
    assert len(result.failures) == 1
    assert result.failures[0].stage == "component-details"
    assert f"no exact match for {BAD}" in result.failures[0].error
    assert client.advisory_requests == [
        f"{BASE}/api/advisories/{BAD}",
        f"{BASE}/api/advisories/{GOOD}",
    ]


def test_scoped_collection_skips_unrelated_bad_advisory() -> None:
    client = Client()
    result = collect_target(
        client,
        target(),
        jira_parent_rollup_criteria(),
        vulnerability_id=GOOD,
    )

    assert result.status == "ok"
    assert [finding.vulnerability for finding in result.findings] == [GOOD]
    assert result.failures == ()
    assert client.advisory_requests == [f"{BASE}/api/advisories/{GOOD}"]


def test_reciprocal_links_use_direct_cve_not_bdsa_score() -> None:
    client = RelatedClient()
    result = collect_target(client, target(), jira_parent_rollup_criteria())

    assert result.status == "ok"
    assert result.failures == ()
    assert [item.vulnerability for item in result.findings] == [
        RELATED_CVE, GOOD
    ]
    cve = result.findings[0]
    assert cve.score == 9.1
    assert cve.severity == "HIGH"
    evidence = cve.attributes["blackduck_occurrences"][0]
    assert evidence["vulnerability"] == RELATED_CVE
    assert evidence["advisory_href"] == CVE_URL
    assert evidence["advisory_match_method"] == "reciprocal-vulnerability-links"
    assert evidence["verified_related_bdsa_href"] == BDSA_URL
    assert evidence["overall_score"]["value"] == 9.1
    assert evidence["remediation_evidence_status"] == "known"
    assert client.direct_requests == [CVE_URL, BDSA_URL]


def test_exact_match_never_reads_fallback_resources() -> None:
    client = RelatedClient()
    client.collection_candidates = [{
        "name": RELATED_CVE,
        "overallScore": 8.5,
        "severity": "HIGH",
        "_meta": {"href": CVE_URL},
    }]

    result = collect_target(client, target(), jira_parent_rollup_criteria())

    assert result.status == "ok"
    assert result.findings[0].score == 8.5
    assert result.findings[0].attributes["blackduck_occurrences"][0][
        "advisory_match_method"
    ] == "exact-advisory-id"
    assert client.direct_requests == []


@pytest.mark.parametrize(
    "change",
    [
        "missing-reverse-link",
        "wrong-cve-name",
        "wrong-bdsa-name",
        "wrong-cve-source",
        "wrong-cve-self",
        "foreign-forward-link",
        "foreign-reverse-link",
        "query-forward-link",
        "extra-candidate",
    ],
)
def test_unverified_relationship_keeps_failure_and_good_sibling(
    change: str,
) -> None:
    client = RelatedClient()
    if change == "missing-reverse-link":
        client.bdsa["_meta"]["links"] = []
    elif change == "wrong-cve-name":
        client.cve["name"] = "CVE-2026-9999"
    elif change == "wrong-bdsa-name":
        client.bdsa["name"] = "BDSA-2026-99999"
    elif change == "wrong-cve-source":
        client.cve["source"] = "BDSA"
    elif change == "wrong-cve-self":
        client.cve["_meta"]["href"] = f"{BASE}/api/vulnerabilities/other"
    elif change == "foreign-forward-link":
        client.cve["_meta"]["links"][0]["href"] = (
            f"https://foreign.example/api/vulnerabilities/{RELATED_BDSA}"
        )
    elif change == "foreign-reverse-link":
        client.bdsa["_meta"]["links"][0]["href"] = (
            f"https://foreign.example/api/vulnerabilities/{RELATED_CVE}"
        )
    elif change == "query-forward-link":
        client.cve["_meta"]["links"][0]["href"] = BDSA_URL + "?other=1"
    elif change == "extra-candidate":
        client.collection_candidates.append({
            "name": "BDSA-2026-99999",
            "overallScore": 9.9,
        })

    result = collect_target(client, target(), jira_parent_rollup_criteria())

    assert result.status == "partial"
    assert [finding.vulnerability for finding in result.findings] == [GOOD]
    assert len(result.failures) == 1
    assert result.failures[0].stage == "component-details"
    assert f"no exact match for {RELATED_CVE}" in result.failures[0].error
    if change == "extra-candidate":
        assert client.direct_requests == []


def test_fallback_never_borrows_bdsa_score_when_cve_score_missing() -> None:
    client = RelatedClient()
    client.cve.pop("overallScore")

    matched = matched_occurrence_advisory(
        client, occurrence(RELATED_CVE), VERSION
    )
    assert matched is not None
    advisory, evidence = matched
    assert advisory["name"] == RELATED_CVE
    assert "overallScore" not in advisory
    assert evidence["overall_score"] == {
        "status": "missing",
        "field": "overallScore",
        "value": None,
    }
    assert evidence["verified_related_bdsa_href"] == BDSA_URL

    result = collect_target(client, target(), jira_parent_rollup_criteria())
    assert result.status == "ok"
    assert result.failures == ()
    assert [finding.vulnerability for finding in result.findings] == [GOOD]
