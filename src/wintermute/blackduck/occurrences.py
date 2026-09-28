from __future__ import annotations

import copy
import math
from typing import Any
from urllib.parse import unquote, urlsplit

from wintermute.blackduck.resources import canonical_href, get_link, get_self_href


IDENTIFIER_FIELDS = (
    "vulnerabilityId",
    "vulnerabilityName",
    "vulnerabilityExternalId",
    "name",
)
EXPLICIT_EXPLOIT_FIELDS = (
    "exploitAvailable",
    "exploit_available",
    "hasExploit",
)


def direct_identifier(value: dict[str, Any]) -> str:
    for field in IDENTIFIER_FIELDS:
        candidate = value.get(field)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return ""


def same_instance_url(client: Any, value: str) -> str:
    if not isinstance(value, str) or not value:
        raise RuntimeError("Black Duck evidence URL is missing")
    base = urlsplit(client.base_url)
    if value.startswith("/api/"):
        value = client.base_url.rstrip("/") + value
    target = urlsplit(value)
    if (
        target.scheme.casefold() != base.scheme.casefold()
        or target.netloc.casefold() != base.netloc.casefold()
        or target.username is not None
        or target.password is not None
        or target.fragment
    ):
        raise RuntimeError("Black Duck evidence URL belongs to another instance")
    return value


def overall_score_evidence(advisory: dict[str, Any]) -> dict[str, Any]:
    raw = advisory.get("overallScore")
    if raw is None or raw == "":
        return {"status": "missing", "field": "overallScore", "value": None}
    if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
        return {"status": "invalid", "field": "overallScore", "value": None}
    try:
        score = float(raw)
    except (ValueError, OverflowError):
        score = math.nan
    if not math.isfinite(score) or not 0 <= score <= 10:
        return {"status": "invalid", "field": "overallScore", "value": None}
    return {"status": "known", "field": "overallScore", "value": score}


def exploit_evidence(advisory: dict[str, Any]) -> dict[str, Any]:
    explicit = []
    for field in EXPLICIT_EXPLOIT_FIELDS:
        if field not in advisory:
            continue
        raw = advisory[field]
        parsed = None
        if isinstance(raw, bool):
            parsed = raw
        elif isinstance(raw, str):
            normalized = raw.strip().casefold()
            if normalized == "true":
                parsed = True
            elif normalized == "false":
                parsed = False
        explicit.append({
            "field": field,
            "raw": copy.deepcopy(raw),
            "value": parsed,
        })

    metrics = {}
    for version in ("cvss2", "cvss3"):
        cvss = advisory.get(version)
        temporal = cvss.get("temporalMetrics") if isinstance(cvss, dict) else None
        if isinstance(temporal, dict) and "exploitability" in temporal:
            metrics[f"{version}.temporalMetrics.exploitability"] = copy.deepcopy(
                temporal["exploitability"]
            )
    cvss4 = advisory.get("cvss4")
    if isinstance(cvss4, dict) and "exploitMaturity" in cvss4:
        metrics["cvss4.exploitMaturity"] = copy.deepcopy(cvss4["exploitMaturity"])

    values = {
        item["value"] for item in explicit
        if item["value"] is not None
    }
    if any(item["value"] is None for item in explicit) or len(values) > 1:
        status, available = "invalid-or-conflicting", None
    elif len(values) == 1:
        status, available = "known", next(iter(values))
    else:
        status, available = "not-explicit", None

    return {
        "status": status,
        "available": available,
        "explicit_fields": explicit,
        "maturity_metrics": metrics,
    }


def occurrence_evidence(
    component: dict[str, Any],
    advisory: dict[str, Any],
    project_version_href: str,
    vulnerability_id: str,
    details_url: str,
) -> dict[str, Any]:
    nested = component.get("vulnerability")
    if not isinstance(nested, dict):
        raise RuntimeError("Project occurrence has no vulnerability object")

    occurrence_href = get_self_href(component)
    source = urlsplit(project_version_href)
    occurrence = urlsplit(occurrence_href)
    prefix = source.path.rstrip("/") + "/components/"
    parts = occurrence.path.rstrip("/").split("/")
    verified_scope = (
        occurrence.scheme.casefold() == source.scheme.casefold()
        and occurrence.netloc.casefold() == source.netloc.casefold()
        and occurrence.username is None
        and occurrence.password is None
        and not occurrence.query
        and not occurrence.fragment
        and occurrence.path.startswith(prefix)
        and len(parts) >= 3
        and parts[-1] == "remediation"
        and parts[-3] == "vulnerabilities"
        and unquote(parts[-2]) == vulnerability_id
    )
    remediation_href = canonical_href(occurrence_href) if verified_scope else ""
    origin_href = ""
    if remediation_href and "/origins/" in occurrence.path:
        before, after = occurrence.path.split("/origins/", 1)
        origin_href = (
            f"{occurrence.scheme}://{occurrence.netloc}"
            f"{before}/origins/{after.split('/', 1)[0]}"
        )

    raw_status = nested.get("remediationStatus")
    if isinstance(raw_status, str) and raw_status.strip():
        remediation_status = raw_status.strip()
        status_evidence = "known" if verified_scope else "scope-unverified"
    elif raw_status is None or raw_status == "":
        remediation_status, status_evidence = "", "missing"
    else:
        remediation_status, status_evidence = "", "invalid"

    vectors = {}
    for version in ("cvss2", "cvss3", "cvss4"):
        cvss = advisory.get(version)
        if isinstance(cvss, dict) and isinstance(cvss.get("vector"), str):
            vectors[f"{version}.vector"] = cvss["vector"]

    related = []
    direct_related = nested.get("relatedVulnerability")
    if isinstance(direct_related, str) and direct_related:
        related.append(direct_related)
    meta = advisory.get("_meta")
    raw_links = meta.get("links", []) if isinstance(meta, dict) else []
    if isinstance(raw_links, list):
        for link in raw_links:
            if (
                isinstance(link, dict)
                and link.get("rel") in {
                    "related-vulnerabilities",
                    "related-affecting-vulnerability",
                }
                and isinstance(link.get("href"), str)
            ):
                related.append(link["href"])

    return {
        "schema_version": 1,
        "project_version_href": canonical_href(project_version_href),
        "occurrence_href": canonical_href(occurrence_href),
        "remediation_href": remediation_href,
        "origin_href": origin_href,
        "vulnerability": vulnerability_id,
        "remediation_status": remediation_status,
        "remediation_evidence_status": status_evidence,
        "remediation_source_field": "vulnerability.remediationStatus",
        "advisory_href": get_self_href(advisory),
        "advisory_collection_href": details_url,
        "severity": str(advisory.get("severity") or nested.get("severity") or "").upper(),
        "overall_score": overall_score_evidence(advisory),
        "exploit": exploit_evidence(advisory),
        "cvss_version": copy.deepcopy(advisory.get("cvssVersion")),
        "cvss_vectors": vectors,
        "related_vulnerability_hrefs": sorted(set(related)),
    }


def matched_occurrence_advisory(
    client: Any,
    component: dict[str, Any],
    project_version_href: str,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    if not getattr(client, "product_occurrence_evidence", False):
        return None

    nested = component.get("vulnerability")
    if not isinstance(nested, dict):
        raise RuntimeError("Product collection requires a project vulnerability occurrence")
    identifier = direct_identifier(nested)
    if not identifier:
        raise RuntimeError("Project occurrence has no vulnerability identifier")

    linked = get_link(component, ("vulnerabilities", "vulnerability"))
    details_url = same_instance_url(client, linked) if linked else ""
    if details_url:
        candidates = client.paged_get(details_url)
        if not isinstance(candidates, list) or not all(
            isinstance(item, dict) for item in candidates
        ):
            raise RuntimeError("Advisory collection must contain objects")
        matches = [
            item for item in candidates
            if direct_identifier(item) == identifier
        ]
        if not matches:
            raise RuntimeError(f"Advisory collection has no exact match for {identifier}")
        advisory = matches[0]
        if any(item != advisory for item in matches[1:]):
            raise RuntimeError(f"Conflicting advisory records for {identifier}")
    else:
        advisory = nested

    evidence = occurrence_evidence(
        component, advisory, project_version_href, identifier, details_url
    )
    merged = copy.deepcopy(advisory)
    merged["vulnerabilityId"] = identifier
    merged["remediationStatus"] = evidence["remediation_status"]
    if "severity" not in merged and "severity" in nested:
        merged["severity"] = nested["severity"]
    return merged, evidence
