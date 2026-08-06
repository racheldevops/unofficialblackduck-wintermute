from __future__ import annotations

from typing import Any, Iterable

from wintermute.blackduck.models import (
    NormalizedFinding,
)
from wintermute.blackduck.resources import (
    sha256_hex,
)


def string_value(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, bool):
        return str(value).lower()

    return str(value)


def jira_parent_rollup_rows(
    findings: Iterable[NormalizedFinding],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for finding in findings:
        child = finding.project_version
        component_version_href = str(
            finding.attributes.get(
                "component_version_href",
                "",
            )
            or ""
        )
        version_identity = (
            finding.component_version
            or component_version_href
            or finding.component_href
        )

        for context in finding.lineage_contexts:
            parent = context.parent
            rollup_key = "|".join(
                [
                    parent.project,
                    parent.version,
                    child.project,
                    child.version,
                    finding.component,
                    version_identity,
                    finding.vulnerability,
                ]
            )

            rows.append(
                {
                    "parent_project": parent.project,
                    "parent_version": parent.version,
                    "parent_version_href": (
                        parent.version_href
                    ),
                    "subproject_path": str(
                        finding.attributes.get(
                            "subproject_path",
                            (
                                f"{child.project}/"
                                f"{child.version}"
                            ),
                        )
                    ),
                    "subproject": child.project,
                    "subproject_version": child.version,
                    "subproject_version_href": (
                        child.version_href
                    ),
                    "relationship_detection_method": (
                        context.detection_method
                    ),
                    "component": finding.component,
                    "component_version": (
                        finding.component_version
                    ),
                    "component_version_href": (
                        component_version_href
                    ),
                    "vulnerability": (
                        finding.vulnerability
                    ),
                    "score_field": finding.score_field,
                    "score": finding.score,
                    "severity": finding.severity,
                    "cvss_vector": (
                        finding.cvss_vector
                    ),
                    "entity": finding.entity,
                    "blackduck_url": (
                        finding.vulnerability_href
                    ),
                    "rollup_key": rollup_key,
                }
            )

    return rows


def datadog_finding_rows(
    findings: Iterable[NormalizedFinding],
    *,
    group_by: str = "project",
    first_seen_source: str = (
        "blackduck-policy-vuln-pull"
    ),
) -> list[dict[str, str]]:
    if group_by not in {
        "project",
        "project-version",
    }:
        raise ValueError(
            "group_by must be project "
            "or project-version"
        )

    rows: list[dict[str, str]] = []

    for finding in findings:
        project_version = finding.project_version

        if group_by == "project-version":
            group_key = "|".join(
                [
                    project_version.project,
                    project_version.version,
                ]
            )
        else:
            group_key = project_version.project

        finding_key = "|".join(
            [
                project_version.project,
                project_version.version,
                finding.component,
                finding.component_version,
                finding.vulnerability,
            ]
        )
        candidate_key = str(
            finding.attributes.get(
                "candidate_key",
                "",
            )
            or ""
        )
        candidate_external_id = str(
            finding.attributes.get(
                "candidate_external_id",
                "",
            )
            or ""
        )

        rows.append(
            {
                "project": (
                    project_version.project
                ),
                "project_version": (
                    project_version.version
                ),
                "project_href": (
                    project_version.project_href
                ),
                "project_version_href": (
                    project_version.version_href
                ),
                "project_group_key": group_key,
                "project_group_external_id": (
                    sha256_hex(group_key)
                ),
                "candidate_key": candidate_key,
                "candidate_external_id": (
                    candidate_external_id
                ),
                "component": finding.component,
                "component_version": (
                    finding.component_version
                ),
                "component_origin_id": str(
                    finding.attributes.get(
                        "component_origin_id",
                        "",
                    )
                    or ""
                ),
                "vulnerability": (
                    finding.vulnerability
                ),
                "severity": finding.severity,
                "score_field": finding.score_field,
                "score": string_value(finding.score),
                "exploit_available": string_value(
                    finding.exploit_available
                ),
                "exploitable": finding.exploitable,
                "reachable": string_value(
                    finding.reachable
                ),
                "reachability": (
                    finding.reachability
                ),
                "reachability_source": (
                    finding.reachability_source
                ),
                "policy_name": (
                    finding.policy_name
                ),
                "policy_rule_href": (
                    finding.policy_rule_href
                ),
                "policy_matched": string_value(
                    finding.attributes.get(
                        "policy_matched",
                        True,
                    )
                ),
                "blackduck_url": (
                    finding.vulnerability_href
                ),
                "bom_component_url": str(
                    finding.attributes.get(
                        "bom_component_url",
                        "",
                    )
                    or ""
                ),
                "finding_key": finding_key,
                "finding_external_id": (
                    sha256_hex(finding_key)
                ),
                "first_seen_source": (
                    first_seen_source
                ),
            }
        )

    return rows
