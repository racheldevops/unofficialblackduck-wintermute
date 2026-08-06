from __future__ import annotations

from typing import Any

from wintermute.blackduck.models import (
    LineageContext,
    NormalizedFinding,
    ProjectVersionRef,
)


def project_version_payload(
    value: ProjectVersionRef,
) -> dict[str, Any]:
    return {
        "instance_url": value.instance_url,
        "project": value.project,
        "version": value.version,
        "project_href": value.project_href,
        "version_href": value.version_href,
        "phase": value.phase,
        "updated": value.updated,
        "identity_key": value.identity_key,
        "external_id": value.external_id,
    }


def lineage_context_payload(
    value: LineageContext,
) -> dict[str, Any]:
    return {
        "external_id": value.external_id,
        "relationship_key": value.relationship_key,
        "detection_method": value.detection_method,
        "bom_component_name": value.bom_component_name,
        "bom_component_version": value.bom_component_version,
        "parent": project_version_payload(
            value.parent
        ),
        "child": project_version_payload(
            value.child
        ),
    }


def normalized_finding_payload(
    value: NormalizedFinding,
) -> dict[str, Any]:
    return {
        "external_id": value.external_id,
        "finding_key": value.finding_key,
        "project_version": project_version_payload(
            value.project_version
        ),
        "component": value.component,
        "component_version": value.component_version,
        "component_href": value.component_href,
        "vulnerability": value.vulnerability,
        "vulnerability_href": value.vulnerability_href,
        "severity": value.severity,
        "score_field": value.score_field,
        "score": value.score,
        "cvss_vector": value.cvss_vector,
        "exploit_available": (
            value.exploit_available
        ),
        "exploitable": value.exploitable,
        "reachable": value.reachable,
        "reachability": value.reachability,
        "reachability_source": (
            value.reachability_source
        ),
        "policy_name": value.policy_name,
        "policy_rule_href": (
            value.policy_rule_href
        ),
        "entity": value.entity,
        "lineage_contexts": [
            lineage_context_payload(context)
            for context in value.lineage_contexts
        ],
        "attributes": dict(value.attributes),
    }


def collection_failure_payload(
    value: Any,
) -> dict[str, Any]:
    return {
        "target_external_id": str(
            getattr(
                value,
                "target_external_id",
                "",
            )
            or ""
        ),
        "project": str(
            getattr(value, "project", "") or ""
        ),
        "project_version": str(
            getattr(
                value,
                "project_version",
                "",
            )
            or ""
        ),
        "project_version_href": str(
            getattr(
                value,
                "project_version_href",
                "",
            )
            or ""
        ),
        "stage": str(
            getattr(value, "stage", "") or ""
        ),
        "error": str(
            getattr(value, "error", "") or ""
        ),
        "component": str(
            getattr(value, "component", "") or ""
        ),
        "component_href": str(
            getattr(
                value,
                "component_href",
                "",
            )
            or ""
        ),
    }


def scope_failure_payload(
    value: Any,
) -> dict[str, Any]:
    return {
        "project": str(
            getattr(value, "project", "") or ""
        ),
        "project_href": str(
            getattr(
                value,
                "project_href",
                "",
            )
            or ""
        ),
        "project_version": str(
            getattr(
                value,
                "project_version",
                "",
            )
            or ""
        ),
        "project_version_href": str(
            getattr(
                value,
                "project_version_href",
                "",
            )
            or ""
        ),
        "stage": str(
            getattr(value, "stage", "") or ""
        ),
        "error": str(
            getattr(value, "error", "") or ""
        ),
    }
