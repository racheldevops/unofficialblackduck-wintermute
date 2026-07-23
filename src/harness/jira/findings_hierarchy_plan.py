#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import urlparse, urlunparse

from harness.paths import ensure_parent_dir, jira_output_path


SCHEMA_VERSION = 3
HIERARCHY_MODE_VULNERABILITY_PROJECT = "vulnerability-project"
HIERARCHY_MODE_PROJECT_SUBPROJECT_VULNERABILITY = "project-subproject-vulnerability"

REQUIRED_FINDING_FIELDS = [
    "parent_project",
    "parent_version",
    "parent_version_href",
    "subproject_path",
    "subproject",
    "subproject_version",
    "subproject_version_href",
    "relationship_detection_method",
    "component",
    "component_version",
    "vulnerability",
    "score_field",
    "score",
    "severity",
    "blackduck_url",
    "rollup_key",
]

OPTIONAL_FINDING_FIELDS = [
    "component_version_href",
    "cvss_vector",
    "entity",
]

KNOWN_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_SORT_RANK = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "": 4,
    "UNKNOWN": 4,
}


def now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def canonical_href(href: str) -> str:
    href = str(href or "").strip()

    if not href:
        return ""

    parsed = urlparse(href)

    if not parsed.scheme or not parsed.netloc:
        return href.rstrip("/")

    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path.rstrip("/"),
            "",
            "",
            "",
        )
    )


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def stable_hash(parts: Iterable[str]) -> str:
    canonical_parts = [str(part or "") for part in parts]
    payload = json.dumps(canonical_parts, ensure_ascii=False, separators=(",", ":"))
    return sha256_hex(payload)


def sanitize_jira_label(value: str) -> str:
    value = str(value or "").strip().lower()
    value = re.sub(r"[^a-z0-9_-]+", "_", value)
    value = re.sub(r"_+", "_", value)
    return value.strip("_") or "unknown"


def truncate(value: str, max_length: int) -> str:
    value = str(value or "")

    if len(value) <= max_length:
        return value

    return value[: max_length - 3] + "..."


def normalize_severity(value: str) -> str:
    return str(value or "").strip().upper()


def severity_label(severity: str) -> str:
    severity = normalize_severity(severity)
    return sanitize_jira_label(f"bd_sev_{severity or 'unknown'}")


def to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def sorted_unique(values: Iterable[str]) -> list[str]:
    return sorted({str(value).strip() for value in values if str(value or "").strip()})


def csv_join(values: Iterable[str]) -> str:
    return ";".join(sorted_unique(values))


def looks_like_resource_url(value: Any) -> bool:
    text = str(value or "").strip().lower()

    return (
        text.startswith("http://")
        or text.startswith("https://")
        or text.startswith("/api/")
    )

def normalize_finding(
        row: dict[str, Any],
) -> dict[str, str]:
    finding = {
        field: str(row.get(field, "") or "").strip()
        for field in (
            REQUIRED_FINDING_FIELDS + OPTIONAL_FINDING_FIELDS
        )
    }

    if not finding["vulnerability"]:
        finding["vulnerability"] = "UNKNOWN"

    if looks_like_resource_url(
        finding["component_version"]
    ):
        if not finding["component_version_href"]:
            finding["component_version_href"] = (
                finding["component_version"]
            )

        finding["component_version"] = ""

    if not finding["rollup_key"]:
        finding["rollup_key"] = "|".join(
            [
                finding["parent_project"],
                finding["parent_version"],
                finding["subproject"],
                finding["subproject_version"],
                finding["component"],
                (
                    finding["component_version"]
                    or finding["component_version_href"]
                ),
                finding["vulnerability"],
            ]
        )

    finding["severity"] = normalize_severity(
        finding["severity"]
    )
    finding["parent_version_href"] = canonical_href(
        finding["parent_version_href"]
    )
    finding["subproject_version_href"] = canonical_href(
        finding["subproject_version_href"]
    )
    finding["component_version_href"] = canonical_href(
        finding["component_version_href"]
    )

    return finding

def read_findings(path: str) -> list[dict[str, str]]:
    if path == "-":
        input_file = sys.stdin
        close_after = False
    else:
        input_file = open(path, newline="", encoding="utf-8")
        close_after = True

    try:
        reader = csv.DictReader(input_file)

        if not reader.fieldnames:
            raise RuntimeError("Findings CSV has no header row")

        missing = [
            field
            for field in REQUIRED_FINDING_FIELDS
            if field not in reader.fieldnames
        ]

        if missing:
            raise RuntimeError(
                "Findings CSV is missing required field(s): "
                + ", ".join(missing)
            )

        return [normalize_finding(row) for row in reader]
    finally:
        if close_after:
            input_file.close()


def dedupe_findings(findings: list[dict[str, str]]) -> list[dict[str, str]]:
    unique: list[dict[str, str]] = []
    seen_rollup_keys: set[str] = set()

    for finding in findings:
        rollup_key = finding["rollup_key"]

        if rollup_key in seen_rollup_keys:
            continue

        seen_rollup_keys.add(rollup_key)
        unique.append(finding)

    return unique


def apply_filters(
        findings: list[dict[str, str]],
        args: argparse.Namespace,
) -> list[dict[str, str]]:
    filtered = list(findings)

    if args.only_parent_project:
        filtered = [
            finding
            for finding in filtered
            if finding["parent_project"] == args.only_parent_project
        ]

    if args.only_parent_version:
        filtered = [
            finding
            for finding in filtered
            if finding["parent_version"] == args.only_parent_version
        ]

    if args.only_subproject:
        filtered = [
            finding
            for finding in filtered
            if finding["subproject"] == args.only_subproject
        ]

    if args.only_vulnerability:
        filtered = [
            finding
            for finding in filtered
            if finding["vulnerability"] == args.only_vulnerability
        ]

    if args.limit is not None:
        filtered = filtered[: args.limit]

    return filtered


def parent_group_key(finding: dict[str, str]) -> tuple[str, str, str]:
    return (
        finding["parent_project"],
        finding["parent_version"],
        canonical_href(finding["parent_version_href"]),
    )


def story_group_key(finding: dict[str, str]) -> tuple[str, str, str, str, str, str, str]:
    parent_project, parent_version, parent_version_href = parent_group_key(finding)

    return (
        parent_project,
        parent_version,
        parent_version_href,
        finding["subproject"],
        finding["subproject_version"],
        canonical_href(finding["subproject_version_href"]),
        finding["subproject_path"],
    )


def affected_project_key(finding: dict[str, str]) -> tuple[str, str, str]:
    return (
        finding["subproject"],
        finding["subproject_version"],
        canonical_href(finding["subproject_version_href"]),
    )


def vulnerability_key(finding: dict[str, str]) -> str:
    return finding.get("vulnerability") or "UNKNOWN"


def vulnerability_project_task_key(finding: dict[str, str]) -> tuple[str, str, str, str]:
    affected_project, affected_version, affected_href = affected_project_key(finding)

    return (
        vulnerability_key(finding),
        affected_project,
        affected_version,
        affected_href,
    )


def sort_tuple(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(str(value or "").lower() for value in values)


def vulnerability_sort_key(finding: dict[str, str]) -> tuple[Any, ...]:
    severity = normalize_severity(finding.get("severity", ""))

    return (
        sort_tuple(parent_group_key(finding)),
        sort_tuple(story_group_key(finding)),
        SEVERITY_SORT_RANK.get(severity, 5),
        str(finding.get("component", "")).lower(),
        str(finding.get("component_version", "")).lower(),
        str(finding.get("vulnerability", "")).lower(),
        str(finding.get("rollup_key", "")).lower(),
    )


def node_external_id(prefix: str, parts: Iterable[str]) -> str:
    return f"{prefix}_{stable_hash(parts)}"


def vulnerability_epic_external_id(vulnerability: str) -> str:
    return f"bd_cve_{sha256_hex(str(vulnerability or 'UNKNOWN'))}"


def node_lookup_label(external_id: str, hash_length: int) -> str:
    hash_part = external_id.rsplit("_", 1)[-1]
    prefix = external_id[: -(len(hash_part) + 1)]
    return sanitize_jira_label(f"{prefix}_{hash_part[:hash_length]}")


def compute_stats(findings: list[dict[str, str]]) -> dict[str, Any]:
    severity_counts = Counter(
        normalize_severity(finding.get("severity", "")) or "UNKNOWN"
        for finding in findings
    )

    unknown_count = sum(
        count
        for severity, count in severity_counts.items()
        if severity not in KNOWN_SEVERITIES
    )

    scores = [
        score
        for score in (to_float(finding.get("score")) for finding in findings)
        if score is not None
    ]

    stats: dict[str, Any] = {
        "finding_count": len(findings),
        "component_count": len(
            {
                (
                    finding.get("component", ""),
                    finding.get("component_version", ""),
                )
                for finding in findings
            }
        ),
        "vulnerability_count": len(
            {finding.get("vulnerability", "") for finding in findings}
        ),
        "affected_project_version_count": len(
            {affected_project_key(finding) for finding in findings}
        ),
        "critical_count": severity_counts.get("CRITICAL", 0),
        "high_count": severity_counts.get("HIGH", 0),
        "medium_count": severity_counts.get("MEDIUM", 0),
        "low_count": severity_counts.get("LOW", 0),
        "unknown_count": unknown_count,
    }

    if scores:
        stats["max_score"] = max(scores)
        stats["min_score"] = min(scores)
        stats["average_score"] = round(sum(scores) / len(scores), 3)
    else:
        stats["max_score"] = ""
        stats["min_score"] = ""
        stats["average_score"] = ""

    return stats


def highest_severity_from_stats(stats: dict[str, Any]) -> str:
    if int(stats.get("critical_count") or 0) > 0:
        return "CRITICAL"

    if int(stats.get("high_count") or 0) > 0:
        return "HIGH"

    if int(stats.get("medium_count") or 0) > 0:
        return "MEDIUM"

    if int(stats.get("low_count") or 0) > 0:
        return "LOW"

    if int(stats.get("unknown_count") or 0) > 0:
        return "UNKNOWN"

    return ""


def base_labels(node_kind_label: str, lookup_label: str) -> list[str]:
    return sorted(
        {
            "blackduck",
            "subproject_rollup",
            node_kind_label,
            lookup_label,
        }
    )


def format_project_version(project: str, version: str) -> str:
    label = " ".join(part for part in [project, version] if part)
    return label or "Unknown project/version"


def component_label(finding: dict[str, str]) -> str:
    return format_project_version(finding.get("component", ""), finding.get("component_version", ""))


def parent_context_label(finding: dict[str, str]) -> str:
    return format_project_version(finding.get("parent_project", ""), finding.get("parent_version", ""))


def build_legacy_epic_summary(context: dict[str, str]) -> str:
    return truncate(
        f"[Black Duck Rollup] "
        f"{format_project_version(context['parent_project'], context['parent_version'])}",
        255,
    )


def build_legacy_story_summary(context: dict[str, str]) -> str:
    child_label = format_project_version(
        context["subproject"],
        context["subproject_version"],
    )

    return truncate(f"[Black Duck Subproject] {child_label}", 255)


def build_legacy_vulnerability_summary(context: dict[str, str]) -> str:
    severity = context.get("severity", "")
    vulnerability = context.get("vulnerability", "") or "Unknown vulnerability"
    component = context.get("component", "") or "unknown component"

    severity_part = f"{severity} " if severity else ""

    return truncate(
        f"[Black Duck] {severity_part}{vulnerability} in {component}",
        255,
    )


def build_legacy_epic_description(
        context: dict[str, str],
        stats: dict[str, Any],
) -> str:
    return "\n".join(
        [
            "Black Duck vulnerability rollup parent container.",
            "",
            f"Parent project: {context['parent_project']}",
            f"Parent version: {context['parent_version']}",
            f"Parent version URL: {context['parent_version_href']}",
            "",
            f"Child/subproject count: {stats.get('child_count', 0)}",
            f"Finding count: {stats.get('finding_count', 0)}",
            f"Critical count: {stats.get('critical_count', 0)}",
            f"High count: {stats.get('high_count', 0)}",
        ]
    )


def build_legacy_story_description(
        context: dict[str, Any],
        stats: dict[str, Any],
) -> str:
    relationship_methods = ", ".join(context.get("relationship_detection_methods", []))

    return "\n".join(
        [
            "Black Duck vulnerability rollup child/subproject container.",
            "",
            f"Parent project: {context['parent_project']}",
            f"Parent version: {context['parent_version']}",
            f"Subproject path: {context['subproject_path']}",
            f"Subproject: {context['subproject']}",
            f"Subproject version: {context['subproject_version']}",
            f"Subproject version URL: {context['subproject_version_href']}",
            f"Relationship detection method(s): {relationship_methods}",
            "",
            f"Finding count: {stats.get('finding_count', 0)}",
            f"Critical count: {stats.get('critical_count', 0)}",
            f"High count: {stats.get('high_count', 0)}",
        ]
    )


def build_legacy_vulnerability_description(context: dict[str, str]) -> str:
    return "\n".join(
        [
            "Black Duck vulnerability rollup finding.",
            "",
            f"Parent project: {context['parent_project']}",
            f"Parent version: {context['parent_version']}",
            f"Subproject path: {context['subproject_path']}",
            f"Subproject: {context['subproject']}",
            f"Subproject version: {context['subproject_version']}",
            f"Component: {context['component']}",
            f"Component version: {context['component_version']}",
            f"Vulnerability: {context['vulnerability']}",
            f"Severity: {context['severity']}",
            f"Score field: {context['score_field']}",
            f"Score: {context['score']}",
            "",
            f"Black Duck vulnerability URL: {context['blackduck_url']}",
            f"Parent version URL: {context['parent_version_href']}",
            f"Subproject version URL: {context['subproject_version_href']}",
            "",
            "Rollup key:",
            context["rollup_key"],
        ]
    )


def build_cve_epic_summary(vulnerability: str) -> str:
    return truncate(f"[Black Duck] {vulnerability or 'UNKNOWN'}", 255)


def build_cve_project_task_summary(
        vulnerability: str,
        affected_project: str,
        affected_version: str,
) -> str:
    return truncate(
        f"{vulnerability or 'UNKNOWN'} Project {format_project_version(affected_project, affected_version)}",
        255,
    )


def build_cve_epic_description(
        vulnerability: str,
        group_findings: list[dict[str, str]],
        stats: dict[str, Any],
        external_id: str,
        lookup_label: str,
) -> str:
    highest_severity = highest_severity_from_stats(stats)
    affected_versions = sorted_unique(
        format_project_version(finding["subproject"], finding["subproject_version"])
        for finding in group_findings
    )
    blackduck_urls = sorted_unique(finding.get("blackduck_url", "") for finding in group_findings)
    components = sorted_unique(component_label(finding) for finding in group_findings)
    parent_contexts = sorted_unique(parent_context_label(finding) for finding in group_findings)

    lines = [
        "Black Duck CVE remediation rollup.",
        "",
        f"Vulnerability: {vulnerability}",
        f"Highest severity: {highest_severity}",
        f"Max score: {stats.get('max_score', '')}",
        "",
        f"Affected project/version count: {stats.get('affected_project_version_count', 0)}",
        f"Finding count: {stats.get('finding_count', 0)}",
        f"Affected component count: {stats.get('component_count', 0)}",
        "",
        "Affected Black Duck project versions:",
    ]

    lines.extend(f"- {item}" for item in affected_versions)
    lines.extend(["", "Black Duck vulnerability links:"])
    lines.extend(f"- {item}" for item in blackduck_urls) if blackduck_urls else lines.append("- none provided")
    lines.extend(["", "Affected components:"])
    lines.extend(f"- {item}" for item in components) if components else lines.append("- none provided")
    lines.extend(["", "Parent rollup context:"])
    lines.extend(f"- {item}" for item in parent_contexts) if parent_contexts else lines.append("- none provided")
    lines.extend(
        [
            "",
            "Suggested advisory workflow:",
            "1. Review all child Tasks under this Epic.",
            "2. Confirm affected project owners and remediation assignments.",
            "3. Validate vulnerable component usage and exploitability as needed.",
            "4. Upgrade, patch, replace, or document risk acceptance for affected components.",
            "5. Rescan affected Black Duck project versions.",
            "6. Generate the security advisory from this Epic and its assigned Tasks.",
            "",
            "Deterministic metadata:",
            f"- External ID: {external_id}",
            f"- Lookup label: {lookup_label}",
        ]
    )

    return "\n".join(lines)


def build_cve_project_task_description(
        vulnerability: str,
        affected_project: str,
        affected_version: str,
        affected_href: str,
        group_findings: list[dict[str, str]],
        stats: dict[str, Any],
        external_id: str,
        lookup_label: str,
) -> str:
    highest_severity = highest_severity_from_stats(stats)
    parent_contexts = sorted_unique(
        parent_context_label(finding)
        for finding in group_findings
    )
    rollup_keys = sorted_unique(
        finding.get("rollup_key", "")
        for finding in group_findings
    )
    cvss_vectors = sorted_unique(
        finding.get("cvss_vector", "")
        for finding in group_findings
    )

    component_rows: list[
        tuple[str, str, str, str, str, str]
    ] = []
    seen_components: set[
        tuple[str, str, str, str, str, str]
    ] = set()

    for finding in sorted(
        group_findings,
        key=vulnerability_sort_key,
    ):
        row = (
            finding.get("component", ""),
            finding.get("component_version", ""),
            finding.get("component_version_href", ""),
            finding.get("severity", ""),
            finding.get("score", ""),
            finding.get("blackduck_url", ""),
        )

        if row in seen_components:
            continue

        seen_components.add(row)
        component_rows.append(row)

    lines = [
        "Black Duck CVE remediation task.",
        "",
        f"Vulnerability: {vulnerability}",
        f"Affected project: {affected_project}",
        f"Affected version: {affected_version}",
        f"Affected project version URL: {affected_href}",
        "",
        f"Severity: {highest_severity}",
    ]

    if cvss_vectors:
        lines.extend(
            [
                "CVSS vector:",
                "{noformat}",
                "\n".join(cvss_vectors),
                "{noformat}",
            ]
        )
    else:
        lines.append("CVSS vector: not provided")

    lines.extend(
        [
            f"Max score: {stats.get('max_score', '')}",
            "",
            "Affected components:",
            "| Component | Version | Component URL | "
            "Severity | Score | Vulnerability URL |",
        ]
    )

    if component_rows:
        for (
            component,
            component_version,
            component_version_href,
            severity,
            score,
            blackduck_url,
        ) in component_rows:
            lines.append(
                f"| {component} | {component_version} | "
                f"{component_version_href} | {severity} | "
                f"{score} | {blackduck_url} |"
            )
    else:
        lines.append(
            "| none provided |  |  |  |  |  |"
        )

    lines.extend(["", "Parent rollup context:"])

    if parent_contexts:
        lines.extend(
            f"- {item}"
            for item in parent_contexts
        )
    else:
        lines.append("- none provided")

    lines.extend(
        [
            "",
            "Suggested remediation workflow:",
            "1. Review the linked Black Duck vulnerability advisory.",
            "2. Confirm affected component usage in this project version.",
            "3. Upgrade, patch, replace, or document accepted risk.",
            "4. Rescan the affected Black Duck project version.",
            "5. Close this Task when this project/version is no longer affected.",
            "",
            "Rollup keys:",
        ]
    )

    if rollup_keys:
        lines.extend(
            f"- {item}"
            for item in rollup_keys
        )
    else:
        lines.append("- none provided")

    lines.extend(
        [
            "",
            "Deterministic metadata:",
            f"- External ID: {external_id}",
            f"- Lookup label: {lookup_label}",
        ]
    )

    return "\n".join(lines)

def build_project_subproject_vulnerability_nodes(
        findings: list[dict[str, str]],
        hash_length: int,
) -> list[dict[str, Any]]:
    parent_groups: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    story_groups: dict[
        tuple[str, str, str, str, str, str, str],
        list[dict[str, str]],
    ] = defaultdict(list)
    stories_by_parent: dict[tuple[str, str, str], set[tuple[str, ...]]] = defaultdict(set)

    for finding in findings:
        parent_key = parent_group_key(finding)
        story_key = story_group_key(finding)

        parent_groups[parent_key].append(finding)
        story_groups[story_key].append(finding)
        stories_by_parent[parent_key].add(story_key)

    parent_external_ids = {
        key: node_external_id("bd_parent", key)
        for key in parent_groups
    }
    story_external_ids = {
        key: node_external_id("bd_child", key)
        for key in story_groups
    }

    nodes: list[dict[str, Any]] = []

    for key in sorted(parent_groups, key=sort_tuple):
        group_findings = parent_groups[key]
        parent_project, parent_version, parent_version_href = key
        external_id = parent_external_ids[key]
        lookup_label = node_lookup_label(external_id, hash_length)

        context = {
            "parent_project": parent_project,
            "parent_version": parent_version,
            "parent_version_href": parent_version_href,
        }

        stats = compute_stats(group_findings)
        stats["child_count"] = len(stories_by_parent.get(key, set()))

        nodes.append(
            {
                "hierarchy_mode": HIERARCHY_MODE_PROJECT_SUBPROJECT_VULNERABILITY,
                "node_type": "epic",
                "external_id": external_id,
                "lookup_label": lookup_label,
                "parent_external_id": "",
                "summary": build_legacy_epic_summary(context),
                "description": build_legacy_epic_description(context, stats),
                "labels": base_labels("bd_rollup_parent", lookup_label),
                "context": context,
                "stats": stats,
            }
        )

    for key in sorted(story_groups, key=sort_tuple):
        group_findings = story_groups[key]
        (
            parent_project,
            parent_version,
            parent_version_href,
            subproject,
            subproject_version,
            subproject_version_href,
            subproject_path,
        ) = key

        parent_key = (
            parent_project,
            parent_version,
            parent_version_href,
        )
        external_id = story_external_ids[key]
        lookup_label = node_lookup_label(external_id, hash_length)

        context = {
            "parent_project": parent_project,
            "parent_version": parent_version,
            "parent_version_href": parent_version_href,
            "subproject": subproject,
            "subproject_version": subproject_version,
            "subproject_version_href": subproject_version_href,
            "subproject_path": subproject_path,
            "relationship_detection_methods": sorted_unique(
                finding.get("relationship_detection_method", "")
                for finding in group_findings
            ),
        }

        stats = compute_stats(group_findings)

        nodes.append(
            {
                "hierarchy_mode": HIERARCHY_MODE_PROJECT_SUBPROJECT_VULNERABILITY,
                "node_type": "story",
                "external_id": external_id,
                "lookup_label": lookup_label,
                "parent_external_id": parent_external_ids[parent_key],
                "summary": build_legacy_story_summary(context),
                "description": build_legacy_story_description(context, stats),
                "labels": base_labels("bd_rollup_child", lookup_label),
                "context": context,
                "stats": stats,
            }
        )

    for finding in sorted(findings, key=vulnerability_sort_key):
        story_key = story_group_key(finding)
        external_id = node_external_id("bd_vuln", [finding["rollup_key"]])
        lookup_label = node_lookup_label(external_id, hash_length)

        labels = set(base_labels("bd_rollup_vuln", lookup_label))
        labels.add(severity_label(finding.get("severity", "")))

        context = dict(finding)
        context["parent_version_href"] = canonical_href(context["parent_version_href"])
        context["subproject_version_href"] = canonical_href(context["subproject_version_href"])

        nodes.append(
            {
                "hierarchy_mode": HIERARCHY_MODE_PROJECT_SUBPROJECT_VULNERABILITY,
                "node_type": "vulnerability",
                "external_id": external_id,
                "lookup_label": lookup_label,
                "parent_external_id": story_external_ids[story_key],
                "summary": build_legacy_vulnerability_summary(context),
                "description": build_legacy_vulnerability_description(context),
                "labels": sorted(labels),
                "context": context,
                "stats": {
                    "finding_count": 1,
                    "component_count": 1,
                    "vulnerability_count": 1,
                    "affected_project_version_count": 1,
                    "critical_count": 1 if context["severity"] == "CRITICAL" else 0,
                    "high_count": 1 if context["severity"] == "HIGH" else 0,
                    "medium_count": 1 if context["severity"] == "MEDIUM" else 0,
                    "low_count": 1 if context["severity"] == "LOW" else 0,
                    "unknown_count": 0 if context["severity"] in KNOWN_SEVERITIES else 1,
                    "max_score": context.get("score", ""),
                    "min_score": context.get("score", ""),
                    "average_score": context.get("score", ""),
                },
            }
        )

    return nodes


def build_vulnerability_project_nodes(
        findings: list[dict[str, str]],
        hash_length: int,
) -> list[dict[str, Any]]:
    vulnerability_groups: dict[
        str,
        list[dict[str, str]],
    ] = defaultdict(list)
    task_groups: dict[
        tuple[str, str, str, str],
        list[dict[str, str]],
    ] = defaultdict(list)
    tasks_by_vulnerability: dict[
        str,
        set[tuple[str, str, str, str]],
    ] = defaultdict(set)

    for finding in findings:
        vulnerability = vulnerability_key(finding)
        task_key = vulnerability_project_task_key(finding)

        vulnerability_groups[vulnerability].append(finding)
        task_groups[task_key].append(finding)
        tasks_by_vulnerability[vulnerability].add(task_key)

    epic_external_ids = {
        vulnerability: vulnerability_epic_external_id(
            vulnerability
        )
        for vulnerability in vulnerability_groups
    }
    task_external_ids = {
        key: node_external_id("bd_cve_project", key)
        for key in task_groups
    }

    nodes: list[dict[str, Any]] = []

    for vulnerability in sorted(
        vulnerability_groups,
        key=lambda value: value.lower(),
    ):
        group_findings = vulnerability_groups[vulnerability]
        external_id = epic_external_ids[vulnerability]
        lookup_label = node_lookup_label(
            external_id,
            hash_length,
        )
        stats = compute_stats(group_findings)

        task_count = len(
            tasks_by_vulnerability[vulnerability]
        )
        stats["affected_project_version_count"] = task_count
        stats["child_count"] = task_count

        highest_severity = highest_severity_from_stats(stats)

        context = {
            "vulnerability": vulnerability,
            "severity": highest_severity,
            "affected_project_count": str(task_count),
            "affected_project_version_count": str(task_count),
            "affected_project_versions": sorted_unique(
                format_project_version(
                    finding["subproject"],
                    finding["subproject_version"],
                )
                for finding in group_findings
            ),
            "parent_projects": sorted_unique(
                parent_context_label(finding)
                for finding in group_findings
            ),
            "blackduck_urls": sorted_unique(
                finding.get("blackduck_url", "")
                for finding in group_findings
            ),
            "components": sorted_unique(
                component_label(finding)
                for finding in group_findings
            ),
            "entities": sorted_unique(
                finding.get("entity", "")
                for finding in group_findings
            ),
            "cvss_vectors": sorted_unique(
                finding.get("cvss_vector", "")
                for finding in group_findings
            ),
        }

        labels = set(
            base_labels(
                "bd_rollup_cve",
                lookup_label,
            )
        )

        if highest_severity:
            labels.add(
                severity_label(highest_severity)
            )

        nodes.append(
            {
                "hierarchy_mode": (
                    HIERARCHY_MODE_VULNERABILITY_PROJECT
                ),
                "node_type": "epic",
                "external_id": external_id,
                "lookup_label": lookup_label,
                "parent_external_id": "",
                "summary": build_cve_epic_summary(
                    vulnerability
                ),
                "description": build_cve_epic_description(
                    vulnerability=vulnerability,
                    group_findings=group_findings,
                    stats=stats,
                    external_id=external_id,
                    lookup_label=lookup_label,
                ),
                "labels": sorted(labels),
                "context": context,
                "stats": stats,
            }
        )

    for key in sorted(
        task_groups,
        key=lambda item: sort_tuple(item),
    ):
        (
            vulnerability,
            affected_project,
            affected_version,
            affected_href,
        ) = key

        group_findings = task_groups[key]
        external_id = task_external_ids[key]
        lookup_label = node_lookup_label(
            external_id,
            hash_length,
        )
        cve_lookup_label = node_lookup_label(
            epic_external_ids[vulnerability],
            hash_length,
        )
        project_version_lookup_label = node_lookup_label(
            node_external_id(
                "bd_project_version",
                [
                    affected_project,
                    affected_version,
                    affected_href,
                ],
            ),
            hash_length,
        )

        stats = compute_stats(group_findings)
        highest_severity = highest_severity_from_stats(stats)

        entity_values = sorted_unique(
            finding.get("entity", "")
            for finding in group_findings
        )
        cvss_vectors = sorted_unique(
            finding.get("cvss_vector", "")
            for finding in group_findings
        )

        context = {
            "vulnerability": vulnerability,
            "severity": highest_severity,
            "affected_project": affected_project,
            "affected_version": affected_version,
            "affected_project_version_href": affected_href,
            "subproject": affected_project,
            "subproject_version": affected_version,
            "subproject_version_href": affected_href,
            "subproject_path": csv_join(
                finding.get("subproject_path", "")
                for finding in group_findings
            ),
            "parent_project": csv_join(
                finding.get("parent_project", "")
                for finding in group_findings
            ),
            "parent_version": csv_join(
                finding.get("parent_version", "")
                for finding in group_findings
            ),
            "parent_version_href": csv_join(
                finding.get("parent_version_href", "")
                for finding in group_findings
            ),
            "parent_projects": sorted_unique(
                parent_context_label(finding)
                for finding in group_findings
            ),
            "relationship_detection_methods": sorted_unique(
                finding.get(
                    "relationship_detection_method",
                    "",
                )
                for finding in group_findings
            ),
            "components": sorted_unique(
                finding.get("component", "")
                for finding in group_findings
            ),
            "component_versions": sorted_unique(
                finding.get("component_version", "")
                for finding in group_findings
            ),
            "blackduck_urls": sorted_unique(
                finding.get("blackduck_url", "")
                for finding in group_findings
            ),
            "rollup_keys": sorted_unique(
                finding.get("rollup_key", "")
                for finding in group_findings
            ),
            "entity": csv_join(entity_values),
            "entities": entity_values,
            "cvss_vector": csv_join(cvss_vectors),
            "cvss_vectors": cvss_vectors,
        }

        labels = set(
            base_labels(
                "bd_rollup_project_version",
                lookup_label,
            )
        )
        labels.add(cve_lookup_label)
        labels.add(project_version_lookup_label)

        if highest_severity:
            labels.add(
                severity_label(highest_severity)
            )

        nodes.append(
            {
                "hierarchy_mode": (
                    HIERARCHY_MODE_VULNERABILITY_PROJECT
                ),
                "node_type": "story",
                "external_id": external_id,
                "lookup_label": lookup_label,
                "parent_external_id": (
                    epic_external_ids[vulnerability]
                ),
                "summary": build_cve_project_task_summary(
                    vulnerability=vulnerability,
                    affected_project=affected_project,
                    affected_version=affected_version,
                ),
                "description": (
                    build_cve_project_task_description(
                        vulnerability=vulnerability,
                        affected_project=affected_project,
                        affected_version=affected_version,
                        affected_href=affected_href,
                        group_findings=group_findings,
                        stats=stats,
                        external_id=external_id,
                        lookup_label=lookup_label,
                    )
                ),
                "labels": sorted(labels),
                "context": context,
                "stats": stats,
            }
        )

    return nodes

def build_nodes(
        findings: list[dict[str, str]],
        hash_length: int,
        hierarchy_mode: str,
) -> list[dict[str, Any]]:
    if hierarchy_mode == HIERARCHY_MODE_PROJECT_SUBPROJECT_VULNERABILITY:
        return build_project_subproject_vulnerability_nodes(
            findings=findings,
            hash_length=hash_length,
        )

    return build_vulnerability_project_nodes(
        findings=findings,
        hash_length=hash_length,
    )


def count_nodes(nodes: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(node.get("node_type", "")) for node in nodes)

    return {
        "epic_count": counts.get("epic", 0),
        "story_count": counts.get("story", 0),
        "vulnerability_count": counts.get("vulnerability", 0),
        "total_node_count": len(nodes),
    }


def write_json_file(
        path: str,
        payload: dict[str, Any],
) -> None:
    ensure_parent_dir(path)

    if path == "-":
        json.dump(
            payload,
            sys.stdout,
            indent=2,
            sort_keys=True,
        )
        print()
        return

    with open(path, "w", encoding="utf-8") as output_file:
        json.dump(
            payload,
            output_file,
            indent=2,
            sort_keys=True,
        )

def csv_cell(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, list):
        return ";".join(str(item) for item in value if str(item or "").strip())

    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)

    return str(value)


def node_summary_row(
        node: dict[str, Any],
) -> dict[str, Any]:
    context = node.get("context", {})
    stats = node.get("stats", {})

    return {
        "hierarchy_mode": node.get("hierarchy_mode", ""),
        "node_type": node.get("node_type", ""),
        "external_id": node.get("external_id", ""),
        "parent_external_id": node.get(
            "parent_external_id",
            "",
        ),
        "lookup_label": node.get("lookup_label", ""),
        "summary": node.get("summary", ""),
        "vulnerability": context.get("vulnerability", ""),
        "entity": context.get("entity", ""),
        "cvss_vector": context.get("cvss_vector", ""),
        "affected_project": context.get(
            "affected_project",
            "",
        ),
        "affected_version": context.get(
            "affected_version",
            "",
        ),
        "affected_project_version_href": context.get(
            "affected_project_version_href",
            "",
        ),
        "parent_project": context.get("parent_project", ""),
        "parent_version": context.get("parent_version", ""),
        "parent_version_href": context.get(
            "parent_version_href",
            "",
        ),
        "subproject": context.get("subproject", ""),
        "subproject_version": context.get(
            "subproject_version",
            "",
        ),
        "subproject_version_href": context.get(
            "subproject_version_href",
            "",
        ),
        "subproject_path": context.get("subproject_path", ""),
        "child_count": stats.get("child_count", ""),
        "finding_count": stats.get("finding_count", ""),
        "component_count": stats.get("component_count", ""),
        "vulnerability_count": stats.get(
            "vulnerability_count",
            "",
        ),
        "affected_project_version_count": stats.get(
            "affected_project_version_count",
            "",
        ),
        "critical_count": stats.get("critical_count", ""),
        "high_count": stats.get("high_count", ""),
        "medium_count": stats.get("medium_count", ""),
        "low_count": stats.get("low_count", ""),
        "unknown_count": stats.get("unknown_count", ""),
        "max_score": stats.get("max_score", ""),
        "min_score": stats.get("min_score", ""),
        "average_score": stats.get("average_score", ""),
    }

def write_summary_csv(
        path: str,
        nodes: list[dict[str, Any]],
) -> None:
    if not path:
        return

    ensure_parent_dir(path)

    fieldnames = [
        "hierarchy_mode",
        "node_type",
        "external_id",
        "parent_external_id",
        "lookup_label",
        "summary",
        "vulnerability",
        "entity",
        "cvss_vector",
        "affected_project",
        "affected_version",
        "affected_project_version_href",
        "parent_project",
        "parent_version",
        "parent_version_href",
        "subproject",
        "subproject_version",
        "subproject_version_href",
        "subproject_path",
        "child_count",
        "finding_count",
        "component_count",
        "vulnerability_count",
        "affected_project_version_count",
        "critical_count",
        "high_count",
        "medium_count",
        "low_count",
        "unknown_count",
        "max_score",
        "min_score",
        "average_score",
    ]

    rows = [
        node_summary_row(node)
        for node in nodes
        if node.get("node_type") in {"epic", "story"}
    ]

    if path == "-":
        output_file = sys.stdout
        close_after = False
    else:
        output_file = open(
            path,
            "w",
            newline="",
            encoding="utf-8",
        )
        close_after = True

    try:
        writer = csv.DictWriter(
            output_file,
            fieldnames=fieldnames,
        )
        writer.writeheader()

        for row in rows:
            writer.writerow(
                {
                    field: csv_cell(row.get(field, ""))
                    for field in fieldnames
                }
            )
    finally:
        if close_after:
            output_file.close()

def node_csv_row(
        node: dict[str, Any],
) -> dict[str, Any]:
    context = node.get("context", {})
    stats = node.get("stats", {})

    return {
        "hierarchy_mode": node.get("hierarchy_mode", ""),
        "node_type": node.get("node_type", ""),
        "external_id": node.get("external_id", ""),
        "parent_external_id": node.get(
            "parent_external_id",
            "",
        ),
        "lookup_label": node.get("lookup_label", ""),
        "summary": node.get("summary", ""),
        "labels": ";".join(node.get("labels", [])),
        "parent_project": context.get("parent_project", ""),
        "parent_version": context.get("parent_version", ""),
        "parent_version_href": context.get(
            "parent_version_href",
            "",
        ),
        "subproject": context.get("subproject", ""),
        "subproject_version": context.get(
            "subproject_version",
            "",
        ),
        "subproject_version_href": context.get(
            "subproject_version_href",
            "",
        ),
        "subproject_path": context.get("subproject_path", ""),
        "affected_project": context.get(
            "affected_project",
            "",
        ),
        "affected_version": context.get(
            "affected_version",
            "",
        ),
        "affected_project_version_href": context.get(
            "affected_project_version_href",
            "",
        ),
        "component": context.get("component", ""),
        "component_version": context.get(
            "component_version",
            "",
        ),
        "components": context.get("components", ""),
        "component_versions": context.get(
            "component_versions",
            "",
        ),
        "vulnerability": context.get("vulnerability", ""),
        "severity": context.get("severity", ""),
        "score": context.get("score", ""),
        "cvss_vector": context.get("cvss_vector", ""),
        "entity": context.get("entity", ""),
        "blackduck_url": context.get("blackduck_url", ""),
        "blackduck_urls": context.get("blackduck_urls", ""),
        "rollup_key": context.get("rollup_key", ""),
        "rollup_keys": context.get("rollup_keys", ""),
        "finding_count": stats.get("finding_count", ""),
        "component_count": stats.get("component_count", ""),
        "vulnerability_count": stats.get(
            "vulnerability_count",
            "",
        ),
        "affected_project_version_count": stats.get(
            "affected_project_version_count",
            "",
        ),
        "critical_count": stats.get("critical_count", ""),
        "high_count": stats.get("high_count", ""),
        "medium_count": stats.get("medium_count", ""),
        "low_count": stats.get("low_count", ""),
        "unknown_count": stats.get("unknown_count", ""),
        "max_score": stats.get("max_score", ""),
        "min_score": stats.get("min_score", ""),
        "average_score": stats.get("average_score", ""),
    }

def write_nodes_csv(
        path: str,
        nodes: list[dict[str, Any]],
) -> None:
    if not path:
        return

    ensure_parent_dir(path)

    fieldnames = [
        "hierarchy_mode",
        "node_type",
        "external_id",
        "parent_external_id",
        "lookup_label",
        "summary",
        "labels",
        "parent_project",
        "parent_version",
        "parent_version_href",
        "subproject",
        "subproject_version",
        "subproject_version_href",
        "subproject_path",
        "affected_project",
        "affected_version",
        "affected_project_version_href",
        "component",
        "component_version",
        "components",
        "component_versions",
        "vulnerability",
        "severity",
        "score",
        "cvss_vector",
        "entity",
        "blackduck_url",
        "blackduck_urls",
        "rollup_key",
        "rollup_keys",
        "finding_count",
        "component_count",
        "vulnerability_count",
        "affected_project_version_count",
        "critical_count",
        "high_count",
        "medium_count",
        "low_count",
        "unknown_count",
        "max_score",
        "min_score",
        "average_score",
    ]

    if path == "-":
        output_file = sys.stdout
        close_after = False
    else:
        output_file = open(
            path,
            "w",
            newline="",
            encoding="utf-8",
        )
        close_after = True

    try:
        writer = csv.DictWriter(
            output_file,
            fieldnames=fieldnames,
        )
        writer.writeheader()

        for node in nodes:
            row = node_csv_row(node)
            writer.writerow(
                {
                    field: csv_cell(row.get(field, ""))
                    for field in fieldnames
                }
            )
    finally:
        if close_after:
            output_file.close()

def build_plan_payload(
        args: argparse.Namespace,
        raw_findings_count: int,
        unique_findings_count: int,
        filtered_findings: list[dict[str, str]],
        nodes: list[dict[str, Any]],
) -> dict[str, Any]:
    plan_counts = count_nodes(nodes)

    return {
        "schema_version": SCHEMA_VERSION,
        "hierarchy_mode": args.hierarchy_mode,
        "generated_at": now_iso(),
        "source_findings": args.findings,
        "source_counts": {
            "raw_finding_count": raw_findings_count,
            "unique_finding_count": unique_findings_count,
            "planned_finding_count": len(filtered_findings),
        },
        "filters": {
            "only_parent_project": args.only_parent_project or "",
            "only_parent_version": args.only_parent_version or "",
            "only_subproject": args.only_subproject or "",
            "only_vulnerability": args.only_vulnerability or "",
            "limit": args.limit,
        },
        "node_counts": plan_counts,
        "nodes": nodes,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create a normalized Jira hierarchy plan from "
            "Black Duck rollup findings. This script does not "
            "call Jira."
        )
    )

    parser.add_argument(
        "--findings",
        default=jira_output_path("findings.csv"),
        help="Input findings CSV from the vulnerability rollup.",
    )
    parser.add_argument(
        "--hierarchy-mode",
        choices=[
            HIERARCHY_MODE_VULNERABILITY_PROJECT,
            HIERARCHY_MODE_PROJECT_SUBPROJECT_VULNERABILITY,
        ],
        default=HIERARCHY_MODE_VULNERABILITY_PROJECT,
        help="Jira hierarchy model.",
    )
    parser.add_argument(
        "--plan-out",
        default=jira_output_path(
            "jira-hierarchy-plan.json"
        ),
        help="Output hierarchy plan JSON.",
    )
    parser.add_argument(
        "--summary-out",
        default=jira_output_path(
            "jira-hierarchy-summary.csv"
        ),
        help="Epic and Task summary CSV output.",
    )
    parser.add_argument(
        "--nodes-out",
        default=jira_output_path(
            "jira-hierarchy-nodes.csv"
        ),
        help="Flattened hierarchy node CSV output.",
    )
    parser.add_argument(
        "--only-parent-project",
        help="Only include this parent project.",
    )
    parser.add_argument(
        "--only-parent-version",
        help="Only include this parent version.",
    )
    parser.add_argument(
        "--only-subproject",
        help="Only include this affected subproject.",
    )
    parser.add_argument(
        "--only-vulnerability",
        help="Only include this vulnerability ID.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Limit deduplicated findings processed.",
    )
    parser.add_argument(
        "--hash-length",
        type=int,
        default=24,
        help="Hash length used in Jira lookup labels.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print debugging details.",
    )

    return parser.parse_args()

def validate_args(args: argparse.Namespace) -> None:
    if args.limit is not None and args.limit < 1:
        raise RuntimeError("--limit must be greater than 0")

    if args.hash_length < 8 or args.hash_length > 64:
        raise RuntimeError("--hash-length must be between 8 and 64")


def process(args: argparse.Namespace) -> int:
    validate_args(args)

    raw_findings = read_findings(args.findings)
    unique_findings = dedupe_findings(raw_findings)
    filtered_findings = apply_filters(unique_findings, args)

    nodes = build_nodes(
        findings=filtered_findings,
        hash_length=args.hash_length,
        hierarchy_mode=args.hierarchy_mode,
    )

    plan_payload = build_plan_payload(
        args=args,
        raw_findings_count=len(raw_findings),
        unique_findings_count=len(unique_findings),
        filtered_findings=filtered_findings,
        nodes=nodes,
    )

    write_json_file(args.plan_out, plan_payload)
    write_summary_csv(args.summary_out, nodes)
    write_nodes_csv(args.nodes_out, nodes)

    node_counts = plan_payload["node_counts"]

    print()
    print("Jira hierarchy plan summary")
    print("===========================")
    print(f"Hierarchy mode:          {args.hierarchy_mode}")
    print(f"Input findings:          {len(raw_findings)}")
    print(f"Unique rollup findings:  {len(unique_findings)}")
    print(f"Planned findings:        {len(filtered_findings)}")

    if args.hierarchy_mode == HIERARCHY_MODE_VULNERABILITY_PROJECT:
        print(f"CVE Epic nodes:          {node_counts['epic_count']}")
        print(f"Project-version Tasks:   {node_counts['story_count']}")
    else:
        print(f"Parent Epic nodes:       {node_counts['epic_count']}")
        print(f"Subproject Story nodes:  {node_counts['story_count']}")

    print(f"Vulnerability nodes:     {node_counts['vulnerability_count']}")
    print(f"Total nodes:             {node_counts['total_node_count']}")
    print(f"Plan JSON:               {args.plan_out}")

    if args.summary_out:
        print(f"Summary CSV:             {args.summary_out}")

    if args.nodes_out:
        print(f"Nodes CSV:               {args.nodes_out}")

    if not filtered_findings:
        print()
        print("Warning: no findings matched the selected filters.", file=sys.stderr)

    return 0


def main() -> int:
    args = parse_args()

    try:
        return process(args)
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
