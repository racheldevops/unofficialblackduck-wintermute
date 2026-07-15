#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import ssl
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


STATE_SCHEMA_VERSION = 1

REQUIRED_FIELDS = [
    "project",
    "project_version",
    "project_group_key",
    "project_group_external_id",
    "component",
    "component_version",
    "vulnerability",
    "severity",
    "score",
    "exploit_available",
    "reachable",
    "blackduck_url",
    "finding_key",
    "finding_external_id",
]

RESULT_FIELDNAMES = [
    "action",
    "event_mode",
    "event_key",
    "datadog_event_id",
    "project",
    "project_group_external_id",
    "finding_external_id",
    "vulnerability",
    "severity",
    "score",
    "message",
]

KNOWN_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_SORT_RANK = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "UNKNOWN": 4,
    "": 5,
}


@dataclass(frozen=True)
class PlannedEvent:
    mode: str
    event_key: str
    payload: dict[str, Any]
    group_rows: list[dict[str, str]]
    finding: dict[str, str] | None = None


def now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def normalize_tag(value: str) -> str:
    value = str(value or "").strip().lower()
    value = re.sub(r"[^a-z0-9_:\.-]+", "_", value)
    value = re.sub(r"_+", "_", value)
    return value.strip("_") or "unknown"


def truncate(value: str, max_length: int) -> str:
    value = str(value or "")

    if len(value) <= max_length:
        return value

    return value[: max_length - 3] + "..."


def to_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_severity(value: Any) -> str:
    return str(value or "").strip().upper()


def severity_alert_type(severity: Any) -> str:
    normalized = normalize_severity(severity)

    if normalized in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return normalized.lower()

    if normalized:
        return normalized.lower()

    return "info"


def highest_severity_from_rows(findings: list[dict[str, str]]) -> str:
    severities = [
        normalize_severity(finding.get("severity", ""))
        for finding in findings
        if normalize_severity(finding.get("severity", ""))
    ]

    if not severities:
        return "UNKNOWN"

    return sorted(
        severities,
        key=lambda severity: SEVERITY_SORT_RANK.get(severity, 99),
    )[0]


def sorted_unique(values: Any) -> list[str]:
    return sorted(
        {
            str(value or "").strip()
            for value in values
            if str(value or "").strip()
        }
    )


def format_project_version_label(finding: dict[str, str]) -> str:
    project = str(finding.get("project") or "unknown project").strip()
    version = str(finding.get("project_version") or "").strip()
    return " ".join(part for part in [project, version] if part) or "unknown project/version"


def format_component_label(finding: dict[str, str]) -> str:
    component = str(finding.get("component") or "unknown component").strip()
    version = str(finding.get("component_version") or "").strip()
    return " ".join(part for part in [component, version] if part) or "unknown component/version"


def format_project_link_label(finding: dict[str, str]) -> str:
    label = format_project_version_label(finding)
    project_href = str(finding.get("project_href") or "").strip()
    project_version_href = str(finding.get("project_version_href") or "").strip()

    links: list[str] = []

    if project_href:
        links.append(f"project: {project_href}")

    if project_version_href:
        links.append(f"version: {project_version_href}")

    if not links:
        return label

    return f"{label} ({'; '.join(links)})"


def vulnerability_group_external_id(vulnerability: str) -> str:
    normalized = str(vulnerability or "UNKNOWN").strip() or "UNKNOWN"
    return sha256_hex(f"vulnerability|{normalized}")


def atomic_write_json(path: str, payload: Any) -> None:
    if not path:
        return

    directory = os.path.dirname(path)

    if directory:
        os.makedirs(directory, exist_ok=True)

    tmp_path = f"{path}.tmp"

    with open(tmp_path, "w", encoding="utf-8") as output_file:
        json.dump(payload, output_file, indent=2, sort_keys=True)

    os.replace(tmp_path, path)


def write_results(path: str, rows: list[dict[str, Any]]) -> None:
    if not path:
        return

    directory = os.path.dirname(path)

    if directory:
        os.makedirs(directory, exist_ok=True)

    tmp_path = f"{path}.tmp"

    with open(tmp_path, "w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=RESULT_FIELDNAMES)
        writer.writeheader()

        for row in rows:
            writer.writerow({field: row.get(field, "") for field in RESULT_FIELDNAMES})

    os.replace(tmp_path, path)


def normalize_finding_row(row: dict[str, Any]) -> dict[str, str]:
    return {str(key): str(value or "") for key, value in row.items()}


def load_findings(path: str) -> list[dict[str, str]]:
    if not path:
        raise RuntimeError("--findings is required")

    if not os.path.exists(path):
        raise RuntimeError(f"Findings file does not exist: {path}")

    if path.endswith(".json"):
        try:
            with open(path, encoding="utf-8") as input_file:
                payload = json.load(input_file)
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError(f"Failed reading findings JSON {path}: {error}") from error

        if not isinstance(payload, list):
            raise RuntimeError(f"{path} must contain a JSON array")

        rows = [
            normalize_finding_row(row)
            for row in payload
            if isinstance(row, dict)
        ]
    else:
        try:
            with open(path, newline="", encoding="utf-8") as input_file:
                reader = csv.DictReader(input_file)

                if not reader.fieldnames:
                    raise RuntimeError("Findings CSV has no header row")

                missing = [
                    field
                    for field in REQUIRED_FIELDS
                    if field not in reader.fieldnames
                ]

                if missing:
                    raise RuntimeError(
                        f"Findings file is missing required field(s): {', '.join(missing)}"
                    )

                rows = [normalize_finding_row(row) for row in reader]
        except OSError as error:
            raise RuntimeError(f"Failed reading findings CSV {path}: {error}") from error

    deduped: list[dict[str, str]] = []
    seen: set[str] = set()

    for row in rows:
        finding_id = str(row.get("finding_external_id") or "").strip()

        if not finding_id or finding_id in seen:
            continue

        seen.add(finding_id)
        deduped.append(row)

    return deduped


def fresh_state() -> dict[str, Any]:
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "groups_by_external_id": {},
        "findings_by_external_id": {},
        "vulnerabilities_by_external_id": {},
        "events_by_key": {},
    }


def load_state(path: str) -> dict[str, Any]:
    if not path or not os.path.exists(path):
        return fresh_state()

    try:
        with open(path, encoding="utf-8") as input_file:
            state = json.load(input_file)
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Failed reading state {path}: {error}") from error

    if not isinstance(state, dict):
        raise RuntimeError(f"State file {path} must contain a JSON object")

    state.setdefault("schema_version", STATE_SCHEMA_VERSION)
    state.setdefault("created_at", now_iso())
    state.setdefault("updated_at", now_iso())
    state.setdefault("groups_by_external_id", {})
    state.setdefault("findings_by_external_id", {})
    state.setdefault("vulnerabilities_by_external_id", {})
    state.setdefault("events_by_key", {})

    if not isinstance(state["groups_by_external_id"], dict):
        raise RuntimeError("State field groups_by_external_id must be an object")

    if not isinstance(state["findings_by_external_id"], dict):
        raise RuntimeError("State field findings_by_external_id must be an object")

    if not isinstance(state["vulnerabilities_by_external_id"], dict):
        raise RuntimeError("State field vulnerabilities_by_external_id must be an object")

    if not isinstance(state["events_by_key"], dict):
        raise RuntimeError("State field events_by_key must be an object")

    return state


def save_state(path: str, state: dict[str, Any]) -> None:
    if not path:
        return

    state["updated_at"] = now_iso()
    atomic_write_json(path, state)


def parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None

    try:
        seconds = float(value)
    except ValueError:
        return None

    if seconds < 0:
        return None

    return seconds


def extra_tags(args: argparse.Namespace) -> list[str]:
    tags: list[str] = []

    for tag in str(args.tags or "").split(","):
        tag = tag.strip()

        if tag:
            tags.append(normalize_tag(tag))

    return tags


def base_tags(args: argparse.Namespace) -> list[str]:
    tags = [
        f"source:{normalize_tag(args.source)}",
        f"service:{normalize_tag(args.service)}",
    ]

    if args.env:
        tags.append(f"env:{normalize_tag(args.env)}")

    tags.extend(extra_tags(args))

    return sorted(set(tags))


def group_findings(findings: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    groups: dict[str, list[dict[str, str]]] = defaultdict(list)

    for finding in findings:
        groups[finding["project_group_external_id"]].append(finding)

    return {
        group_id: sorted(
            group_rows,
            key=lambda row: (
                row.get("project", "").lower(),
                row.get("project_version", "").lower(),
                row.get("vulnerability", "").lower(),
                row.get("component", "").lower(),
                row.get("component_version", "").lower(),
                row.get("finding_external_id", ""),
            ),
        )
        for group_id, group_rows in sorted(groups.items())
    }


def group_vulnerability_findings(findings: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    groups: dict[str, list[dict[str, str]]] = defaultdict(list)

    for finding in findings:
        vulnerability = str(finding.get("vulnerability") or "UNKNOWN").strip() or "UNKNOWN"
        groups[vulnerability_group_external_id(vulnerability)].append(finding)

    return {
        group_id: sorted(
            group_rows,
            key=lambda row: (
                row.get("vulnerability", "").lower(),
                row.get("project", "").lower(),
                row.get("project_version", "").lower(),
                row.get("component", "").lower(),
                row.get("component_version", "").lower(),
                row.get("finding_external_id", ""),
            ),
        )
        for group_id, group_rows in sorted(groups.items())
    }


def summarize_group(findings: list[dict[str, str]]) -> dict[str, Any]:
    scores = [to_float(finding.get("score")) for finding in findings]
    severity_counts = Counter(normalize_severity(finding.get("severity") or "UNKNOWN") for finding in findings)
    vulnerabilities = Counter(str(finding.get("vulnerability") or "UNKNOWN") for finding in findings)
    components = Counter(format_component_label(finding) for finding in findings)

    versions = sorted_unique(
        finding.get("project_version")
        for finding in findings
        if finding.get("project_version")
    )

    policies = sorted_unique(
        finding.get("policy_name")
        for finding in findings
        if finding.get("policy_name")
    )

    project_links = sorted_unique(format_project_link_label(finding) for finding in findings)
    vulnerability_links = sorted_unique(finding.get("blackduck_url") for finding in findings)
    component_links = sorted_unique(finding.get("bom_component_url") for finding in findings)

    return {
        "finding_count": len(findings),
        "max_score": max(scores) if scores else 0.0,
        "highest_severity": highest_severity_from_rows(findings),
        "critical_count": severity_counts.get("CRITICAL", 0),
        "high_count": severity_counts.get("HIGH", 0),
        "medium_count": severity_counts.get("MEDIUM", 0),
        "low_count": severity_counts.get("LOW", 0),
        "top_vulnerabilities": vulnerabilities.most_common(10),
        "top_components": components.most_common(10),
        "versions": versions,
        "policies": policies,
        "project_links": project_links,
        "vulnerability_links": vulnerability_links,
        "component_links": component_links,
    }


def summarize_vulnerability_group(findings: list[dict[str, str]]) -> dict[str, Any]:
    scores = [to_float(finding.get("score")) for finding in findings]
    severity_counts = Counter(normalize_severity(finding.get("severity") or "UNKNOWN") for finding in findings)

    project_versions = sorted_unique(format_project_version_label(finding) for finding in findings)
    project_links = sorted_unique(format_project_link_label(finding) for finding in findings)
    components = sorted_unique(format_component_label(finding) for finding in findings)
    vulnerability_links = sorted_unique(finding.get("blackduck_url") for finding in findings)
    component_links = sorted_unique(finding.get("bom_component_url") for finding in findings)
    policies = sorted_unique(finding.get("policy_name") for finding in findings if finding.get("policy_name"))

    return {
        "finding_count": len(findings),
        "max_score": max(scores) if scores else 0.0,
        "highest_severity": highest_severity_from_rows(findings),
        "critical_count": severity_counts.get("CRITICAL", 0),
        "high_count": severity_counts.get("HIGH", 0),
        "medium_count": severity_counts.get("MEDIUM", 0),
        "low_count": severity_counts.get("LOW", 0),
        "affected_project_version_count": len(project_versions),
        "affected_component_count": len(components),
        "project_versions": project_versions,
        "project_links": project_links,
        "components": components,
        "vulnerability_links": vulnerability_links,
        "component_links": component_links,
        "policies": policies,
    }


def project_event(
    group_id: str,
    findings: list[dict[str, str]],
    args: argparse.Namespace,
    resolved: bool = False,
) -> dict[str, Any]:
    first = findings[0] if findings else {}
    project = first.get("project", "unknown")

    if resolved:
        title = f"[Black Duck] Resolved: project no longer has matching exploitable high-risk vulnerabilities: {project}"
        text = "No current findings matched the configured Black Duck criteria in the latest run."
        alert_type = "success"
        status_tag = "bd_status:resolved"
        highest_severity = normalize_severity(first.get("severity", "")) or "UNKNOWN"
    else:
        summary = summarize_group(findings)
        highest_severity = str(summary["highest_severity"] or "UNKNOWN")

        title = f"[Black Duck] {highest_severity} project has exploitable high-risk vulnerabilities: {project}"

        lines = [
            f"Project: {project}",
            f"Highest severity: {highest_severity}",
            f"Active finding count: {summary['finding_count']}",
            f"Max score: {summary['max_score']}",
            f"Critical count: {summary['critical_count']}",
            f"High count: {summary['high_count']}",
            f"Medium count: {summary['medium_count']}",
            f"Low count: {summary['low_count']}",
            "",
            "Affected versions:",
            *[f"- {version}" for version in summary["versions"][:20]],
            "",
            "Black Duck project links:",
        ]

        project_links = summary.get("project_links", [])

        if project_links:
            lines.extend(f"- {link}" for link in project_links[:20])
        else:
            lines.append("- none provided")

        lines.extend(
            [
                "",
                "Top vulnerabilities:",
                *[f"- {name}: {count}" for name, count in summary["top_vulnerabilities"]],
                "",
                "Top components:",
                *[f"- {name}: {count}" for name, count in summary["top_components"] if name],
            ]
        )

        vulnerability_links = summary.get("vulnerability_links", [])

        if vulnerability_links:
            lines.extend(["", "Black Duck vulnerability links:"])
            lines.extend(f"- {link}" for link in vulnerability_links[:20])

        component_links = summary.get("component_links", [])

        if component_links:
            lines.extend(["", "Black Duck component links:"])
            lines.extend(f"- {link}" for link in component_links[:20])

        if summary["policies"]:
            lines.extend(
                [
                    "",
                    "Matched policies:",
                    *[f"- {name}" for name in summary["policies"][:20]],
                ]
            )

        lines.extend(
            [
                "",
                f"Project group external ID: {group_id}",
            ]
        )

        text = "\n".join(lines)
        alert_type = severity_alert_type(highest_severity)
        status_tag = "bd_status:open"

    tags = base_tags(args) + [
        "bd_group:project",
        f"bd_project:{normalize_tag(project)}",
        status_tag,
    ]

    if not resolved and highest_severity:
        tags.append(f"bd_severity:{normalize_tag(highest_severity)}")

    return {
        "title": truncate(title, 4000),
        "text": truncate(text, 4000),
        "alert_type": alert_type,
        "source_type_name": args.source,
        "aggregation_key": f"bd_project_{group_id}",
        "tags": sorted(set(tags)),
    }


def finding_event(
    finding: dict[str, str],
    args: argparse.Namespace,
    resolved: bool = False,
) -> dict[str, Any]:
    project = finding.get("project", "unknown")
    group_id = finding.get("project_group_external_id", "")
    vulnerability = finding.get("vulnerability", "UNKNOWN")
    component = finding.get("component", "unknown")
    severity = normalize_severity(finding.get("severity", ""))

    if resolved:
        title = f"[Black Duck] Resolved: {vulnerability} in {component} - {project}"
        text = (
            "Finding disappeared from latest Black Duck pull.\n\n"
            f"Finding ID: {finding.get('finding_external_id', '')}"
        )
        alert_type = "success"
        status_tag = "bd_status:resolved"
    else:
        title = f"[Black Duck] {severity} {vulnerability} in {component} - {project}"

        text = "\n".join(
            [
                f"Project: {project}",
                f"Version: {finding.get('project_version', '')}",
                f"Project URL: {finding.get('project_href', '')}",
                f"Project version URL: {finding.get('project_version_href', '')}",
                f"Component: {component}",
                f"Component version: {finding.get('component_version', '')}",
                f"Component URL: {finding.get('bom_component_url', '')}",
                f"Vulnerability: {vulnerability}",
                f"Severity: {severity}",
                f"Score: {finding.get('score', '')}",
                f"Exploit available: {finding.get('exploit_available', '')}",
                f"Reachable: {finding.get('reachable', '')}",
                f"Policy: {finding.get('policy_name', '')}",
                "",
                f"Black Duck vulnerability URL: {finding.get('blackduck_url', '')}",
                f"Finding ID: {finding.get('finding_external_id', '')}",
            ]
        )
        alert_type = severity_alert_type(severity)
        status_tag = "bd_status:open"

    tags = base_tags(args) + [
        "bd_group:finding",
        f"bd_project:{normalize_tag(project)}",
        f"bd_vulnerability:{normalize_tag(vulnerability)}",
        f"bd_component:{normalize_tag(component)}",
        f"bd_finding_id:{normalize_tag(finding.get('finding_external_id', ''))}",
        status_tag,
    ]

    if not resolved and severity:
        tags.append(f"bd_severity:{normalize_tag(severity)}")

    return {
        "title": truncate(title, 4000),
        "text": truncate(text, 4000),
        "alert_type": alert_type,
        "source_type_name": args.source,
        "aggregation_key": f"bd_project_{group_id}",
        "tags": sorted(set(tags)),
    }


def vulnerability_event(
    vulnerability_id: str,
    findings: list[dict[str, str]],
    args: argparse.Namespace,
    resolved: bool = False,
) -> dict[str, Any]:
    first = findings[0] if findings else {}
    vulnerability = str(first.get("vulnerability") or "UNKNOWN").strip() or "UNKNOWN"

    if resolved:
        title = f"[Black Duck] Resolved: {vulnerability} no longer has matching exploitable high-risk findings"
        text = (
            "No current findings matched the configured Black Duck criteria for this vulnerability "
            "in the latest run.\n\n"
            f"Vulnerability group external ID: {vulnerability_id}"
        )
        alert_type = "success"
        status_tag = "bd_status:resolved"
        highest_severity = normalize_severity(first.get("severity", "")) or "UNKNOWN"
    else:
        summary = summarize_vulnerability_group(findings)
        highest_severity = str(summary["highest_severity"] or "UNKNOWN")
        affected_project_version_count = int(summary.get("affected_project_version_count") or 0)
        affected_component_count = int(summary.get("affected_component_count") or 0)

        title = (
            f"[Black Duck] {highest_severity} {vulnerability} affects "
            f"{affected_project_version_count} project version(s)"
        )

        lines = [
            "Black Duck vulnerability rollup event.",
            "",
            f"Vulnerability: {vulnerability}",
            f"Highest severity: {highest_severity}",
            f"Active finding count: {summary['finding_count']}",
            f"Max score: {summary['max_score']}",
            f"Affected project/version count: {affected_project_version_count}",
            f"Affected component count: {affected_component_count}",
            f"Critical count: {summary['critical_count']}",
            f"High count: {summary['high_count']}",
            f"Medium count: {summary['medium_count']}",
            f"Low count: {summary['low_count']}",
            "",
            "Affected Black Duck projects/project versions:",
        ]

        project_links = summary.get("project_links", [])

        if project_links:
            lines.extend(f"- {link}" for link in project_links[:50])
        else:
            lines.append("- none provided")

        lines.extend(["", "Affected components:"])

        components = summary.get("components", [])

        if components:
            lines.extend(f"- {component}" for component in components[:50])
        else:
            lines.append("- none provided")

        detail_rows: list[str] = []
        seen_detail_rows: set[str] = set()

        for finding in sorted(
            findings,
            key=lambda row: (
                row.get("project", "").lower(),
                row.get("project_version", "").lower(),
                row.get("component", "").lower(),
                row.get("component_version", "").lower(),
                row.get("finding_external_id", ""),
            ),
        ):
            detail = (
                f"- {format_project_version_label(finding)} | "
                f"{format_component_label(finding)} | "
                f"severity={normalize_severity(finding.get('severity', '')) or 'UNKNOWN'} | "
                f"score={finding.get('score', '')}"
            )

            project_href = str(finding.get("project_href") or "").strip()
            project_version_href = str(finding.get("project_version_href") or "").strip()
            blackduck_url = str(finding.get("blackduck_url") or "").strip()
            bom_component_url = str(finding.get("bom_component_url") or "").strip()

            if project_href:
                detail += f" | project={project_href}"

            if project_version_href:
                detail += f" | version={project_version_href}"

            if blackduck_url:
                detail += f" | vulnerability={blackduck_url}"

            if bom_component_url:
                detail += f" | component={bom_component_url}"

            if detail in seen_detail_rows:
                continue

            seen_detail_rows.add(detail)
            detail_rows.append(detail)

            if len(detail_rows) >= 50:
                break

        lines.extend(["", "Project/component findings:"])
        lines.extend(detail_rows if detail_rows else ["- none provided"])

        vulnerability_links = summary.get("vulnerability_links", [])

        if vulnerability_links:
            lines.extend(["", "Black Duck vulnerability links:"])
            lines.extend(f"- {link}" for link in vulnerability_links[:20])

        if summary["policies"]:
            lines.extend(["", "Matched policies:"])
            lines.extend(f"- {name}" for name in summary["policies"][:20])

        lines.extend(
            [
                "",
                f"Vulnerability group external ID: {vulnerability_id}",
            ]
        )

        text = "\n".join(lines)
        alert_type = severity_alert_type(highest_severity)
        status_tag = "bd_status:open"

    tags = base_tags(args) + [
        "bd_group:vulnerability",
        f"bd_vulnerability:{normalize_tag(vulnerability)}",
        status_tag,
    ]

    if not resolved and highest_severity:
        tags.append(f"bd_severity:{normalize_tag(highest_severity)}")

    return {
        "title": truncate(title, 4000),
        "text": truncate(text, 4000),
        "alert_type": alert_type,
        "source_type_name": args.source,
        "aggregation_key": f"bd_vulnerability_{vulnerability_id}",
        "tags": sorted(set(tags)),
    }


class DatadogClient:
    def __init__(
        self,
        site: str,
        api_key: str,
        timeout: int,
        retries: int,
        retry_delay: float,
        debug: bool,
        insecure: bool = False,
    ):
        site = site.strip().rstrip("/")

        if site.startswith(("http://", "https://")):
            if site.endswith("/api/v1/events"):
                site = site[: -len("/api/v1/events")]
            self.base_url = site.rstrip("/")
        else:
            self.base_url = f"https://api.{site}"

        self.api_key = api_key
        self.timeout = timeout
        self.retries = retries
        self.retry_delay = retry_delay
        self.debug = debug
        self.ssl_context = ssl._create_unverified_context() if insecure else None

    def send_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}/api/v1/events"
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "DD-API-KEY": self.api_key,
        }

        for attempt in range(self.retries + 1):
            request = Request(url, data=data, headers=headers, method="POST")

            try:
                with urlopen(
                    request,
                    timeout=self.timeout,
                    context=self.ssl_context,
                ) as response:
                    body = response.read().decode("utf-8", errors="replace")

                    if response.status not in {200, 202}:
                        raise RuntimeError(f"HTTP {response.status}: {body[:1000]}")

                    if not body:
                        return {}

                    try:
                        return json.loads(body)
                    except json.JSONDecodeError:
                        return {"raw_response": body}

            except (HTTPError, URLError, TimeoutError, OSError, RuntimeError) as error:
                retry_after_seconds: float | None = None

                if isinstance(error, HTTPError):
                    body = error.read().decode("utf-8", errors="replace")
                    retryable = error.code in {408, 409, 425, 429, 500, 502, 503, 504}
                    retry_after_seconds = parse_retry_after(error.headers.get("Retry-After"))
                    message = f"HTTP {error.code} {error.reason}: {body[:1000]}"
                else:
                    retryable = True
                    message = str(error)

                if not retryable or attempt >= self.retries:
                    raise RuntimeError(f"POST {url} failed: {message}") from error

                sleep_seconds = (
                    retry_after_seconds
                    if retry_after_seconds is not None
                    else self.retry_delay * (attempt + 1)
                )

                if self.debug:
                    print(
                        f"Retrying Datadog event send after error: {message}; "
                        f"attempt {attempt + 1}/{self.retries}, sleeping {sleep_seconds}s",
                        file=sys.stderr,
                    )

                time.sleep(sleep_seconds)

        raise RuntimeError("Datadog event send failed unexpectedly")


def update_group_state(
    state: dict[str, Any],
    group_id: str,
    findings: list[dict[str, str]],
    status: str,
    action: str,
) -> None:
    groups = state.setdefault("groups_by_external_id", {})
    previous = groups.get(group_id, {}) if isinstance(groups.get(group_id), dict) else {}
    first = findings[0] if findings else previous

    groups[group_id] = {
        "project_group_external_id": group_id,
        "project_group_key": first.get("project_group_key", ""),
        "project": first.get("project", ""),
        "status": status,
        "finding_count": len(findings),
        "first_seen_at": previous.get("first_seen_at") or now_iso(),
        "last_seen_at": now_iso() if status == "active" else previous.get("last_seen_at", ""),
        "last_resolved_at": now_iso() if status == "resolved" else previous.get("last_resolved_at", ""),
        "last_action": action,
    }


def update_finding_state(
    state: dict[str, Any],
    finding: dict[str, str],
    status: str,
    action: str,
) -> None:
    findings = state.setdefault("findings_by_external_id", {})
    finding_id = finding["finding_external_id"]
    previous = findings.get(finding_id, {}) if isinstance(findings.get(finding_id), dict) else {}

    findings[finding_id] = {
        **finding,
        "status": status,
        "first_seen_at": previous.get("first_seen_at") or now_iso(),
        "last_seen_at": now_iso() if status == "active" else previous.get("last_seen_at", ""),
        "last_resolved_at": now_iso() if status == "resolved" else previous.get("last_resolved_at", ""),
        "last_action": action,
    }


def update_vulnerability_state(
    state: dict[str, Any],
    vulnerability_id: str,
    findings: list[dict[str, str]],
    status: str,
    action: str,
) -> None:
    vulnerabilities = state.setdefault("vulnerabilities_by_external_id", {})
    previous = vulnerabilities.get(vulnerability_id, {}) if isinstance(vulnerabilities.get(vulnerability_id), dict) else {}
    first = findings[0] if findings else previous
    summary = summarize_vulnerability_group(findings) if findings else {}

    vulnerabilities[vulnerability_id] = {
        "vulnerability_group_external_id": vulnerability_id,
        "vulnerability": first.get("vulnerability", ""),
        "severity": summary.get("highest_severity") or previous.get("severity", ""),
        "status": status,
        "finding_count": len(findings),
        "affected_project_version_count": summary.get(
            "affected_project_version_count",
            previous.get("affected_project_version_count", 0),
        ),
        "first_seen_at": previous.get("first_seen_at") or now_iso(),
        "last_seen_at": now_iso() if status == "active" else previous.get("last_seen_at", ""),
        "last_resolved_at": now_iso() if status == "resolved" else previous.get("last_resolved_at", ""),
        "last_action": action,
    }


def record_event(
    state: dict[str, Any],
    event_key: str,
    payload: dict[str, Any],
    response: dict[str, Any],
    action: str,
) -> None:
    state.setdefault("events_by_key", {})[event_key] = {
        "event_key": event_key,
        "action": action,
        "sent_at": now_iso(),
        "title": payload.get("title", ""),
        "aggregation_key": payload.get("aggregation_key", ""),
        "datadog_event_id": str(response.get("event", {}).get("id") or response.get("id") or ""),
        "response": response,
    }


def result_row(
    action: str,
    mode: str,
    event_key: str,
    source_row: dict[str, str],
    message: str,
    datadog_event_id: str = "",
) -> dict[str, Any]:
    return {
        "action": action,
        "event_mode": mode,
        "event_key": event_key,
        "datadog_event_id": datadog_event_id,
        "project": source_row.get("project", ""),
        "project_group_external_id": source_row.get("project_group_external_id", ""),
        "finding_external_id": source_row.get("finding_external_id", ""),
        "vulnerability": source_row.get("vulnerability", ""),
        "severity": source_row.get("severity", ""),
        "score": source_row.get("score", ""),
        "message": message,
    }


def plan_events(
    findings: list[dict[str, str]],
    grouped: dict[str, list[dict[str, str]]],
    state: dict[str, Any],
    args: argparse.Namespace,
    results: list[dict[str, Any]],
) -> list[PlannedEvent]:
    planned: list[PlannedEvent] = []
    vulnerability_grouped = group_vulnerability_findings(findings)

    if args.event_mode in {"project", "both"}:
        for group_id, group_rows in grouped.items():
            existing = state.setdefault("groups_by_external_id", {}).get(group_id)

            if isinstance(existing, dict) and existing.get("status") == "active" and not args.refresh_existing:
                update_group_state(state, group_id, group_rows, "active", "seen_existing_state")
                results.append(
                    result_row(
                        action="skip_existing_state",
                        mode="project",
                        event_key=f"project_open:{group_id}",
                        source_row=group_rows[0] if group_rows else {},
                        message="Project group already active in local state",
                    )
                )
            else:
                planned.append(
                    PlannedEvent(
                        mode="project",
                        event_key=f"project_open:{group_id}",
                        payload=project_event(group_id, group_rows, args),
                        group_rows=group_rows,
                    )
                )

    if args.event_mode == "vulnerability":
        for vulnerability_id, group_rows in vulnerability_grouped.items():
            existing = state.setdefault("vulnerabilities_by_external_id", {}).get(vulnerability_id)

            if isinstance(existing, dict) and existing.get("status") == "active" and not args.refresh_existing:
                update_vulnerability_state(
                    state=state,
                    vulnerability_id=vulnerability_id,
                    findings=group_rows,
                    status="active",
                    action="seen_existing_state",
                )
                results.append(
                    result_row(
                        action="skip_existing_state",
                        mode="vulnerability",
                        event_key=f"vulnerability_open:{vulnerability_id}",
                        source_row=group_rows[0] if group_rows else {},
                        message="Vulnerability group already active in local state",
                    )
                )
            else:
                planned.append(
                    PlannedEvent(
                        mode="vulnerability",
                        event_key=f"vulnerability_open:{vulnerability_id}",
                        payload=vulnerability_event(vulnerability_id, group_rows, args),
                        group_rows=group_rows,
                    )
                )

    if args.event_mode in {"finding", "both"}:
        for finding in sorted(findings, key=lambda row: row.get("finding_external_id", "")):
            finding_id = finding["finding_external_id"]
            existing = state.setdefault("findings_by_external_id", {}).get(finding_id)

            if isinstance(existing, dict) and existing.get("status") == "active" and not args.refresh_existing:
                update_finding_state(state, finding, "active", "seen_existing_state")
                results.append(
                    result_row(
                        action="skip_existing_state",
                        mode="finding",
                        event_key=f"finding_open:{finding_id}",
                        source_row=finding,
                        message="Finding already active in local state",
                    )
                )
            else:
                planned.append(
                    PlannedEvent(
                        mode="finding",
                        event_key=f"finding_open:{finding_id}",
                        payload=finding_event(finding, args),
                        group_rows=[],
                        finding=finding,
                    )
                )

    current_finding_ids = {finding["finding_external_id"] for finding in findings}
    current_group_ids = set(grouped)
    current_vulnerability_ids = set(vulnerability_grouped)

    if args.send_resolved:
        previous_findings = state.setdefault("findings_by_external_id", {})

        for finding_id, previous in sorted(previous_findings.items()):
            if not isinstance(previous, dict):
                continue

            if previous.get("status") != "active":
                continue

            if finding_id in current_finding_ids:
                continue

            previous_as_row = {
                str(key): str(value or "")
                for key, value in previous.items()
            }

            if args.event_mode in {"finding", "both"}:
                planned.append(
                    PlannedEvent(
                        mode="finding",
                        event_key=f"finding_resolved:{finding_id}",
                        payload=finding_event(previous_as_row, args, resolved=True),
                        group_rows=[],
                        finding=previous_as_row,
                    )
                )
            else:
                update_finding_state(state, previous_as_row, "resolved", "resolved_without_event")
                results.append(
                    result_row(
                        action="resolved_without_event",
                        mode="finding",
                        event_key=f"finding_resolved:{finding_id}",
                        source_row=previous_as_row,
                        message="Finding marked resolved in state; finding events not enabled",
                    )
                )

        if args.event_mode in {"project", "both"}:
            previous_groups = state.setdefault("groups_by_external_id", {})

            for group_id, previous in sorted(previous_groups.items()):
                if not isinstance(previous, dict):
                    continue

                if previous.get("status") != "active":
                    continue

                if group_id in current_group_ids:
                    continue

                pseudo = {
                    "project": str(previous.get("project") or ""),
                    "project_group_key": str(previous.get("project_group_key") or ""),
                    "project_group_external_id": group_id,
                }

                planned.append(
                    PlannedEvent(
                        mode="project",
                        event_key=f"project_resolved:{group_id}",
                        payload=project_event(group_id, [pseudo], args, resolved=True),
                        group_rows=[pseudo],
                    )
                )

        if args.event_mode == "vulnerability":
            previous_vulnerabilities = state.setdefault("vulnerabilities_by_external_id", {})

            for vulnerability_id, previous in sorted(previous_vulnerabilities.items()):
                if not isinstance(previous, dict):
                    continue

                if previous.get("status") != "active":
                    continue

                if vulnerability_id in current_vulnerability_ids:
                    continue

                pseudo = {
                    "vulnerability": str(previous.get("vulnerability") or "UNKNOWN"),
                    "severity": str(previous.get("severity") or ""),
                    "project_group_external_id": vulnerability_id,
                }

                planned.append(
                    PlannedEvent(
                        mode="vulnerability",
                        event_key=f"vulnerability_resolved:{vulnerability_id}",
                        payload=vulnerability_event(vulnerability_id, [pseudo], args, resolved=True),
                        group_rows=[pseudo],
                    )
                )

    return planned


def apply_max_send(
    planned: list[PlannedEvent],
    max_send: int | None,
    results: list[dict[str, Any]],
) -> list[PlannedEvent]:
    if max_send is None:
        return planned

    selected = planned[:max_send]
    skipped = planned[max_send:]

    for event in skipped:
        source_row = event.finding or (event.group_rows[0] if event.group_rows else {})
        results.append(
            result_row(
                action="skip_max_send_reached",
                mode=event.mode,
                event_key=event.event_key,
                source_row=source_row,
                message=f"--max-send {max_send} reached",
            )
        )

    return selected


def process(args: argparse.Namespace) -> int:
    if args.destination != "events":
        raise RuntimeError("Only --destination events is currently implemented")

    findings = load_findings(args.findings)
    state = load_state(args.state)
    grouped = group_findings(findings)
    vulnerability_grouped = group_vulnerability_findings(findings)
    dry_run = args.dry_run or not args.apply

    if args.insecure and not dry_run:
        print(
            "Warning: --insecure is enabled for Datadog HTTPS calls; "
            "TLS certificate verification is disabled.",
            file=sys.stderr,
        )

    client: DatadogClient | None = None

    if not dry_run:
        api_key = os.getenv(args.api_key_env)

        if not api_key:
            raise RuntimeError(f"{args.api_key_env} is required when --apply is used")

        client = DatadogClient(
            site=args.site,
            api_key=api_key,
            timeout=args.timeout,
            retries=args.retries,
            retry_delay=args.retry_delay,
            debug=args.debug,
            insecure=bool(args.insecure),
        )

    results: list[dict[str, Any]] = []
    planned = plan_events(findings, grouped, state, args, results)
    selected_events = apply_max_send(planned, args.max_send, results)

    errors = 0
    sent = 0
    planned_send_count = len(selected_events)

    for index, event in enumerate(selected_events, start=1):
        source_row = event.finding or (event.group_rows[0] if event.group_rows else {})
        action = "would_send" if dry_run else "send"

        if args.progress_every > 0 and (
            index == 1
            or index % args.progress_every == 0
            or index == planned_send_count
        ):
            print(
                f"[datadog] processing event {index:,}/{planned_send_count:,}: "
                f"{event.event_key}",
                file=sys.stderr,
            )

        if dry_run:
            results.append(
                result_row(
                    action=action,
                    mode=event.mode,
                    event_key=event.event_key,
                    source_row=source_row,
                    message=str(event.payload.get("title", "")),
                )
            )
            continue

        try:
            assert client is not None
            response = client.send_event(event.payload)
            datadog_event_id = str(response.get("event", {}).get("id") or response.get("id") or "")

            record_event(state, event.event_key, event.payload, response, "sent")
            sent += 1

            if event.event_key.startswith("project_open:"):
                update_group_state(state, event.event_key.split(":", 1)[1], event.group_rows, "active", "sent_open")
            elif event.event_key.startswith("project_resolved:"):
                update_group_state(state, event.event_key.split(":", 1)[1], event.group_rows, "resolved", "sent_resolved")
            elif event.event_key.startswith("vulnerability_open:"):
                update_vulnerability_state(
                    state=state,
                    vulnerability_id=event.event_key.split(":", 1)[1],
                    findings=event.group_rows,
                    status="active",
                    action="sent_open",
                )
            elif event.event_key.startswith("vulnerability_resolved:"):
                update_vulnerability_state(
                    state=state,
                    vulnerability_id=event.event_key.split(":", 1)[1],
                    findings=event.group_rows,
                    status="resolved",
                    action="sent_resolved",
                )
            elif event.event_key.startswith("finding_open:") and event.finding:
                update_finding_state(state, event.finding, "active", "sent_open")
            elif event.event_key.startswith("finding_resolved:") and event.finding:
                update_finding_state(state, event.finding, "resolved", "sent_resolved")

            results.append(
                result_row(
                    action="sent",
                    mode=event.mode,
                    event_key=event.event_key,
                    source_row=source_row,
                    message=str(event.payload.get("title", "")),
                    datadog_event_id=datadog_event_id,
                )
            )

            if args.checkpoint_every > 0 and sent % args.checkpoint_every == 0:
                save_state(args.state, state)
                print(f"[datadog] checkpointed state after {sent:,} sent event(s).", file=sys.stderr)

        except RuntimeError as error:
            errors += 1
            results.append(
                result_row(
                    action="error",
                    mode=event.mode,
                    event_key=event.event_key,
                    source_row=source_row,
                    message=str(error),
                )
            )

            if args.fail_fast:
                print(f"[datadog] fail-fast enabled; stopping after error: {error}", file=sys.stderr)
                break

    if not dry_run:
        save_state(args.state, state)

    plan_payload = {
        "generated_at": now_iso(),
        "dry_run": dry_run,
        "destination": args.destination,
        "event_mode": args.event_mode,
        "input_finding_count": len(findings),
        "project_group_count": len(grouped),
        "vulnerability_group_count": len(vulnerability_grouped),
        "planned_event_count_before_limit": len(planned),
        "event_count": len(selected_events),
        "max_send": args.max_send,
        "events": [
            {
                "event_key": event.event_key,
                "mode": event.mode,
                "payload": event.payload,
            }
            for event in selected_events
        ],
        "results": results,
    }

    atomic_write_json(args.plan_out, plan_payload)
    write_results(args.results_out, results)

    skipped_existing_count = sum(1 for row in results if row.get("action") == "skip_existing_state")
    skipped_max_send_count = sum(1 for row in results if row.get("action") == "skip_max_send_reached")
    resolved_without_event_count = sum(1 for row in results if row.get("action") == "resolved_without_event")

    print()
    print("Datadog publish summary")
    print("=======================")
    print(f"Input findings:             {len(findings):,}")
    print(f"Project groups:             {len(grouped):,}")
    print(f"Vulnerability groups:       {len(vulnerability_grouped):,}")
    print(f"Dry run:                    {dry_run}")
    print(f"Planned events before limit:{len(planned):,}")
    print(f"Selected events:            {len(selected_events):,}")
    print(f"Would send:                 {len(selected_events) if dry_run else 0:,}")
    print(f"Sent:                       {sent:,}")
    print(f"Skipped existing state:     {skipped_existing_count:,}")
    print(f"Skipped max-send:           {skipped_max_send_count:,}")
    print(f"Resolved without event:     {resolved_without_event_count:,}")
    print(f"Errors:                     {errors:,}")

    if args.results_out:
        print(f"Results CSV:                {args.results_out}")

    if args.plan_out:
        print(f"Plan JSON:                  {args.plan_out}")

    if dry_run:
        print()
        print("No Datadog events were sent. Add --apply when ready.")

    return 1 if errors else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Publish Black Duck high-risk vulnerability findings to Datadog Events."
    )
    parser.add_argument("--findings", default="policy_findings.csv")
    parser.add_argument("--destination", choices=["events"], default="events")
    parser.add_argument(
        "--event-mode",
        choices=["vulnerability", "project", "finding", "both"],
        default="vulnerability",
        help=(
            "Datadog event grouping mode. Default: vulnerability, which sends one "
            "CVE/vulnerability rollup event listing all affected projects/components. "
            "project keeps project-level grouping; finding sends one event per finding; "
            "both sends project plus finding events."
        ),
    )
    parser.add_argument("--site", default="datadoghq.com")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help=(
            "Disable TLS certificate verification for Datadog HTTPS calls. "
            "Useful behind corporate TLS inspection proxies. Default: verify TLS."
        ),
    )
    parser.add_argument("--api-key-env", default="DATADOG_API_KEY")
    parser.add_argument("--service", default="blackduck")
    parser.add_argument("--source", default="blackduck")
    parser.add_argument("--env", default="")
    parser.add_argument("--tags", default="")
    parser.add_argument("--state", default="datadog-findings-state.json")
    parser.add_argument("--results-out", default="datadog-publish-results.csv")
    parser.add_argument("--plan-out", default="datadog-publish-plan.json")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--refresh-existing", action="store_true")
    parser.set_defaults(send_resolved=True)
    parser.add_argument("--send-resolved", dest="send_resolved", action="store_true")
    parser.add_argument("--no-send-resolved", dest="send_resolved", action="store_false")
    parser.add_argument("--max-send", type=int)
    parser.add_argument(
        "--progress-every",
        type=int,
        default=25,
        help="Print send progress every N planned Datadog events. Use 0 to disable. Default: 25.",
    )
    parser.add_argument(
        "--checkpoint-every",
        type=int,
        default=25,
        help="Save Datadog state after every N successfully sent events. Use 0 to save only at end. Default: 25.",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop sending after the first Datadog send error. Default: continue and report all errors.",
    )
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--retry-delay", type=float, default=2.0)
    parser.add_argument("--debug", action="store_true")
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if args.timeout <= 0:
        raise RuntimeError("--timeout must be greater than 0")

    if args.retries < 0:
        raise RuntimeError("--retries must be 0 or greater")

    if args.retry_delay < 0:
        raise RuntimeError("--retry-delay must be 0 or greater")

    if args.max_send is not None and args.max_send < 1:
        raise RuntimeError("--max-send must be greater than 0")

    if args.progress_every < 0:
        raise RuntimeError("--progress-every must be 0 or greater")

    if args.checkpoint_every < 0:
        raise RuntimeError("--checkpoint-every must be 0 or greater")


def main() -> int:
    args = parse_args()

    try:
        validate_args(args)
        return process(args)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
