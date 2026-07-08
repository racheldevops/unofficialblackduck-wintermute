#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


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


def to_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def load_findings(path: str) -> list[dict[str, str]]:
    if path.endswith(".json"):
        with open(path, encoding="utf-8") as input_file:
            payload = json.load(input_file)

        if not isinstance(payload, list):
            raise RuntimeError(f"{path} must contain a JSON array")

        rows = [
            {str(key): str(value or "") for key, value in row.items()}
            for row in payload
            if isinstance(row, dict)
        ]
    else:
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

            rows = [dict(row) for row in reader]

    deduped: list[dict[str, str]] = []
    seen: set[str] = set()

    for row in rows:
        finding_id = str(row.get("finding_external_id") or "")

        if not finding_id or finding_id in seen:
            continue

        seen.add(finding_id)
        deduped.append(row)

    return deduped


def load_state(path: str) -> dict[str, Any]:
    if not path or not os.path.exists(path):
        return {
            "schema_version": 1,
            "created_at": now_iso(),
            "updated_at": now_iso(),
            "groups_by_external_id": {},
            "findings_by_external_id": {},
            "events_by_key": {},
        }

    try:
        with open(path, encoding="utf-8") as input_file:
            state = json.load(input_file)
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Failed reading state {path}: {error}") from error

    if not isinstance(state, dict):
        raise RuntimeError(f"State file {path} must contain a JSON object")

    state.setdefault("schema_version", 1)
    state.setdefault("created_at", now_iso())
    state.setdefault("updated_at", now_iso())
    state.setdefault("groups_by_external_id", {})
    state.setdefault("findings_by_external_id", {})
    state.setdefault("events_by_key", {})

    return state


def save_state(path: str, state: dict[str, Any]) -> None:
    state["updated_at"] = now_iso()
    tmp_path = f"{path}.tmp"

    with open(tmp_path, "w", encoding="utf-8") as output_file:
        json.dump(state, output_file, indent=2, sort_keys=True)

    os.replace(tmp_path, path)


def write_json_file(path: str, payload: dict[str, Any]) -> None:
    if not path:
        return

    with open(path, "w", encoding="utf-8") as output_file:
        json.dump(payload, output_file, indent=2, sort_keys=True)


def write_results(path: str, rows: list[dict[str, Any]]) -> None:
    if not path:
        return

    with open(path, "w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=RESULT_FIELDNAMES)
        writer.writeheader()

        for row in rows:
            writer.writerow({field: row.get(field, "") for field in RESULT_FIELDNAMES})


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

    return dict(groups)


def summarize_group(findings: list[dict[str, str]]) -> dict[str, Any]:
    scores = [to_float(finding.get("score")) for finding in findings]
    severity_counts = Counter(str(finding.get("severity") or "UNKNOWN").upper() for finding in findings)
    vulnerabilities = Counter(str(finding.get("vulnerability") or "UNKNOWN") for finding in findings)
    components = Counter(
        f"{finding.get('component', '')} {finding.get('component_version', '')}".strip()
        for finding in findings
    )

    versions = sorted(
        {
            str(finding.get("project_version") or "")
            for finding in findings
            if finding.get("project_version")
        }
    )

    policies = sorted(
        {
            str(finding.get("policy_name") or "")
            for finding in findings
            if finding.get("policy_name")
        }
    )

    return {
        "finding_count": len(findings),
        "max_score": max(scores) if scores else 0.0,
        "critical_count": severity_counts.get("CRITICAL", 0),
        "high_count": severity_counts.get("HIGH", 0),
        "top_vulnerabilities": vulnerabilities.most_common(10),
        "top_components": components.most_common(10),
        "versions": versions,
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
    else:
        summary = summarize_group(findings)

        title = f"[Black Duck] Project has exploitable high-risk vulnerabilities: {project}"

        lines = [
            f"Project: {project}",
            f"Active finding count: {summary['finding_count']}",
            f"Max score: {summary['max_score']}",
            f"Critical count: {summary['critical_count']}",
            f"High count: {summary['high_count']}",
            "",
            "Affected versions:",
            *[f"- {version}" for version in summary["versions"][:20]],
            "",
            "Top vulnerabilities:",
            *[f"- {name}: {count}" for name, count in summary["top_vulnerabilities"]],
            "",
            "Top components:",
            *[f"- {name}: {count}" for name, count in summary["top_components"] if name],
        ]

        if summary["policies"]:
            lines.extend(
                [
                    "",
                    "Matched policies:",
                    *[f"- {name}" for name in summary["policies"][:20]],
                ]
            )

        text = "\n".join(lines)
        alert_type = "error"
        status_tag = "bd_status:open"

    tags = base_tags(args) + [
        "bd_group:project",
        f"bd_project:{normalize_tag(project)}",
        status_tag,
    ]

    return {
        "title": title[:4000],
        "text": text[:4000],
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

    if resolved:
        title = f"[Black Duck] Resolved: {vulnerability} in {component} - {project}"
        text = (
            "Finding disappeared from latest Black Duck pull.\n\n"
            f"Finding ID: {finding.get('finding_external_id', '')}"
        )
        alert_type = "success"
        status_tag = "bd_status:resolved"
    else:
        title = f"[Black Duck] {finding.get('severity', '')} {vulnerability} in {component} - {project}"

        text = "\n".join(
            [
                f"Project: {project}",
                f"Version: {finding.get('project_version', '')}",
                f"Component: {component}",
                f"Component version: {finding.get('component_version', '')}",
                f"Vulnerability: {vulnerability}",
                f"Severity: {finding.get('severity', '')}",
                f"Score: {finding.get('score', '')}",
                f"Exploit available: {finding.get('exploit_available', '')}",
                f"Reachable: {finding.get('reachable', '')}",
                f"Policy: {finding.get('policy_name', '')}",
                "",
                f"Black Duck URL: {finding.get('blackduck_url', '')}",
                f"Finding ID: {finding.get('finding_external_id', '')}",
            ]
        )
        alert_type = "error"
        status_tag = "bd_status:open"

    tags = base_tags(args) + [
        "bd_group:finding",
        f"bd_project:{normalize_tag(project)}",
        f"bd_vulnerability:{normalize_tag(vulnerability)}",
        f"bd_component:{normalize_tag(component)}",
        f"bd_finding_id:{normalize_tag(finding.get('finding_external_id', ''))}",
        status_tag,
    ]

    return {
        "title": title[:4000],
        "text": text[:4000],
        "alert_type": alert_type,
        "source_type_name": args.source,
        "aggregation_key": f"bd_project_{group_id}",
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
    ):
        site = site.strip().rstrip("/")

        if site.startswith(("http://", "https://")):
            self.base_url = site
        else:
            self.base_url = f"https://api.{site}"

        self.api_key = api_key
        self.timeout = timeout
        self.retries = retries
        self.retry_delay = retry_delay
        self.debug = debug

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
                with urlopen(request, timeout=self.timeout) as response:
                    body = response.read().decode("utf-8", errors="replace")

                    if response.status not in {200, 202}:
                        raise RuntimeError(f"HTTP {response.status}: {body[:1000]}")

                    return json.loads(body) if body else {}

            except (HTTPError, URLError, TimeoutError, OSError, RuntimeError) as error:
                if isinstance(error, HTTPError):
                    body = error.read().decode("utf-8", errors="replace")
                    retryable = error.code in {429, 500, 502, 503, 504}
                    message = f"HTTP {error.code} {error.reason}: {body[:1000]}"
                else:
                    retryable = True
                    message = str(error)

                if not retryable or attempt >= self.retries:
                    raise RuntimeError(f"POST {url} failed: {message}") from error

                if self.debug:
                    print(f"Retrying Datadog event send: {message}", file=sys.stderr)

                time.sleep(self.retry_delay * (attempt + 1))

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


def process(args: argparse.Namespace) -> int:
    if args.destination != "events":
        raise RuntimeError("Only --destination events is currently implemented")

    findings = load_findings(args.findings)
    state = load_state(args.state)
    grouped = group_findings(findings)
    dry_run = args.dry_run or not args.apply

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
        )

    desired_events: list[tuple[str, str, dict[str, Any], list[dict[str, str]], dict[str, str] | None]] = []

    if args.event_mode in {"project", "both"}:
        for group_id, group_rows in grouped.items():
            existing = state.setdefault("groups_by_external_id", {}).get(group_id)

            if isinstance(existing, dict) and existing.get("status") == "active" and not args.refresh_existing:
                update_group_state(state, group_id, group_rows, "active", "seen_existing_state")
            else:
                desired_events.append(
                    (
                        "project",
                        f"project_open:{group_id}",
                        project_event(group_id, group_rows, args),
                        group_rows,
                        None,
                    )
                )

    if args.event_mode in {"finding", "both"}:
        for finding in findings:
            finding_id = finding["finding_external_id"]
            existing = state.setdefault("findings_by_external_id", {}).get(finding_id)

            if isinstance(existing, dict) and existing.get("status") == "active" and not args.refresh_existing:
                update_finding_state(state, finding, "active", "seen_existing_state")
            else:
                desired_events.append(
                    (
                        "finding",
                        f"finding_open:{finding_id}",
                        finding_event(finding, args),
                        [],
                        finding,
                    )
                )

    current_finding_ids = {finding["finding_external_id"] for finding in findings}
    current_group_ids = set(grouped)

    if args.send_resolved:
        previous_findings = state.setdefault("findings_by_external_id", {})

        for finding_id, previous in list(previous_findings.items()):
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
                desired_events.append(
                    (
                        "finding",
                        f"finding_resolved:{finding_id}",
                        finding_event(previous_as_row, args, resolved=True),
                        [],
                        previous_as_row,
                    )
                )
            else:
                update_finding_state(state, previous_as_row, "resolved", "resolved_without_event")

        previous_groups = state.setdefault("groups_by_external_id", {})

        for group_id, previous in list(previous_groups.items()):
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

            desired_events.append(
                (
                    "project",
                    f"project_resolved:{group_id}",
                    project_event(group_id, [pseudo], args, resolved=True),
                    [pseudo],
                    None,
                )
            )

    if args.max_send is not None:
        desired_events = desired_events[: args.max_send]

    results: list[dict[str, Any]] = []
    errors = 0
    sent = 0

    for mode, event_key, payload, group_rows, finding in desired_events:
        source_row = finding or (group_rows[0] if group_rows else {})

        result = {
            "action": "would_send" if dry_run else "send",
            "event_mode": mode,
            "event_key": event_key,
            "datadog_event_id": "",
            "project": source_row.get("project", ""),
            "project_group_external_id": source_row.get("project_group_external_id", ""),
            "finding_external_id": source_row.get("finding_external_id", ""),
            "vulnerability": source_row.get("vulnerability", ""),
            "severity": source_row.get("severity", ""),
            "score": source_row.get("score", ""),
            "message": payload.get("title", ""),
        }

        if dry_run:
            results.append(result)
            continue

        try:
            assert client is not None
            response = client.send_event(payload)
            record_event(state, event_key, payload, response, "sent")
            result["datadog_event_id"] = str(response.get("event", {}).get("id") or response.get("id") or "")
            result["action"] = "sent"
            sent += 1

            if event_key.startswith("project_open:"):
                update_group_state(state, event_key.split(":", 1)[1], group_rows, "active", "sent_open")
            elif event_key.startswith("project_resolved:"):
                update_group_state(state, event_key.split(":", 1)[1], group_rows, "resolved", "sent_resolved")
            elif event_key.startswith("finding_open:") and finding:
                update_finding_state(state, finding, "active", "sent_open")
            elif event_key.startswith("finding_resolved:") and finding:
                update_finding_state(state, finding, "resolved", "sent_resolved")

        except RuntimeError as error:
            result["action"] = "error"
            result["message"] = str(error)
            errors += 1

        results.append(result)

    if dry_run:
        for group_id, group_rows in grouped.items():
            update_group_state(state, group_id, group_rows, "active", "would_mark_active")

        for finding in findings:
            update_finding_state(state, finding, "active", "would_mark_active")
    else:
        save_state(args.state, state)

    write_json_file(
        args.plan_out,
        {
            "generated_at": now_iso(),
            "dry_run": dry_run,
            "destination": args.destination,
            "event_mode": args.event_mode,
            "event_count": len(desired_events),
            "events": [
                {
                    "event_key": event_key,
                    "payload": payload,
                }
                for _, event_key, payload, _, _ in desired_events
            ],
            "results": results,
        },
    )
    write_results(args.results_out, results)

    print()
    print("Datadog publish summary")
    print("=======================")
    print(f"Input findings:          {len(findings)}")
    print(f"Project groups:          {len(grouped)}")
    print(f"Dry run:                 {dry_run}")
    print(f"Would send:              {len(desired_events) if dry_run else 0}")
    print(f"Sent:                    {sent}")
    print(f"Errors:                  {errors}")

    if args.results_out:
        print(f"Results CSV:             {args.results_out}")

    if args.plan_out:
        print(f"Plan JSON:               {args.plan_out}")

    return 1 if errors else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Publish Black Duck high-risk vulnerability findings to Datadog Events."
    )
    parser.add_argument("--findings", default="policy_findings.csv")
    parser.add_argument("--destination", choices=["events"], default="events")
    parser.add_argument("--event-mode", choices=["project", "finding", "both"], default="project")
    parser.add_argument("--site", default="datadoghq.com")
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


def main() -> int:
    args = parse_args()

    try:
        validate_args(args)
        return process(args)
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
