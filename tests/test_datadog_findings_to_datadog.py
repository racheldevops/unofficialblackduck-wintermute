from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

import pytest

from wintermute.datadog import findings_to_datadog as datadog


def finding(**overrides: str) -> dict[str, str]:
    row = {
        "project": "Service A",
        "project_version": "1.0",
        "project_href": "https://bd.example/api/projects/a",
        "project_version_href": (
            "https://bd.example/api/projects/a/versions/1"
        ),
        "project_group_key": "Service A",
        "project_group_external_id": "group-a",
        "candidate_key": "Service A|1.0",
        "candidate_external_id": "candidate-a",
        "component": "openssl",
        "component_version": "3.0.1",
        "component_origin_id": "origin-a",
        "vulnerability": "CVE-2026-0001",
        "severity": "CRITICAL",
        "score_field": "overallScore",
        "score": "9.8",
        "exploit_available": "true",
        "exploitable": "true",
        "reachable": "true",
        "reachability": "reachable",
        "reachability_source": "field",
        "policy_name": "Security Policy",
        "policy_rule_href": "https://bd.example/policy/rule",
        "policy_matched": "true",
        "blackduck_url": (
            "https://bd.example/vulnerabilities/CVE-2026-0001"
        ),
        "bom_component_url": "https://bd.example/components/a",
        "finding_key": (
            "Service A|1.0|openssl|3.0.1|CVE-2026-0001"
        ),
        "finding_external_id": "finding-a",
        "first_seen_source": "test",
    }
    row.update(overrides)
    return row


def event_args(**overrides: Any) -> argparse.Namespace:
    values: dict[str, Any] = {
        "source": "blackduck",
        "service": "blackduck",
        "env": "test",
        "tags": "team:security, owner:appsec",
        "event_project_limit": 25,
        "event_component_limit": 8,
        "event_finding_limit": 3,
        "event_vulnerability_link_limit": 3,
        "event_mode": "vulnerability",
        "refresh_existing": False,
        "send_resolved": True,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def process_args(tmp_path: Path, findings_path: Path) -> argparse.Namespace:
    return argparse.Namespace(
        findings=str(findings_path),
        destination="events",
        event_mode="vulnerability",
        site="datadoghq.com",
        insecure=False,
        api_key_env="DATADOG_API_KEY",
        service="blackduck",
        source="blackduck",
        env="test",
        tags="team:security",
        state=str(tmp_path / "state.json"),
        results_out=str(tmp_path / "results.csv"),
        plan_out=str(tmp_path / "plan.json"),
        apply=False,
        dry_run=True,
        refresh_existing=False,
        send_resolved=True,
        max_send=None,
        event_project_limit=25,
        event_component_limit=8,
        event_finding_limit=3,
        event_vulnerability_link_limit=3,
        progress_every=0,
        checkpoint_every=0,
        fail_fast=False,
        timeout=30,
        retries=2,
        retry_delay=2.0,
        debug=False,
    )


def write_findings_csv(
    path: Path,
    rows: list[dict[str, str]],
) -> None:
    with path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(
            output_file,
            fieldnames=datadog.REQUIRED_FIELDS,
        )
        writer.writeheader()

        for row in rows:
            writer.writerow(
                {
                    field: row.get(field, "")
                    for field in datadog.REQUIRED_FIELDS
                }
            )


def test_normalize_tag_and_severity_mapping() -> None:
    assert datadog.normalize_tag(" Team / App Sec ") == "team_app_sec"
    assert datadog.normalize_tag("") == "unknown"
    assert datadog.severity_alert_type("critical") == "error"
    assert datadog.severity_alert_type("MEDIUM") == "warning"
    assert datadog.severity_alert_type("LOW") == "info"


def test_highest_severity_uses_known_order() -> None:
    rows = [
        finding(severity="LOW"),
        finding(severity="HIGH"),
        finding(severity="MEDIUM"),
    ]

    assert datadog.highest_severity_from_rows(rows) == "HIGH"
    assert datadog.highest_severity_from_rows([]) == "UNKNOWN"


def test_retry_after_parsing() -> None:
    assert datadog.parse_retry_after("2.5") == 2.5
    assert datadog.parse_retry_after("-1") is None
    assert datadog.parse_retry_after("invalid") is None
    assert datadog.parse_retry_after(None) is None


def test_load_findings_deduplicates_external_ids(
    tmp_path: Path,
) -> None:
    path = tmp_path / "findings.csv"
    write_findings_csv(
        path,
        [
            finding(),
            finding(project="Duplicate"),
            finding(finding_external_id=""),
            finding(finding_external_id="finding-b"),
        ],
    )

    rows = datadog.load_findings(str(path))

    assert [row["finding_external_id"] for row in rows] == [
        "finding-a",
        "finding-b",
    ]
    assert rows[0]["project"] == "Service A"


def test_load_findings_supports_json(tmp_path: Path) -> None:
    path = tmp_path / "findings.json"
    path.write_text(
        json.dumps(
            [
                finding(),
                finding(project="Duplicate"),
                "ignored",
            ]
        ),
        encoding="utf-8",
    )

    rows = datadog.load_findings(str(path))

    assert len(rows) == 1
    assert rows[0]["finding_external_id"] == "finding-a"


def test_load_findings_rejects_missing_csv_fields(
    tmp_path: Path,
) -> None:
    path = tmp_path / "invalid.csv"
    path.write_text("project\nService A\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="missing required field"):
        datadog.load_findings(str(path))


def test_fresh_state_has_all_required_sections() -> None:
    state = datadog.fresh_state()

    assert state["schema_version"] == datadog.STATE_SCHEMA_VERSION
    assert state["groups_by_external_id"] == {}
    assert state["findings_by_external_id"] == {}
    assert state["vulnerabilities_by_external_id"] == {}
    assert state["events_by_key"] == {}


def test_load_state_rejects_invalid_sections(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps(
            {
                "groups_by_external_id": [],
                "findings_by_external_id": {},
                "vulnerabilities_by_external_id": {},
                "events_by_key": {},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="groups_by_external_id"):
        datadog.load_state(str(path))


def test_grouping_is_deterministic() -> None:
    rows = [
        finding(
            finding_external_id="finding-b",
            component="zlib",
        ),
        finding(
            finding_external_id="finding-a",
            component="openssl",
        ),
        finding(
            finding_external_id="finding-c",
            project_group_external_id="group-b",
            project="Service B",
        ),
    ]

    grouped = datadog.group_findings(list(reversed(rows)))

    assert list(grouped) == ["group-a", "group-b"]
    assert [
        row["component"]
        for row in grouped["group-a"]
    ] == ["openssl", "zlib"]


def test_vulnerability_grouping_uses_stable_hash() -> None:
    rows = [
        finding(),
        finding(
            finding_external_id="finding-b",
            project="Service B",
        ),
    ]

    grouped = datadog.group_vulnerability_findings(rows)
    group_id = datadog.vulnerability_group_external_id(
        "CVE-2026-0001"
    )

    assert list(grouped) == [group_id]
    assert len(grouped[group_id]) == 2
    assert group_id == datadog.vulnerability_group_external_id(
        "CVE-2026-0001"
    )


def test_group_summary_aggregates_findings() -> None:
    rows = [
        finding(),
        finding(
            finding_external_id="finding-b",
            severity="HIGH",
            score="8.5",
            component="zlib",
            component_version="1.3",
            project_version="2.0",
        ),
    ]

    summary = datadog.summarize_group(rows)

    assert summary["finding_count"] == 2
    assert summary["max_score"] == 9.8
    assert summary["highest_severity"] == "CRITICAL"
    assert summary["critical_count"] == 1
    assert summary["high_count"] == 1
    assert summary["versions"] == ["1.0", "2.0"]


def test_vulnerability_event_respects_body_limits() -> None:
    rows = [
        finding(),
        finding(
            finding_external_id="finding-b",
            project="Service B",
            project_version="2.0",
            project_group_external_id="group-b",
            component="zlib",
            component_version="1.3",
        ),
    ]
    group_id = datadog.vulnerability_group_external_id(
        "CVE-2026-0001"
    )
    args = event_args(
        event_project_limit=1,
        event_component_limit=1,
        event_finding_limit=1,
        event_vulnerability_link_limit=1,
    )

    event = datadog.vulnerability_event(
        group_id,
        rows,
        args,
    )

    assert "affects 2 project version(s)" in event["title"]
    assert (
        "Affected Black Duck project versions shown: 1 of 2"
        in event["text"]
    )
    assert "and 1 more not shown" in event["text"]
    assert event["alert_type"] == "error"
    assert event["aggregation_key"] == (
        f"bd_vulnerability_{group_id}"
    )
    assert "bd_group:vulnerability" in event["tags"]
    assert "bd_status:open" in event["tags"]
    assert len(event["text"]) <= 4000


def test_resolved_events_are_success_events() -> None:
    args = event_args()
    group_id = datadog.vulnerability_group_external_id(
        "CVE-2026-0001"
    )

    event = datadog.vulnerability_event(
        group_id,
        [finding()],
        args,
        resolved=True,
    )

    assert event["alert_type"] == "success"
    assert "Resolved" in event["title"]
    assert "bd_status:resolved" in event["tags"]
    assert not any(
        tag.startswith("bd_severity:")
        for tag in event["tags"]
    )


def test_datadog_client_normalizes_site_urls() -> None:
    domain_client = datadog.DatadogClient(
        site="datadoghq.com",
        api_key="key",
        timeout=1,
        retries=0,
        retry_delay=0,
        debug=False,
    )
    full_url_client = datadog.DatadogClient(
        site="https://proxy.example/api/v1/events",
        api_key="key",
        timeout=1,
        retries=0,
        retry_delay=0,
        debug=False,
        insecure=True,
    )

    assert domain_client.base_url == "https://api.datadoghq.com"
    assert full_url_client.base_url == "https://proxy.example"
    assert full_url_client.ssl_context is not None


def test_plan_events_skips_active_vulnerability_state() -> None:
    rows = [finding()]
    grouped = datadog.group_findings(rows)
    vulnerability_id = datadog.vulnerability_group_external_id(
        "CVE-2026-0001"
    )
    state = datadog.fresh_state()
    state["vulnerabilities_by_external_id"][vulnerability_id] = {
        "status": "active",
        "vulnerability": "CVE-2026-0001",
    }
    results: list[dict[str, Any]] = []

    planned = datadog.plan_events(
        rows,
        grouped,
        state,
        event_args(
            event_mode="vulnerability",
            refresh_existing=False,
            send_resolved=False,
        ),
        results,
    )

    assert planned == []
    assert results[0]["action"] == "skip_existing_state"
    assert (
        state["vulnerabilities_by_external_id"][vulnerability_id][
            "last_action"
        ]
        == "seen_existing_state"
    )


def test_plan_events_creates_resolution_for_missing_vulnerability() -> None:
    vulnerability_id = datadog.vulnerability_group_external_id(
        "CVE-2026-0001"
    )
    state = datadog.fresh_state()
    state["vulnerabilities_by_external_id"][vulnerability_id] = {
        "status": "active",
        "vulnerability": "CVE-2026-0001",
        "severity": "CRITICAL",
    }

    planned = datadog.plan_events(
        [],
        {},
        state,
        event_args(
            event_mode="vulnerability",
            send_resolved=True,
        ),
        [],
    )

    assert len(planned) == 1
    assert planned[0].event_key == (
        f"vulnerability_resolved:{vulnerability_id}"
    )
    assert planned[0].payload["alert_type"] == "success"


def test_apply_max_send_records_skipped_events() -> None:
    args = event_args()
    planned = [
        datadog.PlannedEvent(
            mode="finding",
            event_key=f"finding_open:{index}",
            payload=datadog.finding_event(
                finding(finding_external_id=str(index)),
                args,
            ),
            group_rows=[],
            finding=finding(finding_external_id=str(index)),
        )
        for index in range(3)
    ]
    results: list[dict[str, Any]] = []

    selected = datadog.apply_max_send(
        planned,
        max_send=1,
        results=results,
    )

    assert len(selected) == 1
    assert len(results) == 2
    assert {
        row["action"]
        for row in results
    } == {"skip_max_send_reached"}


def test_state_updates_preserve_first_seen() -> None:
    state = datadog.fresh_state()

    datadog.update_finding_state(
        state,
        finding(),
        "active",
        "sent_open",
    )
    first_seen = state["findings_by_external_id"]["finding-a"][
        "first_seen_at"
    ]

    datadog.update_finding_state(
        state,
        finding(),
        "resolved",
        "sent_resolved",
    )

    entry = state["findings_by_external_id"]["finding-a"]
    assert entry["first_seen_at"] == first_seen
    assert entry["status"] == "resolved"
    assert entry["last_action"] == "sent_resolved"


def test_process_dry_run_writes_plan_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DATADOG_API_KEY", raising=False)
    findings_path = tmp_path / "findings.csv"
    write_findings_csv(findings_path, [finding()])
    args = process_args(tmp_path, findings_path)

    assert datadog.process(args) == 0

    plan = json.loads(
        (tmp_path / "plan.json").read_text(encoding="utf-8")
    )
    assert plan["dry_run"] is True
    assert plan["input_finding_count"] == 1
    assert plan["event_count"] == 1
    assert plan["results"][0]["action"] == "would_send"
    assert not (tmp_path / "state.json").exists()

    with (tmp_path / "results.csv").open(
        newline="",
        encoding="utf-8",
    ) as input_file:
        rows = list(csv.DictReader(input_file))

    assert len(rows) == 1
    assert rows[0]["action"] == "would_send"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("timeout", 0, "timeout"),
        ("retries", -1, "retries"),
        ("retry_delay", -1, "retry-delay"),
        ("max_send", 0, "max-send"),
        ("event_project_limit", -1, "event-project-limit"),
        ("progress_every", -1, "progress-every"),
    ],
)
def test_validate_args_rejects_invalid_values(
    field: str,
    value: Any,
    message: str,
) -> None:
    args = argparse.Namespace(
        timeout=30,
        retries=2,
        retry_delay=2.0,
        max_send=None,
        event_project_limit=25,
        event_component_limit=8,
        event_finding_limit=3,
        event_vulnerability_link_limit=3,
        progress_every=25,
        checkpoint_every=25,
    )
    setattr(args, field, value)

    with pytest.raises(RuntimeError, match=message):
        datadog.validate_args(args)


def test_datadog_eu_browser_site_maps_to_api() -> None:
    assert datadog.normalize_datadog_base_url(
        "app.datadoghq.eu"
    ) == "https://api.datadoghq.eu"
    assert datadog.normalize_datadog_base_url(
        "https://app.datadoghq.eu"
    ) == "https://api.datadoghq.eu"
    assert datadog.normalize_datadog_base_url(
        "datadoghq.eu"
    ) == "https://api.datadoghq.eu"


def test_datadog_environment_tls_setting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "DATADOG_INSECURE",
        "true",
    )

    assert datadog.environment_bool(
        "DATADOG_INSECURE"
    ) is True


def test_send_event_rejects_non_json_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self) -> bytes:
            return b"<html>proxy response</html>"

    monkeypatch.setattr(
        datadog,
        "urlopen",
        lambda *args, **kwargs: Response(),
    )
    client = datadog.DatadogClient(
        site="app.datadoghq.eu",
        api_key="x",
        timeout=1,
        retries=0,
        retry_delay=0,
        debug=False,
        insecure=True,
    )

    with pytest.raises(
        RuntimeError,
        match="non-JSON",
    ):
        client.send_event(
            {
                "title": "test",
                "text": "test",
            }
        )


def test_send_event_requires_event_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self) -> bytes:
            return b'{"status":"ok"}'

    monkeypatch.setattr(
        datadog,
        "urlopen",
        lambda *args, **kwargs: Response(),
    )
    client = datadog.DatadogClient(
        site="app.datadoghq.eu",
        api_key="x",
        timeout=1,
        retries=0,
        retry_delay=0,
        debug=False,
        insecure=True,
    )

    with pytest.raises(
        RuntimeError,
        match="event ID",
    ):
        client.send_event(
            {
                "title": "test",
                "text": "test",
            }
        )


def test_datadog_state_binds_to_site() -> None:
    state = datadog.fresh_state()

    datadog.bind_state_destination(
        state,
        "app.datadoghq.eu",
    )

    assert state["datadog_base_url"] == (
        "https://api.datadoghq.eu"
    )


def test_datadog_state_rejects_site_change() -> None:
    state = datadog.fresh_state()
    state["datadog_base_url"] = (
        "https://api.datadoghq.eu"
    )

    with pytest.raises(
        RuntimeError,
        match="state belongs to",
    ):
        datadog.bind_state_destination(
            state,
            "datadoghq.com",
        )
