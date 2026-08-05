from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

import pytest

from harness.datadog import policy_vuln_pull as puller


VERSION_HREF = (
    "https://bd.example/api/projects/project-a/versions/version-a"
)


def candidate(**overrides: str) -> dict[str, str]:
    row = {
        "project": "Service A",
        "project_version": "1.0",
        "project_href": "https://bd.example/api/projects/project-a",
        "project_version_href": VERSION_HREF,
        "candidate_key": f"Service A|1.0|{VERSION_HREF}",
        "candidate_external_id": "candidate-a",
    }
    row.update(overrides)
    return row


def settings(**overrides: Any) -> puller.PullSettings:
    values: dict[str, Any] = {
        "base_url": "https://bd.example",
        "api_token": "token",
        "bearer_token": "bearer",
        "insecure": False,
        "timeout": 30,
        "retries": 1,
        "retry_delay": 0.0,
        "page_limit": 100,
        "debug": False,
        "threshold": 8.9,
        "score_operator": "gt",
        "score_field": "overallScore",
        "require_exploit_available": True,
        "require_reachable": False,
        "reachability_mode": "field",
        "policy_name": "",
        "policy_rule_id": "",
        "group_by": "project",
        "skip_policy_rules": False,
        "include_policy_rule_details": False,
        "component_workers": 1,
    }
    values.update(overrides)
    return puller.PullSettings(**values)


def state_args(**overrides: Any) -> argparse.Namespace:
    values: dict[str, Any] = {
        "bd_url": "https://bd.example",
        "threshold": 8.9,
        "score_operator": "gt",
        "score_field": "overallScore",
        "require_exploit_available": True,
        "require_reachable": False,
        "reachability_mode": "field",
        "policy_name": None,
        "policy_rule_id": None,
        "group_by": "project",
        "skip_policy_rules": False,
        "include_policy_rule_details": False,
        "resume": True,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def valid_args(**overrides: Any) -> argparse.Namespace:
    values: dict[str, Any] = {
        "timeout": 30,
        "retries": 1,
        "retry_delay": 2.0,
        "page_limit": 100,
        "api_cache_max_age_hours": 20.0,
        "api_cache_max_entries": 5000,
        "limit_candidates": None,
        "limit_findings": None,
        "workers": 4,
        "component_workers": 1,
        "progress_every": 10,
        "heartbeat_every": 60.0,
        "cache_save_every": 25,
        "max_runtime_minutes": None,
        "policy_name": None,
        "policy_rule_id": None,
        "skip_policy_rules": False,
        "shard_count": 1,
        "out": "findings.csv",
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_boolish_and_reachability_parsing() -> None:
    for value in (
        True,
        "true",
        "yes",
        "available",
        "reachable",
        "confirmed",
    ):
        assert puller.boolish(value) is True

    assert puller.boolish("false") is False
    assert puller.extract_reachability(
        {"reachabilityStatus": "reachable"}
    ) == (True, "reachable", "field")


def test_exploit_detection_uses_direct_and_nested_fields() -> None:
    assert puller.extract_exploit_available(
        {"exploitAvailable": True}
    ) == (True, "True")

    available, raw = puller.extract_exploit_available(
        {"metadata": {"exploitAvailable": "available"}}
    )
    assert available is True
    assert raw == "available"

    assert puller.extract_exploit_available({}) == (False, "")


def test_extract_vulnerability_candidates_supports_nested_data() -> None:
    payload = {
        "wrapper": {
            "vulnerability": {
                "vulnerabilityName": "CVE-2026-0001",
                "overallScore": 9.8,
                "severity": "CRITICAL",
            },
            "exploitAvailable": True,
        }
    }

    rows = puller.extract_vulnerability_candidates(
        payload,
        "overallScore",
    )

    assert rows
    assert {
        puller.vulnerability_identifier(row)
        for row in rows
    } == {"CVE-2026-0001"}


@pytest.mark.parametrize(
    ("operator", "score", "expected"),
    [
        ("gt", 9.0, True),
        ("gt", 8.9, False),
        ("gte", 8.9, True),
        ("gte", 8.8, False),
        ("gte", None, False),
    ],
)
def test_score_filtering(
    operator: str,
    score: float | None,
    expected: bool,
) -> None:
    assert puller.score_passes(
        score,
        settings(score_operator=operator),
    ) is expected


def test_candidate_identity_prefers_external_id() -> None:
    assert puller.candidate_identity(candidate()) == "candidate-a"

    without_id = candidate(
        candidate_external_id="",
        candidate_key="explicit-key",
    )
    assert puller.candidate_identity(without_id) == puller.sha256_hex(
        "explicit-key"
    )


def test_candidate_filters() -> None:
    args = argparse.Namespace(
        project_name=None,
        project_name_contains="service",
        version_name="1.0",
        only_candidate_external_id="candidate-a",
    )

    assert puller.candidate_matches(candidate(), args) is True
    assert puller.candidate_matches(
        candidate(project="Other"),
        args,
    ) is False


def test_api_cache_returns_deep_copies(tmp_path: Path) -> None:
    cache = puller.ApiResponseCache(
        path=str(tmp_path / "cache.json"),
        base_url="https://bd.example",
        max_age_hours=-1,
        max_entries=10,
        refresh=True,
    )
    cache.put_items(
        "https://bd.example/items",
        [{"nested": {"value": 1}}],
    )

    first = cache.get_items("https://bd.example/items")
    assert first is not None
    first[0]["nested"]["value"] = 99

    assert cache.get_items(
        "https://bd.example/items"
    ) == [{"nested": {"value": 1}}]


def test_api_cache_prunes_old_entries(tmp_path: Path) -> None:
    cache = puller.ApiResponseCache(
        path=str(tmp_path / "cache.json"),
        base_url="https://bd.example",
        max_age_hours=-1,
        max_entries=2,
        refresh=True,
    )
    cache.data["entries"] = {
        "old": {
            "last_used_at": "2026-01-01T00:00:00Z",
            "cached_at": "2026-01-01T00:00:00Z",
            "items": [],
        },
        "middle": {
            "last_used_at": "2026-01-02T00:00:00Z",
            "cached_at": "2026-01-02T00:00:00Z",
            "items": [],
        },
        "new": {
            "last_used_at": "2026-01-03T00:00:00Z",
            "cached_at": "2026-01-03T00:00:00Z",
            "items": [],
        },
    }

    cache.prune()

    assert set(cache.data["entries"]) == {"middle", "new"}


def test_policy_match_supports_name_and_rule_id() -> None:
    rules = [
        {
            "name": "Security Policy",
            "_meta": {
                "href": "https://bd.example/policy-rules/rule-123"
            },
        }
    ]

    assert puller.policy_match(
        rules,
        settings(policy_name="Security Policy"),
    ) == (
        True,
        "Security Policy",
        "https://bd.example/policy-rules/rule-123",
    )

    assert puller.policy_match(
        rules,
        settings(policy_rule_id="rule-123"),
    )[0] is True

    assert puller.policy_match(
        rules,
        settings(policy_name="Missing"),
    ) == (False, "", "")


def test_should_fetch_policy_rules_respects_settings() -> None:
    assert puller.should_fetch_policy_rules(
        settings(skip_policy_rules=True)
    ) is False
    assert puller.should_fetch_policy_rules(
        settings(policy_name="Policy")
    ) is True
    assert puller.should_fetch_policy_rules(
        settings(include_policy_rule_details=True)
    ) is True
    assert puller.should_fetch_policy_rules(settings()) is False


def test_collect_for_component_builds_normalized_finding() -> None:
    component = {
        "componentName": "openssl",
        "componentVersionName": "3.0.1",
        "componentOriginId": "origin-a",
        "_meta": {
            "href": "https://bd.example/components/openssl",
            "links": [
                {
                    "rel": "vulnerabilities",
                    "href": (
                        "https://bd.example/components/openssl/"
                        "vulnerabilities"
                    ),
                }
            ],
        },
    }

    class Client:
        def paged_get(
            self,
            path: str,
        ) -> list[dict[str, Any]]:
            assert path.endswith("/vulnerabilities")
            return [
                {
                    "vulnerabilityName": "CVE-2026-0001",
                    "overallScore": 9.8,
                    "severity": "CRITICAL",
                    "exploitAvailable": True,
                    "reachable": True,
                    "_meta": {
                        "href": (
                            "https://bd.example/vulnerabilities/"
                            "CVE-2026-0001"
                        )
                    },
                }
            ]

    result = puller.collect_for_component(
        Client(),
        candidate(),
        component,
        settings(
            require_exploit_available=True,
            require_reachable=True,
        ),
        fetch_policy_rules=False,
    )

    assert result.failures == []
    assert len(result.findings) == 1

    row = result.findings[0]
    assert row["project"] == "Service A"
    assert row["component"] == "openssl"
    assert row["component_version"] == "3.0.1"
    assert row["vulnerability"] == "CVE-2026-0001"
    assert row["score"] == "9.8"
    assert row["exploit_available"] == "true"
    assert row["reachable"] == "true"
    assert row["project_group_key"] == "Service A"
    assert row["finding_external_id"] == puller.sha256_hex(
        row["finding_key"]
    )


def test_collect_for_component_applies_exploit_filter() -> None:
    component = {
        "componentName": "library",
        "componentVersionName": "1",
        "_meta": {
            "links": [
                {
                    "rel": "vulnerabilities",
                    "href": "https://bd.example/vulnerabilities",
                }
            ]
        },
    }

    class Client:
        def paged_get(self, path: str) -> list[dict[str, Any]]:
            del path
            return [
                {
                    "vulnerabilityName": "CVE-1",
                    "overallScore": 10.0,
                    "severity": "CRITICAL",
                    "exploitAvailable": False,
                }
            ]

    result = puller.collect_for_component(
        Client(),
        candidate(),
        component,
        settings(require_exploit_available=True),
        fetch_policy_rules=False,
    )

    assert result.findings == []
    assert result.failures == []


def test_collect_candidate_supports_component_workers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    components = [
        {"id": "a"},
        {"id": "b"},
    ]
    monkeypatch.setattr(
        puller,
        "get_vulnerable_components",
        lambda *_: components,
    )

    def fake_collect(
        client: Any,
        candidate_row: dict[str, str],
        component: dict[str, Any],
        pull_settings: puller.PullSettings,
        fetch_policy_rules: bool,
    ) -> puller.ComponentPullResult:
        del client, candidate_row, pull_settings, fetch_policy_rules
        return puller.ComponentPullResult(
            findings=[
                {
                    "finding_external_id": component["id"],
                }
            ],
            failures=[],
        )

    monkeypatch.setattr(
        puller,
        "collect_for_component",
        fake_collect,
    )

    findings, failures = puller.collect_for_candidate(
        object(),
        candidate(),
        settings(component_workers=2),
    )

    assert {
        row["finding_external_id"]
        for row in findings
    } == {"a", "b"}
    assert failures == []


def test_auth_failure_detection() -> None:
    result = puller.CandidatePullResult(
        index=1,
        candidate=candidate(),
        findings=[],
        failures=[
            {
                "error": "HTTP 401 Unauthorized",
            }
        ],
        elapsed_seconds=0,
        status="partial",
    )

    assert puller.result_has_auth_failures(result) is True
    assert puller.is_auth_failure_text(
        "bearer-token refresh failed"
    ) is True
    assert puller.is_auth_failure_text("timeout") is False


def test_pull_candidate_retries_auth_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    authenticated = 0

    class Client:
        def authenticate(self) -> None:
            nonlocal authenticated
            authenticated += 1

    monkeypatch.setattr(
        puller,
        "build_candidate_client",
        lambda *_: Client(),
    )

    def fake_collect(
        client: Any,
        candidate_row: dict[str, str],
        pull_settings: puller.PullSettings,
    ) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
        del client, candidate_row, pull_settings
        nonlocal calls
        calls += 1

        if calls == 1:
            raise RuntimeError("HTTP 401 Unauthorized")

        return [{"finding_external_id": "finding-a"}], []

    monkeypatch.setattr(
        puller,
        "collect_for_candidate",
        fake_collect,
    )
    monkeypatch.setattr(puller.time, "sleep", lambda _: None)

    result = puller.pull_one_candidate(
        settings(retry_delay=0),
        None,
        puller.PullTarget(
            index=1,
            candidate=candidate(),
        ),
    )

    assert result.status == "ok"
    assert calls == 2
    assert authenticated == 1
    assert result.findings == [
        {"finding_external_id": "finding-a"}
    ]


def test_resume_state_restores_completed_findings() -> None:
    args = state_args()
    state = puller.fresh_state(args)
    result = puller.CandidatePullResult(
        index=1,
        candidate=candidate(),
        findings=[
            {
                "finding_external_id": "finding-a",
                "project": "Service A",
            }
        ],
        failures=[],
        elapsed_seconds=1.5,
        status="ok",
    )
    state["completed_candidates"]["candidate-a"] = (
        puller.state_entry_from_result(result)
    )

    findings, failures, finding_ids, candidate_ids = (
        puller.load_completed_from_state(
            state,
            [candidate()],
        )
    )

    assert findings == [
        {
            "finding_external_id": "finding-a",
            "project": "Service A",
        }
    ]
    assert failures == []
    assert finding_ids == {"finding-a"}
    assert candidate_ids == {"candidate-a"}


def test_state_signature_changes_with_filter_settings() -> None:
    first = puller.settings_signature(state_args())
    second = puller.settings_signature(
        state_args(threshold=9.5)
    )

    assert first != second


def test_merge_findings_deduplicates_shards(
    tmp_path: Path,
) -> None:
    first_path = tmp_path / "first.csv"
    second_path = tmp_path / "second.csv"
    output_path = tmp_path / "merged.csv"

    first = {
        "project": "Service A",
        "project_version": "1.0",
        "finding_external_id": "finding-a",
        "score": "9.8",
    }
    second = {
        "project": "Service B",
        "project_version": "2.0",
        "finding_external_id": "finding-b",
        "score": "9.0",
    }

    puller.write_findings(
        str(first_path),
        [first],
        json_mode=False,
    )
    puller.write_findings(
        str(second_path),
        [first, second],
        json_mode=False,
    )

    count = puller.merge_findings_files(
        [str(first_path), str(second_path)],
        str(output_path),
        json_mode=False,
    )

    assert count == 2

    with output_path.open(
        newline="",
        encoding="utf-8",
    ) as input_file:
        rows = list(csv.DictReader(input_file))

    assert {
        row["finding_external_id"]
        for row in rows
    } == {"finding-a", "finding-b"}


def test_validate_args_clamps_concurrency_limits() -> None:
    args = valid_args(
        workers=100,
        component_workers=100,
        shard_count=100,
    )

    puller.validate_args(args)

    assert args.workers == puller.MAX_WORKERS
    assert args.component_workers == puller.MAX_COMPONENT_WORKERS
    assert args.shard_count == 32


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"timeout": 0}, "timeout"),
        ({"workers": 0}, "workers"),
        ({"component_workers": 0}, "component-workers"),
        ({"progress_every": 0}, "progress-every"),
        ({"heartbeat_every": -1}, "heartbeat-every"),
        ({"shard_count": 0}, "shard-count"),
        (
            {
                "policy_name": "Policy",
                "skip_policy_rules": True,
            },
            "skip-policy-rules",
        ),
        (
            {
                "shard_count": 2,
                "out": "-",
            },
            "shard-count",
        ),
    ],
)
def test_validate_args_rejects_invalid_values(
    override: dict[str, Any],
    message: str,
) -> None:
    args = valid_args(**override)

    with pytest.raises(RuntimeError, match=message):
        puller.validate_args(args)
