from __future__ import annotations

from typing import Any

from wintermute.blackduck.candidates import (
    CandidateDiscoveryCriteria,
    candidate_cache_settings,
    candidate_external_id,
    candidate_key,
    scan_candidate,
    stable_candidate,
)


PROJECT_HREF = (
    "https://bd.example/api/projects/service"
)
VERSION_HREF = (
    f"{PROJECT_HREF}/versions/1"
)


def project() -> dict[str, Any]:
    return {
        "name": "Service",
        "_meta": {"href": PROJECT_HREF},
    }


def version() -> dict[str, Any]:
    return {
        "versionName": "1.0",
        "phase": "RELEASED",
        "updatedAt": "2026-08-01T00:00:00Z",
        "_meta": {"href": VERSION_HREF},
    }


def test_candidate_identity_is_stable() -> None:
    key = candidate_key(
        "Service",
        "1.0",
        f"{VERSION_HREF}/",
    )

    assert key == (
        f"Service|1.0|{VERSION_HREF}"
    )
    assert candidate_external_id(
        "Service",
        "1.0",
        VERSION_HREF,
    ) == candidate_external_id(
        "Service",
        "1.0",
        f"{VERSION_HREF}/",
    )


def test_candidate_scan_uses_requested_mode() -> None:
    criteria = CandidateDiscoveryCriteria(
        candidate_mode="both",
    )
    calls: list[str] = []

    def count_vulnerable(
        client: Any,
        version_resource: dict[str, Any],
        href: str,
    ) -> int:
        del client, version_resource
        calls.append(f"vulnerable:{href}")
        return 2

    def count_policy(
        client: Any,
        href: str,
        settings: Any,
    ) -> tuple[int, int, str, str]:
        del client, settings
        calls.append(f"policy:{href}")
        return 1, 1, "Security", "rule"

    row = scan_candidate(
        object(),
        project(),
        version(),
        criteria,
        vulnerable_counter=count_vulnerable,
        policy_counter=count_policy,
    )

    assert calls == [
        f"vulnerable:{VERSION_HREF}",
        f"policy:{VERSION_HREF}",
    ]
    assert row[
        "candidate_vulnerable_component_count"
    ] == "2"
    assert row[
        "candidate_policy_violation_count"
    ] == "1"
    assert row[
        "candidate_security_violation_count"
    ] == "1"
    assert row["candidate_reason"] == (
        "policy-violation;"
        "security-policy-violation;"
        "vulnerable-bom-components"
    )


def test_requested_policy_must_match() -> None:
    criteria = CandidateDiscoveryCriteria(
        candidate_mode="both",
        policy_name="Required Policy",
    )

    row = scan_candidate(
        object(),
        project(),
        version(),
        criteria,
        vulnerable_counter=lambda *args: 3,
        policy_counter=lambda *args: (
            1,
            1,
            "",
            "",
        ),
    )

    assert row["candidate_reason"] == ""


def test_candidate_cache_settings_are_destination_neutral() -> None:
    criteria = CandidateDiscoveryCriteria(
        candidate_mode="policy-only",
        policy_name="Policy",
    )

    assert candidate_cache_settings(
        criteria
    ) == {
        "candidate_mode": "policy-only",
        "policy_name": "Policy",
        "policy_rule_id": "",
        "skip_policy_rules": False,
    }


def test_stable_candidate_ignores_runtime_fields() -> None:
    first = {
        "candidate_external_id": "id",
        "project": "Service",
        "candidate_reason": "reason",
        "candidate_detected_at": "first",
        "scan_error": "",
    }
    second = {
        **first,
        "candidate_detected_at": "second",
    }

    assert stable_candidate(first) == (
        stable_candidate(second)
    )
