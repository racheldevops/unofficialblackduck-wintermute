from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from wintermute.blackduck.actions import (
    ActionArtifactError,
    ActionEvidence,
    ActionLimits,
    ActionOwnership,
    ActionPlan,
    ActionTarget,
    BlackDuckAction,
    load_verified_action_plan,
    write_action_plan,
)
from wintermute.blackduck.actions.models import (
    stable_digest,
)


BASE_URL = "https://blackduck.example.invalid"


def example_action() -> BlackDuckAction:
    evidence = {
        "cip_tag": "v6.1.173-cip56",
        "tag_commit": "a" * 40,
        "fix_commits": ["b" * 40],
    }

    return BlackDuckAction.build(
        kind="vulnerability-remediation.set",
        target=ActionTarget(
            resource_type="bom-vulnerability",
            resource_href=(
                f"{BASE_URL}/api/projects/project"
                "/versions/version/components/component"
                "/vulnerabilities/CVE-2026-0001"
            ),
            project_version_href=(
                f"{BASE_URL}/api/projects/project"
                "/versions/version"
            ),
            identifiers={
                "vulnerability": "CVE-2026-0001",
                "component_version": (
                    "v6.1.173-cip56"
                ),
            },
        ),
        observed={
            "remediation_status": "NEW",
        },
        desired={
            "remediation_status": "PATCHED",
            "comment": (
                "CIP fix is included in the "
                "configured release tag."
            ),
        },
        ownership=ActionOwnership(
            producer="cip-remediation",
            marker="wintermute:cip:v1",
        ),
        evidence=ActionEvidence(
            provider="cip-kernel-sec",
            subject="CVE-2026-0001",
            revision="c" * 40,
            digest=stable_digest(evidence),
            details=evidence,
        ),
        reason=(
            "Required fixes are present in the "
            "configured CIP release."
        ),
    )


def example_plan(
    *,
    created_at: datetime | None = None,
    expires_in_hours: int = 24,
) -> ActionPlan:
    return ActionPlan.create(
        producer="cip-remediation",
        producer_version="1",
        blackduck_base_url=BASE_URL,
        actions=(example_action(),),
        limits=ActionLimits(
            maximum_actions=10,
            maximum_blackduck_reads=100,
            maximum_blackduck_writes=10,
        ),
        metadata={
            "configuration_digest": stable_digest(
                {"targets": 1}
            ),
        },
        created_at=created_at,
        expires_in_hours=expires_in_hours,
    )


def test_action_identity_is_deterministic() -> None:
    first = example_action()
    second = example_action()

    assert first.action_id == second.action_id
    assert (
        first.observed_fingerprint
        == second.observed_fingerprint
    )


def test_plan_rejects_cross_instance_target() -> None:
    source = example_action()
    action = BlackDuckAction.build(
        kind=source.kind,
        target=ActionTarget(
            resource_type=(
                source.target.resource_type
            ),
            resource_href=(
                "https://other.example.invalid"
                "/api/resource"
            ),
            project_version_href=(
                source.target.project_version_href
            ),
            identifiers=(
                source.target.identifiers
            ),
        ),
        observed=source.observed,
        desired=source.desired,
        ownership=source.ownership,
        evidence=source.evidence,
        reason=source.reason,
    )

    with pytest.raises(
        ValueError,
        match="another Black Duck instance",
    ):
        ActionPlan.create(
            producer="cip-remediation",
            producer_version="1",
            blackduck_base_url=BASE_URL,
            actions=(action,),
        )


def test_action_plan_round_trip(
    tmp_path,
) -> None:
    plan = example_plan()
    path = write_action_plan(
        tmp_path,
        plan,
        attachments={
            "evidence.json": {
                "assessment_count": 1,
            },
        },
    )

    assert load_verified_action_plan(path) == plan


def test_modified_plan_is_rejected(
    tmp_path,
) -> None:
    path = write_action_plan(
        tmp_path,
        example_plan(),
    )
    plan_path = path / "plan.json"
    payload = json.loads(
        plan_path.read_text(encoding="utf-8")
    )
    payload["actions"][0]["desired"][
        "remediation_status"
    ] = "IGNORED"
    plan_path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    with pytest.raises(
        ActionArtifactError,
        match="Checksum mismatch",
    ):
        load_verified_action_plan(path)


def test_expired_plan_is_rejected(
    tmp_path,
) -> None:
    plan = example_plan(
        created_at=(
            datetime.now(timezone.utc)
            - timedelta(days=2)
        ),
        expires_in_hours=1,
    )
    path = write_action_plan(
        tmp_path,
        plan,
    )

    with pytest.raises(
        ActionArtifactError,
        match="expired",
    ):
        load_verified_action_plan(path)
