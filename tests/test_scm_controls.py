from __future__ import annotations

import pytest

from wintermute.scm.controls import (
    ControlInventory,
    ControlKind,
    ControlObservation,
    ControlState,
    control_inventory_payload,
)


def observation(
    control: ControlKind,
    state: ControlState,
) -> ControlObservation:
    return ControlObservation(
        provider="GitHub",
        provider_instance=(
            "https://github.example/"
        ),
        tenant_id="O_acme",
        repository_external_id="repository-a",
        name_with_owner="acme/service",
        control=control,
        state=state,
        source="github-ruleset",
        attributes=(
            ("ruleset", "42"),
        ),
    )


def test_control_observation_normalizes_identity() -> None:
    value = observation(
        ControlKind.REQUIRED_SCAN_WORKFLOW,
        ControlState.COMPLIANT,
    )

    assert value.provider == "github"
    assert value.provider_instance == (
        "github.example"
    )
    assert len(value.external_id) == 64


def test_control_payload_is_deterministic() -> None:
    inventory = ControlInventory(
        observations=(
            observation(
                ControlKind.REQUIRED_SCAN_WORKFLOW,
                ControlState.COMPLIANT,
            ),
            observation(
                ControlKind.ONBOARDING_POLICY,
                ControlState.COMPLIANT,
            ),
        )
    )
    payload = control_inventory_payload(
        inventory
    )

    assert [
        item["control"]
        for item in payload["observations"]
    ] == [
        "onboarding-policy",
        "required-scan-workflow",
    ]
    assert payload["observation_count"] == 2
    assert payload["failure_count"] == 0


def test_control_inventory_rejects_duplicates() -> None:
    value = observation(
        ControlKind.ONBOARDING_POLICY,
        ControlState.COMPLIANT,
    )

    with pytest.raises(
        ValueError,
        match="duplicate",
    ):
        ControlInventory(
            observations=(value, value)
        )
