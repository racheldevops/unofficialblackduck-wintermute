from __future__ import annotations

import pytest

from wintermute.scm.evidence import (
    EvidenceInventory,
    EvidenceKind,
    EvidenceObservation,
    EvidenceScope,
    canonical_value,
    evidence_inventory_payload,
)


def observation(
    *,
    key: str = "policy",
) -> EvidenceObservation:
    return EvidenceObservation(
        provider="GitHub",
        provider_instance=(
            "https://github.example/"
        ),
        tenant_id="O_acme",
        kind=(
            EvidenceKind
            .REPOSITORY_CUSTOM_PROPERTY
        ),
        scope=EvidenceScope.REPOSITORY,
        key=key,
        source=(
            "github-custom-property-value"
        ),
        repository_external_id=(
            "repository-a"
        ),
        name_with_owner="acme/service",
        attributes=(
            (
                "value",
                canonical_value(
                    ["required"]
                ),
            ),
        ),
    )


def test_evidence_identity_is_stable() -> None:
    first = observation()
    second = observation()

    assert first.identity_key == (
        second.identity_key
    )
    assert first.external_id == (
        second.external_id
    )
    assert first.provider == "github"
    assert first.provider_instance == (
        "github.example"
    )


def test_evidence_payload_is_deterministic() -> None:
    payload = evidence_inventory_payload(
        EvidenceInventory(
            observations=(
                observation(key="z"),
                observation(key="a"),
            )
        )
    )

    assert [
        value["key"]
        for value in payload["observations"]
    ] == ["a", "z"]
    assert payload["observation_count"] == 2
    assert payload["failure_count"] == 0


def test_evidence_rejects_duplicate_identity() -> None:
    value = observation()

    with pytest.raises(
        ValueError,
        match="duplicate",
    ):
        EvidenceInventory(
            observations=(value, value)
        )


def test_repository_evidence_requires_name() -> None:
    with pytest.raises(
        ValueError,
        match="name_with_owner",
    ):
        EvidenceObservation(
            provider="github",
            provider_instance=(
                "github.example"
            ),
            tenant_id="O_acme",
            kind=(
                EvidenceKind
                .REPOSITORY_CUSTOM_PROPERTY
            ),
            scope=(
                EvidenceScope.REPOSITORY
            ),
            key="policy",
            source="test",
        )
