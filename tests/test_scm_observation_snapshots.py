from __future__ import annotations

import json
from pathlib import Path

import pytest

from wintermute.scm.controls import (
    ControlInventory,
    ControlKind,
    ControlObservation,
    ControlState,
)
from wintermute.scm.evidence import (
    EvidenceInventory,
    EvidenceKind,
    EvidenceObservation,
    EvidenceScope,
)
from wintermute.scm.models import (
    Repository,
    RepositoryInventory,
    ScmTenant,
)
from wintermute.scm.observations import (
    ScmObservationResult,
)
from wintermute.scm.snapshots import (
    SnapshotError,
    load_inventory_snapshot,
    write_inventory_snapshot,
)


def tenant() -> ScmTenant:
    return ScmTenant(
        provider="github",
        provider_instance="github.example",
        tenant_id="O_acme",
        namespace="acme",
    )


def repository() -> Repository:
    return Repository(
        provider="github",
        provider_instance="github.example",
        tenant_id="O_acme",
        repository_id="R_service",
        namespace="acme",
        name="service",
        canonical_url=(
            "https://github.example/acme/service"
        ),
        default_branch="main",
        visibility="private",
        activity_status="active",
        languages=("python",),
    )


def inventory() -> RepositoryInventory:
    return RepositoryInventory(
        repositories=(repository(),),
        exclusions=(),
        failures=(),
        discovered_count=1,
    )


def observations() -> ScmObservationResult:
    current = repository()

    return ScmObservationResult(
        evidence=EvidenceInventory(
            observations=(
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
                    key="blackduck_sca_policy",
                    source=(
                        "github-custom-property-value"
                    ),
                    repository_external_id=(
                        current.external_id
                    ),
                    name_with_owner=(
                        current.name_with_owner
                    ),
                    attributes=(
                        ("value", '"required"'),
                    ),
                ),
            )
        ),
        controls=ControlInventory(
            observations=(
                ControlObservation(
                    provider="github",
                    provider_instance=(
                        "github.example"
                    ),
                    tenant_id="O_acme",
                    repository_external_id=(
                        current.external_id
                    ),
                    name_with_owner=(
                        current.name_with_owner
                    ),
                    control=(
                        ControlKind
                        .ONBOARDING_POLICY
                    ),
                    state=(
                        ControlState.COMPLIANT
                    ),
                    source=(
                        "github-custom-property"
                    ),
                    expected=(
                        "blackduck_sca_policy=required"
                    ),
                    observed='"required"',
                ),
            )
        ),
    )


def test_complete_scm_snapshot_round_trip(
    tmp_path: Path,
) -> None:
    expected = observations()
    directory = write_inventory_snapshot(
        tmp_path,
        tenant(),
        inventory(),
        observations=expected,
        snapshot_id="complete",
    )
    loaded = load_inventory_snapshot(
        directory
    )

    assert loaded.inventory == inventory()
    assert loaded.evidence == (
        expected.evidence
    )
    assert loaded.controls == (
        expected.controls
    )
    assert (
        loaded.metadata[
            "evidence_observation_count"
        ]
        == 1
    )
    assert (
        loaded.metadata[
            "control_observation_count"
        ]
        == 1
    )
    assert (
        loaded.metadata["status"]
        == "succeeded"
    )

    for name in (
        "provider-evidence.json",
        "onboarding-controls.json",
        "checksums.json",
        "READY",
    ):
        assert (
            directory / name
        ).is_file()


def test_modified_evidence_is_rejected(
    tmp_path: Path,
) -> None:
    directory = write_inventory_snapshot(
        tmp_path,
        tenant(),
        inventory(),
        observations=observations(),
        snapshot_id="tampered",
    )
    path = (
        directory / "provider-evidence.json"
    )
    payload = json.loads(
        path.read_text(encoding="utf-8")
    )
    payload["observation_count"] = 99
    path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    with pytest.raises(
        SnapshotError,
        match="Checksum mismatch",
    ):
        load_inventory_snapshot(directory)


def test_unknown_repository_control_is_rejected(
    tmp_path: Path,
) -> None:
    invalid = observations()
    control = invalid.controls.observations[0]
    invalid = ScmObservationResult(
        evidence=invalid.evidence,
        controls=ControlInventory(
            observations=(
                ControlObservation(
                    provider=control.provider,
                    provider_instance=(
                        control.provider_instance
                    ),
                    tenant_id=control.tenant_id,
                    repository_external_id=(
                        "unknown-repository"
                    ),
                    name_with_owner=(
                        control.name_with_owner
                    ),
                    control=control.control,
                    state=control.state,
                    source=control.source,
                ),
            )
        ),
    )

    with pytest.raises(
        SnapshotError,
        match="unknown repository",
    ):
        write_inventory_snapshot(
            tmp_path,
            tenant(),
            inventory(),
            observations=invalid,
            snapshot_id="invalid",
        )
