from __future__ import annotations

import json
from pathlib import Path

import pytest

from wintermute.scm.models import (
    InventoryFailure,
    Repository,
    RepositoryInventory,
    ScmTenant,
)
from wintermute.scm.snapshots import (
    SnapshotError,
    load_inventory_snapshot,
    validate_snapshot_id,
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


def inventory(
    *,
    failures: tuple[
        InventoryFailure,
        ...
    ] = (),
) -> RepositoryInventory:
    return RepositoryInventory(
        repositories=(repository(),),
        exclusions=(),
        failures=failures,
        discovered_count=1 + len(failures),
    )


def test_snapshot_round_trip(
    tmp_path: Path,
) -> None:
    directory = write_inventory_snapshot(
        tmp_path,
        tenant(),
        inventory(),
        snapshot_id="snapshot-1",
    )
    loaded = load_inventory_snapshot(
        directory
    )

    assert loaded.snapshot_id == "snapshot-1"
    assert loaded.tenant == tenant()
    assert loaded.inventory == inventory()
    assert (
        loaded.metadata["status"]
        == "succeeded"
    )
    assert (
        directory / "READY"
    ).is_file()


def test_partial_inventory_is_retained(
    tmp_path: Path,
) -> None:
    failure = InventoryFailure(
        provider="github",
        provider_instance="github.example",
        tenant_id="O_acme",
        repository_id="R_failed",
        name_with_owner="acme/failed",
        stage="map-repository",
        error="invalid response",
    )
    expected = inventory(
        failures=(failure,)
    )
    directory = write_inventory_snapshot(
        tmp_path,
        tenant(),
        expected,
        snapshot_id="partial",
    )
    loaded = load_inventory_snapshot(
        directory
    )

    assert loaded.inventory == expected
    assert (
        loaded.metadata["status"]
        == "partial"
    )


def test_modified_artifact_is_rejected(
    tmp_path: Path,
) -> None:
    directory = write_inventory_snapshot(
        tmp_path,
        tenant(),
        inventory(),
        snapshot_id="tampered",
    )
    path = directory / "repositories.json"
    payload = json.loads(
        path.read_text(encoding="utf-8")
    )
    payload["repository_count"] = 99
    path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    with pytest.raises(
        SnapshotError,
        match="Checksum mismatch",
    ):
        load_inventory_snapshot(directory)


def test_snapshot_requires_ready_marker(
    tmp_path: Path,
) -> None:
    directory = write_inventory_snapshot(
        tmp_path,
        tenant(),
        inventory(),
        snapshot_id="not-ready",
    )
    (
        directory / "READY"
    ).unlink()

    with pytest.raises(
        SnapshotError,
        match="not ready",
    ):
        load_inventory_snapshot(directory)


@pytest.mark.parametrize(
    "value",
    [
        "",
        ".",
        "..",
        "../escape",
        "contains space",
        "/absolute",
    ],
)
def test_snapshot_id_rejects_unsafe_values(
    value: str,
) -> None:
    with pytest.raises(SnapshotError):
        validate_snapshot_id(value)
