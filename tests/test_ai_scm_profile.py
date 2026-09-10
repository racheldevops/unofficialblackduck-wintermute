from __future__ import annotations

from pathlib import Path

import pytest

from wintermute.ai.scm_profile import (
    latest_snapshot,
    select_repository,
)
from wintermute.scm.models import (
    Repository,
    RepositoryInventory,
    ScmTenant,
)
from wintermute.scm.snapshots import (
    write_inventory_snapshot,
)


def repository(
    name: str = "service",
) -> Repository:
    return Repository(
        provider="gitlab",
        provider_instance=(
            "gitlab.example.invalid"
        ),
        tenant_id="10",
        repository_id=f"id-{name}",
        namespace="group/subgroup",
        name=name,
        canonical_url=(
            "https://gitlab.example.invalid/"
            f"group/subgroup/{name}"
        ),
        default_branch="main",
        head_sha="a" * 40,
        visibility="private",
        activity_status="active",
        languages=("python",),
    )


def write_snapshot(
    root: Path,
    snapshot_id: str,
    name: str,
) -> Path:
    value = repository(name)

    return write_inventory_snapshot(
        root,
        ScmTenant(
            provider="gitlab",
            provider_instance=(
                "gitlab.example.invalid"
            ),
            tenant_id="10",
            namespace="group/subgroup",
        ),
        RepositoryInventory(
            repositories=(value,),
            exclusions=(),
            failures=(),
            discovered_count=1,
        ),
        snapshot_id=snapshot_id,
    )


def test_select_repository_by_name(
    tmp_path: Path,
) -> None:
    directory = write_snapshot(
        tmp_path,
        "snapshot-one",
        "service",
    )
    from wintermute.scm.snapshots import (
        load_inventory_snapshot,
    )

    snapshot = load_inventory_snapshot(
        directory
    )
    selected = select_repository(
        snapshot,
        name_with_owner=(
            "group/subgroup/service"
        ),
    )

    assert selected.repository_id == (
        "id-service"
    )


def test_latest_snapshot_selects_matching_repository(
    tmp_path: Path,
) -> None:
    write_snapshot(
        tmp_path,
        "20260101-old",
        "old",
    )
    write_snapshot(
        tmp_path,
        "20260102-new",
        "service",
    )

    selected = latest_snapshot(
        tmp_path,
        provider="gitlab",
        repository_name=(
            "group/subgroup/service"
        ),
        include_excluded=False,
    )

    assert selected.snapshot_id == (
        "20260102-new"
    )


def test_repository_selection_requires_identity(
    tmp_path: Path,
) -> None:
    directory = write_snapshot(
        tmp_path,
        "snapshot-one",
        "service",
    )
    from wintermute.scm.snapshots import (
        load_inventory_snapshot,
    )

    snapshot = load_inventory_snapshot(
        directory
    )

    with pytest.raises(
        ValueError,
        match="required",
    ):
        select_repository(snapshot)
