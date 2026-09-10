from __future__ import annotations

from pathlib import Path

from wintermute.ai.batch import (
    build_registry,
    latest_snapshots,
    profile_group_key,
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
    provider: str,
    name: str,
) -> Repository:
    instance = (
        "github.example"
        if provider == "github"
        else "gitlab.example"
    )
    namespace = (
        "acme"
        if provider == "github"
        else "group/subgroup"
    )

    return Repository(
        provider=provider,
        provider_instance=instance,
        tenant_id=(
            f"tenant-{provider}"
        ),
        repository_id=(
            f"id-{provider}-{name}"
        ),
        namespace=namespace,
        name=name,
        canonical_url=(
            f"https://{instance}/"
            f"{namespace}/{name}"
        ),
        default_branch="main",
        head_sha="a" * 40,
        visibility="private",
        activity_status="active",
        languages=("python",),
    )


def write_snapshot(
    root: Path,
    provider: str,
    snapshot_id: str,
) -> None:
    value = repository(
        provider,
        "service",
    )

    write_inventory_snapshot(
        root,
        ScmTenant(
            provider=provider,
            provider_instance=(
                value.provider_instance
            ),
            tenant_id=value.tenant_id,
            namespace=value.namespace,
        ),
        RepositoryInventory(
            repositories=(value,),
            exclusions=(),
            failures=(),
            discovered_count=1,
        ),
        snapshot_id=snapshot_id,
    )


def test_latest_snapshots_selects_one_per_tenant(
    tmp_path: Path,
) -> None:
    write_snapshot(
        tmp_path,
        "github",
        "20260101-github",
    )
    write_snapshot(
        tmp_path,
        "github",
        "20260102-github",
    )
    write_snapshot(
        tmp_path,
        "gitlab",
        "20260103-gitlab",
    )

    selected = latest_snapshots(
        tmp_path,
        providers=set(),
    )

    assert {
        value.snapshot_id
        for value in selected
    } == {
        "20260102-github",
        "20260103-gitlab",
    }


def test_profile_group_key_is_deterministic() -> None:
    profile = {
        "central_template": "python",
        "scan_mode": "detector",
        "build_systems": ["python"],
        "package_managers": ["pip"],
        "parameters": {
            "buildless": True,
        },
    }

    assert profile_group_key(
        profile
    ) == profile_group_key(
        dict(reversed(list(
            profile.items()
        )))
    )


def test_registry_groups_equal_profiles() -> None:
    profile = {
        "central_template": "python",
        "scan_mode": "detector",
        "build_systems": ["python"],
        "package_managers": ["pip"],
        "parameters": {
            "buildless": True,
        },
    }
    values = [
        {
            "repository": {
                "provider": "github",
                "provider_instance": (
                    "github.example"
                ),
                "repository_id": "1",
                "external_id": "one",
                "name_with_owner": (
                    "acme/one"
                ),
            },
            "scan_profile": dict(profile),
        },
        {
            "repository": {
                "provider": "gitlab",
                "provider_instance": (
                    "gitlab.example"
                ),
                "repository_id": "2",
                "external_id": "two",
                "name_with_owner": (
                    "group/two"
                ),
            },
            "scan_profile": dict(profile),
        },
    ]
    registry = build_registry(values)

    assert registry["profile_count"] == 2
    assert (
        registry["profile_group_count"]
        == 1
    )
    assert registry["groups"][0][
        "repository_external_ids"
    ] == [
        "one",
        "two",
    ]
