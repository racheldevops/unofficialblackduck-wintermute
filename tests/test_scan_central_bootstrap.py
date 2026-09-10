from __future__ import annotations

from pathlib import Path

from wintermute.scm.onboarding.bootstrap import (
    GitHubBootstrapTarget,
    GitLabBootstrapTarget,
    build_bootstrap_plan,
    load_verified_bootstrap_plan,
    load_verified_central_bundle,
    write_bootstrap_plan,
)


def central_bundle(
    tmp_path: Path,
) -> Path:
    root = tmp_path / "bundle"
    (
        root
        / "registry"
    ).mkdir(
        parents=True
    )
    (
        root
        / ".github"
        / "workflows"
    ).mkdir(
        parents=True
    )
    (
        root
        / "templates"
    ).mkdir(
        parents=True
    )
    (
        root
        / "registry"
        / "scan-registry.json"
    ).write_text(
        '{"schema_version":1}\n',
        encoding="utf-8",
    )
    (
        root
        / ".github"
        / "workflows"
        / "wintermute-security.yml"
    ).write_text(
        "name: Wintermute Security Scan\n",
        encoding="utf-8",
    )
    (
        root
        / "templates"
        / "wintermute-security.yml"
    ).write_text(
        "wintermute_security_scan:\n",
        encoding="utf-8",
    )
    managed = {
        "schema_version": 1,
        "bundle_id": "bundle-one",
        "management_mode": (
            "initialize-only"
        ),
    }

    import json
    import hashlib

    (
        root / "wintermute-managed.json"
    ).write_text(
        json.dumps(
            managed,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    names = (
        "registry/scan-registry.json",
        ".github/workflows/"
        "wintermute-security.yml",
        "templates/"
        "wintermute-security.yml",
        "wintermute-managed.json",
    )
    checksums = {
        name: hashlib.sha256(
            (root / name).read_bytes()
        ).hexdigest()
        for name in names
    }
    (
        root / "checksums.json"
    ).write_text(
        json.dumps(
            {
                "schema_version": 1,
                "sha256": checksums,
            }
        ),
        encoding="utf-8",
    )
    (
        root / "READY"
    ).write_text(
        json.dumps(
            {
                "schema_version": 1,
                "bundle_id": "bundle-one",
            }
        ),
        encoding="utf-8",
    )

    return root


def test_bootstrap_plan_is_provider_scoped(
    tmp_path: Path,
) -> None:
    bundle = (
        load_verified_central_bundle(
            central_bundle(tmp_path)
        )
    )
    plan, files = build_bootstrap_plan(
        bundle,
        github=GitHubBootstrapTarget(
            organization="acme",
        ),
        gitlab=GitLabBootstrapTarget(
            group="group",
        ),
    )

    assert plan["repository_count"] == 2
    assert (
        ".github/workflows/"
        "wintermute-security.yml"
        in files["github"]
    )
    assert (
        "templates/"
        "wintermute-security.yml"
        not in files["github"]
    )
    assert (
        "templates/"
        "wintermute-security.yml"
        in files["gitlab"]
    )
    assert (
        ".github/workflows/"
        "wintermute-security.yml"
        not in files["gitlab"]
    )


def test_bootstrap_plan_round_trip(
    tmp_path: Path,
) -> None:
    bundle = (
        load_verified_central_bundle(
            central_bundle(tmp_path)
        )
    )
    plan, files = build_bootstrap_plan(
        bundle,
        github=GitHubBootstrapTarget(
            organization="acme",
        ),
    )
    directory = write_bootstrap_plan(
        tmp_path / "plans",
        plan,
        files,
    )
    loaded = (
        load_verified_bootstrap_plan(
            directory
        )
    )

    assert loaded.plan["plan_id"] == (
        plan["plan_id"]
    )
    assert (
        "wintermute-managed.json"
        in loaded.files["github"]
    )
    assert loaded.digest.startswith(
        "sha256:"
    )
