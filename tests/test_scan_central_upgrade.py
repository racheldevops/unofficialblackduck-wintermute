from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import pytest

from wintermute.scm.onboarding.bootstrap import (
    LoadedCentralBundle,
)
from wintermute.scm.onboarding.central_upgrade import (
    CentralUpgradeError,
    build_upgrade_plan,
    execute_upgrade_plan,
    load_verified_upgrade_plan,
    write_upgrade_plan,
)
from wintermute.scm.onboarding.http import (
    HttpResult,
)


PROJECT = (
    "rhorner/wintermute-security-scans"
)
BRANCH = "main"
OLD_BUNDLE_DIGEST = (
    "sha256:" + "a" * 64
)
NEW_BUNDLE_DIGEST = (
    "sha256:" + "b" * 64
)


def rendered_json(
    value: Any,
) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def old_files() -> dict[str, bytes]:
    registry = b'{"old":true}\n'
    template = b"old_template:\n"
    manifest = rendered_json(
        {
            "schema_version": 1,
            "owner": "wintermute",
            "management_mode": (
                "initialize-only"
            ),
            "provider": "gitlab",
            "repository": PROJECT,
            "source_bundle_id": (
                "old-bundle"
            ),
            "source_bundle_digest": (
                OLD_BUNDLE_DIGEST
            ),
            "managed_files": {
                "registry/scan-registry.json": (
                    __import__(
                        "hashlib"
                    ).sha256(
                        registry
                    ).hexdigest()
                ),
                (
                    "templates/"
                    "wintermute-security.yml"
                ): (
                    __import__(
                        "hashlib"
                    ).sha256(
                        template
                    ).hexdigest()
                ),
            },
        }
    )

    return {
        "registry/scan-registry.json": (
            registry
        ),
        (
            "templates/"
            "wintermute-security.yml"
        ): template,
        "wintermute-managed.json": (
            manifest
        ),
    }


def bundle(
    tmp_path: Path,
) -> LoadedCentralBundle:
    return LoadedCentralBundle(
        directory=tmp_path / "bundle",
        bundle_id="new-bundle",
        managed={
            "bundle_id": "new-bundle",
            "management_mode": (
                "initialize-only"
            ),
            "registry_sha256": (
                "c" * 64
            ),
        },
        digest=NEW_BUNDLE_DIGEST,
        files={
            "registry/scan-registry.json": (
                b'{"new":true}\n'
            ),
            (
                "templates/"
                "wintermute-security.yml"
            ): b"new_template:\n",
            "wintermute-managed.json": (
                b"unused\n"
            ),
        },
    )


def decoded_file_path(
    path: str,
) -> str:
    marker = "/repository/files/"
    selected = path.split(
        marker,
        1,
    )[1]
    selected = selected.removesuffix(
        "/raw"
    )

    return unquote(selected)


class Client:
    def __init__(self) -> None:
        self.files = old_files()
        self.last_commit_ids = {
            path: (
                str(index) * 40
            )
            for index, path in enumerate(
                sorted(self.files),
                start=1,
            )
        }
        self.requests = 0
        self.writes = 0
        self.commits: list[
            dict[str, Any]
        ] = []

    def get_json(
        self,
        path: str,
        *,
        params=None,
        allow_not_found=False,
    ) -> HttpResult:
        del params
        self.requests += 1

        if path == (
            "/projects/rhorner%2F"
            "wintermute-security-scans"
        ):
            return HttpResult(
                200,
                {
                    "id": 100,
                    "path_with_namespace": (
                        PROJECT
                    ),
                    "default_branch": BRANCH,
                    "visibility": "private",
                },
                {},
            )

        file_path = decoded_file_path(
            path
        )

        if file_path not in self.files:
            if allow_not_found:
                return HttpResult(
                    404,
                    None,
                    {},
                )

            raise AssertionError(
                f"Missing file: {file_path}"
            )

        return HttpResult(
            200,
            {
                "file_path": file_path,
                "last_commit_id": (
                    self.last_commit_ids[
                        file_path
                    ]
                ),
            },
            {},
        )

    def get_bytes(
        self,
        path: str,
        *,
        params=None,
        allow_not_found=False,
    ) -> HttpResult:
        del params
        del allow_not_found
        self.requests += 1
        file_path = decoded_file_path(
            path
        )

        return HttpResult(
            200,
            self.files[file_path],
            {},
        )

    def mutate_json(
        self,
        method: str,
        path: str,
        body: dict[str, Any],
        *,
        expected_statuses: set[int],
    ) -> HttpResult:
        assert method == "POST"
        assert path.endswith(
            "/repository/commits"
        )
        assert expected_statuses == {201}
        self.requests += 1
        self.writes += 1
        self.commits.append(body)
        commit_id = "f" * 40

        for action in body["actions"]:
            file_path = action["file_path"]
            kind = action["action"]

            if kind == "update":
                assert (
                    action["last_commit_id"]
                    == self.last_commit_ids[
                        file_path
                    ]
                )
            elif kind == "create":
                assert (
                    file_path
                    not in self.files
                )
            else:
                raise AssertionError(kind)

            self.files[file_path] = (
                action["content"].encode(
                    "utf-8"
                )
            )
            self.last_commit_ids[
                file_path
            ] = commit_id

        return HttpResult(
            201,
            {"id": commit_id},
            {},
        )


def loaded_plan(
    tmp_path: Path,
    client: Client,
):
    values = build_upgrade_plan(
        client,
        bundle(tmp_path),
        project=PROJECT,
        branch=BRANCH,
        expected_new_bundle_digest=(
            NEW_BUNDLE_DIGEST
        ),
    )
    directory = write_upgrade_plan(
        tmp_path / "plans",
        *values,
    )

    return load_verified_upgrade_plan(
        directory
    )


def test_upgrade_plan_verifies_previous_files(
    tmp_path: Path,
) -> None:
    selected = loaded_plan(
        tmp_path,
        Client(),
    )

    assert selected.plan[
        "previous_source_bundle_digest"
    ] == OLD_BUNDLE_DIGEST
    assert selected.plan[
        "source_bundle_digest"
    ] == NEW_BUNDLE_DIGEST
    assert selected.plan[
        "estimated_writes"
    ] == 1
    assert selected.plan[
        "changed_file_count"
    ] == 3
    assert {
        value["path"]
        for value
        in selected.plan["actions"]
    } == {
        "registry/scan-registry.json",
        (
            "templates/"
            "wintermute-security.yml"
        ),
        "wintermute-managed.json",
    }


def test_upgrade_dry_run_writes_nothing(
    tmp_path: Path,
) -> None:
    client = Client()
    selected = loaded_plan(
        tmp_path,
        client,
    )
    writes_before = client.writes
    code, result, path = (
        execute_upgrade_plan(
            selected,
            client,
            mode="dry-run",
            result_root=(
                tmp_path / "results"
            ),
            maximum_writes=1,
        )
    )

    assert code == 0
    assert result["status"] == "ok"
    assert result["outcome"] == "planned"
    assert result["writes"] == 0
    assert client.writes == writes_before
    assert (
        path / "rollback.json"
    ).is_file()


def test_upgrade_applies_one_atomic_commit(
    tmp_path: Path,
) -> None:
    client = Client()
    selected = loaded_plan(
        tmp_path,
        client,
    )
    code, result, path = (
        execute_upgrade_plan(
            selected,
            client,
            mode="apply",
            result_root=(
                tmp_path / "results"
            ),
            maximum_writes=1,
            confirm_apply=True,
            expected_plan_digest=(
                selected.digest
            ),
        )
    )

    assert code == 0
    assert result["status"] == "ok"
    assert result["outcome"] == "applied"
    assert result["writes"] == 1
    assert result["commit_id"] == (
        "f" * 40
    )
    assert len(client.commits) == 1
    assert len(
        client.commits[0]["actions"]
    ) == 3
    assert result["after"][
        "actions"
    ] == []

    rollback = json.loads(
        (
            path / "rollback.json"
        ).read_text(encoding="utf-8")
    )

    assert rollback["status"] == (
        "available"
    )
    assert len(
        rollback["actions"]
    ) == 3


def test_customer_modified_file_is_rejected(
    tmp_path: Path,
) -> None:
    client = Client()
    client.files[
        "registry/scan-registry.json"
    ] = b'{"customer":"change"}\n'

    with pytest.raises(
        CentralUpgradeError,
        match="Customer-modified",
    ):
        build_upgrade_plan(
            client,
            bundle(tmp_path),
            project=PROJECT,
            branch=BRANCH,
            expected_new_bundle_digest=(
                NEW_BUNDLE_DIGEST
            ),
        )


def test_expected_previous_digest_is_enforced(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        CentralUpgradeError,
        match="Expected current bundle",
    ):
        build_upgrade_plan(
            Client(),
            bundle(tmp_path),
            project=PROJECT,
            branch=BRANCH,
            expected_new_bundle_digest=(
                NEW_BUNDLE_DIGEST
            ),
            expected_current_bundle_digest=(
                "sha256:" + "9" * 64
            ),
        )


def test_upgrade_requires_exact_plan_digest(
    tmp_path: Path,
) -> None:
    client = Client()
    selected = loaded_plan(
        tmp_path,
        client,
    )

    with pytest.raises(
        ValueError,
        match="digest",
    ):
        execute_upgrade_plan(
            selected,
            client,
            mode="apply",
            result_root=(
                tmp_path / "results"
            ),
            maximum_writes=1,
            confirm_apply=True,
            expected_plan_digest=(
                "sha256:" + "0" * 64
            ),
        )
