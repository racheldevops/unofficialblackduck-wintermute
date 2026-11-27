from __future__ import annotations

import hashlib
import io
import json
import zipfile

import pytest

from wintermute.scan.trigger import (
    LauncherTriggerError,
    pipeline_variables,
    validate_commit,
    verify_launcher_artifact,
)
from wintermute.scm.onboarding.central_bundle import (
    BUNDLE_RENDERER_VERSION,
    CentralBundleConfiguration,
    render_gitlab_launcher,
    render_gitlab_template,
)


PROVIDER_INSTANCE = "gitlab.example"
PROJECT_ID = 10682
COMMIT = "a" * 40


def artifact() -> bytes:
    receipt = {
        "schema_version": 1,
        "status": "succeeded",
        "mode": "dry-run",
        "provider": "gitlab",
        "provider_instance": (
            PROVIDER_INSTANCE
        ),
        "project_id": str(PROJECT_ID),
        "commit_sha": COMMIT,
        "scan_contract_id": "scan-python",
        "registry_sha256": "b" * 64,
        "bridge_sha256": "c" * 64,
        "archive_sha256": "d" * 64,
        "scan_exit_code": 0,
        "workspace_deleted": True,
        "target_repository_modified": False,
    }
    receipt_bytes = (
        json.dumps(
            receipt,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    checksums = {
        "schema_version": 1,
        "sha256": {
            "launcher-receipt.json": (
                hashlib.sha256(
                    receipt_bytes
                ).hexdigest()
            )
        },
    }
    output = io.BytesIO()

    with zipfile.ZipFile(
        output,
        mode="w",
    ) as archive:
        archive.writestr(
            (
                ".wintermute/scan/receipts/"
                "one/launcher-receipt.json"
            ),
            receipt_bytes,
        )
        archive.writestr(
            (
                ".wintermute/scan/receipts/"
                "one/checksums.json"
            ),
            json.dumps(checksums),
        )

    return output.getvalue()


def configuration() -> CentralBundleConfiguration:
    return CentralBundleConfiguration(
        image=(
            "registry.example/scan@sha256:"
            + "e" * 64
        ),
        bridge_sha256="f" * 64,
        gitlab_project=(
            "group/security-scans"
        ),
        gitlab_ref="main",
    )


def test_gitlab_jobs_clear_image_entrypoint() -> None:
    launcher = render_gitlab_launcher(
        configuration(),
        "1" * 64,
    )
    template = render_gitlab_template(
        configuration(),
        "1" * 64,
    )

    for rendered in (
        launcher,
        template,
    ):
        assert 'entrypoint: [""]' in rendered
        assert "  image:\n" in rendered
        assert "    name: " in rendered


def test_renderer_version_is_explicit() -> None:
    assert BUNDLE_RENDERER_VERSION >= 2


def test_pipeline_variables_force_dry_run() -> None:
    values = pipeline_variables(
        target_project_id=PROJECT_ID,
        commit_sha=COMMIT,
        target_ref="main",
    )
    by_name = {
        value["key"]: value["value"]
        for value in values
    }

    assert by_name[
        "TARGET_PROJECT_ID"
    ] == str(PROJECT_ID)
    assert by_name[
        "TARGET_COMMIT_SHA"
    ] == COMMIT
    assert by_name[
        "WINTERMUTE_SCAN_MODE"
    ] == "dry-run"
    assert by_name[
        "WINTERMUTE_SCAN_CONFIRMATION"
    ] == ""


def test_full_commit_is_required() -> None:
    assert validate_commit(COMMIT) == COMMIT

    with pytest.raises(
        LauncherTriggerError,
        match="full",
    ):
        validate_commit("main")


def test_launcher_artifact_verifies() -> None:
    (
        receipt,
        receipt_bytes,
        checksums_bytes,
    ) = verify_launcher_artifact(
        artifact(),
        provider_instance=(
            PROVIDER_INSTANCE
        ),
        project_id=PROJECT_ID,
        commit_sha=COMMIT,
    )

    assert receipt[
        "scan_contract_id"
    ] == "scan-python"
    assert receipt_bytes
    assert checksums_bytes


def test_launcher_artifact_rejects_wrong_commit() -> None:
    with pytest.raises(
        LauncherTriggerError,
        match="commit_sha",
    ):
        verify_launcher_artifact(
            artifact(),
            provider_instance=(
                PROVIDER_INSTANCE
            ),
            project_id=PROJECT_ID,
            commit_sha="9" * 40,
        )
