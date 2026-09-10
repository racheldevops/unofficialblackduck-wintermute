from __future__ import annotations

import copy
import io
import json
import tarfile
from pathlib import Path

import pytest

from wintermute.ai.models import stable_digest
from wintermute.scan.launcher import (
    LauncherError,
    extract_archive,
    safe_member_path,
    validate_commit_response,
)
from wintermute.scm.onboarding.central_bundle import (
    CentralBundleConfiguration,
    render_gitlab_launcher,
)
from wintermute.scm.onboarding.project_access import (
    GitLabProjectAccessClient,
)
from wintermute.scm.onboarding.setup import (
    SetupError,
    gitlab_configuration,
    load_configuration,
    target_projects,
    tls_options,
)


@pytest.fixture
def setup_configuration() -> dict:
    """Synthetic customer configuration: no personal files or credentials."""
    return {
        "schema_version": 1,
        "gitlab": {
            "url": "https://gitlab.example.invalid",
            "central_project": "example/security-scans",
            "central_branch": "main",
            "image_project": "example/scan-image",
        },
        "target_projects": ["example/application"],
        "tls": {
            "insecure": False,
        },
        "scan_image": {
            "digest_reference": (
                "registry.example.invalid/example/scan@sha256:"
                + "a" * 64
            ),
            "publish_if_missing": False,
        },
        "reuse": {
            "merged_template_plan": "artifacts/template-plan",
            "merged_template_plan_digest": "sha256:" + "b" * 64,
        },
        "expected_counts": {
            "repository_count": 1,
            "required_count": 1,
            "review_count": 0,
            "scan_contract_count": 1,
        },
    }


def test_archive_path_rejects_traversal() -> None:
    with pytest.raises(LauncherError, match="unsafe path"):
        safe_member_path("../outside")


def test_archive_rejects_symbolic_links(tmp_path: Path) -> None:
    archive_path = tmp_path / "source.tar.gz"

    with tarfile.open(archive_path, mode="w:gz") as archive:
        directory = tarfile.TarInfo("project/")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)

        link = tarfile.TarInfo("project/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        archive.addfile(link)

    with pytest.raises(LauncherError, match="link or special"):
        extract_archive(archive_path, tmp_path / "workspace")


def test_archive_extracts_one_source_root(tmp_path: Path) -> None:
    archive_path = tmp_path / "source.tar.gz"
    content = b"print('ok')\n"

    with tarfile.open(archive_path, mode="w:gz") as archive:
        directory = tarfile.TarInfo("project/")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)

        file_info = tarfile.TarInfo("project/main.py")
        file_info.size = len(content)
        archive.addfile(file_info, io.BytesIO(content))

    source, files, size = extract_archive(
        archive_path,
        tmp_path / "workspace",
    )

    assert source.name == "project"
    assert files == 1
    assert size == len(content)
    assert (source / "main.py").read_bytes() == content


def test_commit_validation_is_exact() -> None:
    validate_commit_response({"id": "a" * 40}, "a" * 40)

    with pytest.raises(LauncherError, match="exact"):
        validate_commit_response({"id": "b" * 40}, "a" * 40)


def test_launcher_pipeline_defaults_to_dry_run() -> None:
    text = render_gitlab_launcher(
        CentralBundleConfiguration(
            image="registry.example.invalid/scan@sha256:" + "a" * 64,
            bridge_sha256="b" * 64,
            gitlab_project="example/security-scans",
        ),
        "c" * 64,
    )

    assert 'WINTERMUTE_SCAN_MODE: "dry-run"' in text
    assert "python -m wintermute.scan.launcher" in text
    assert "CI_JOB_TOKEN" not in text
    assert ".wintermute/scan/receipts/" in text
    assert "resource_group:" in text


def test_project_access_client_has_scoped_routes() -> None:
    client = GitLabProjectAccessClient(
        "gitlab",
        "https://gitlab.example.invalid/api/v4",
        "synthetic-test-token",
    )

    client._validate_route("GET", "/projects/10/job_token_scope/allowlist")
    client._validate_route("POST", "/projects/10/job_token_scope/allowlist")


def test_public_onboarding_configuration_is_valid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    setup_configuration: dict,
) -> None:
    """Configuration loading must work without a checkout-local config/."""
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "customer-onboarding.json"
    config_path.write_text(
        json.dumps(setup_configuration),
        encoding="utf-8",
    )

    source, payload, digest = load_configuration(str(config_path))

    assert source == config_path.resolve()
    assert payload == setup_configuration
    assert digest == stable_digest(setup_configuration)

    gitlab = gitlab_configuration(payload)
    assert gitlab["rest_url"] == "https://gitlab.example.invalid/api/v4"
    assert gitlab["central_project"] == "example/security-scans"
    assert gitlab["central_branch"] == "main"
    assert gitlab["image_project"] == "example/scan-image"
    assert target_projects(payload) == ("example/application",)
    assert tls_options(payload) == {
        "insecure": False,
        "ca_bundle": None,
    }


def test_configuration_digest_changes_with_target_scope(
    tmp_path: Path,
    setup_configuration: dict,
) -> None:
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    changed = copy.deepcopy(setup_configuration)
    changed["target_projects"] = ["example/another-application"]

    first_path.write_text(
        json.dumps(setup_configuration),
        encoding="utf-8",
    )
    second_path.write_text(
        json.dumps(changed),
        encoding="utf-8",
    )

    assert load_configuration(str(first_path))[2] != (
        load_configuration(str(second_path))[2]
    )


@pytest.mark.parametrize("version", [0, 2, "1", None])
def test_configuration_rejects_unsupported_schema(
    tmp_path: Path,
    setup_configuration: dict,
    version: object,
) -> None:
    setup_configuration["schema_version"] = version
    path = tmp_path / "invalid-schema.json"
    path.write_text(json.dumps(setup_configuration), encoding="utf-8")

    with pytest.raises(SetupError, match="schema version"):
        load_configuration(str(path))


@pytest.mark.parametrize("content", ["[]", "null", "{invalid"])
def test_configuration_rejects_invalid_document(
    tmp_path: Path,
    content: str,
) -> None:
    path = tmp_path / "invalid.json"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(SetupError):
        load_configuration(str(path))


def test_configuration_reports_missing_file(tmp_path: Path) -> None:
    with pytest.raises(SetupError, match="Could not read"):
        load_configuration(str(tmp_path / "missing.json"))


def test_configuration_rejects_conflicting_tls_options() -> None:
    with pytest.raises(SetupError, match="not both"):
        tls_options({
            "tls": {
                "insecure": True,
                "ca_bundle": "example-ca.pem",
            },
        })


@pytest.mark.parametrize("value", ["true", 1, None])
def test_configuration_requires_boolean_tls_setting(value: object) -> None:
    with pytest.raises(SetupError, match="must be boolean"):
        tls_options({"tls": {"insecure": value}})


@pytest.mark.parametrize(
    "targets",
    [
        [],
        "example/application",
        ["application"],
        [None],
    ],
)
def test_configuration_requires_project_paths(targets: object) -> None:
    with pytest.raises(SetupError, match="target_projects"):
        target_projects({"target_projects": targets})
