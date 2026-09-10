from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

from wintermute.ai.models import stable_digest
from wintermute.ai.storage import (
    atomic_write_json,
    sha256_file,
)
from wintermute.scm.onboarding.bootstrap import (
    LoadedCentralBundle,
)
from wintermute.scm.onboarding.http import (
    OnboardingHttpClient,
)


OWNERSHIP_PATH = "wintermute-managed.json"
CONFIRMATION = "UPGRADE CENTRAL SCAN REPOSITORY"
HEX_DIGEST_PATTERN = re.compile(
    r"^[0-9a-f]{64}$"
)
STABLE_DIGEST_PATTERN = re.compile(
    r"^sha256:[0-9a-f]{64}$"
)
COMMIT_PATTERN = re.compile(
    r"^[0-9a-f]{40}|[0-9a-f]{64}$"
)
_SEGMENT = r"[^/?#]+"
_UPGRADE_ROUTES = {
    "GET": (
        re.compile(
            rf"^/projects/{_SEGMENT}/"
            rf"repository/files/{_SEGMENT}$"
        ),
    ),
    "POST": (
        re.compile(
            rf"^/projects/{_SEGMENT}/"
            r"repository/commits$"
        ),
    ),
}


class CentralUpgradeError(RuntimeError):
    pass


class GitLabCentralUpgradeClient(
    OnboardingHttpClient
):
    def _validate_route(
        self,
        method: str,
        path: str,
    ) -> None:
        patterns = _UPGRADE_ROUTES.get(
            method,
            (),
        )

        if any(
            pattern.fullmatch(path)
            for pattern in patterns
        ):
            return

        super()._validate_route(
            method,
            path,
        )


@dataclass(frozen=True)
class RemoteFile:
    path: str
    exists: bool
    content: bytes = b""
    digest: str = ""
    last_commit_id: str = ""


@dataclass(frozen=True)
class LoadedCentralUpgradePlan:
    directory: Path
    plan: dict[str, Any]
    digest: str
    desired_files: dict[str, bytes]
    rollback_files: dict[str, bytes]


def now_text() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def create_plan_id() -> str:
    return (
        datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ"
        )
        + "-central-managed-upgrade-"
        + uuid.uuid4().hex[:12]
    )


def create_execution_id() -> str:
    return (
        datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ"
        )
        + "-central-upgrade-execution-"
        + uuid.uuid4().hex[:12]
    )


def required_text(
    value: Any,
    field: str,
) -> str:
    selected = str(value or "").strip()

    if not selected:
        raise CentralUpgradeError(
            f"{field} must not be empty"
        )

    return selected


def safe_path(
    value: str,
) -> str:
    selected = str(value or "").strip()
    path = PurePosixPath(selected)

    if (
        not selected
        or selected.startswith("/")
        or "\\" in selected
        or ".." in path.parts
        or not path.parts
    ):
        raise CentralUpgradeError(
            f"Unsafe managed path: {value!r}"
        )

    return path.as_posix()


def sha256_bytes(
    value: bytes,
) -> str:
    return hashlib.sha256(
        value
    ).hexdigest()


def json_bytes(
    value: Any,
) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def validate_project_path(
    value: str,
) -> str:
    selected = str(value or "").strip("/")
    parts = selected.split("/")

    if (
        len(parts) < 2
        or any(
            not part
            or part in {".", ".."}
            or any(
                character.isspace()
                for character in part
            )
            for part in parts
        )
    ):
        raise CentralUpgradeError(
            "GitLab project path is invalid"
        )

    return selected


def project_endpoint(
    project: str,
) -> str:
    return (
        f"/projects/{quote(project, safe='')}"
    )


def file_endpoints(
    project: str,
    path: str,
) -> tuple[str, str]:
    selected = safe_path(path)
    base = (
        f"{project_endpoint(project)}/"
        "repository/files/"
        f"{quote(selected, safe='')}"
    )

    return base, f"{base}/raw"


def resolve_project(
    client: GitLabCentralUpgradeClient,
    project: str,
    branch: str,
) -> dict[str, Any]:
    selected_project = validate_project_path(
        project
    )
    payload = client.get_json(
        project_endpoint(
            selected_project
        )
    ).payload

    if not isinstance(payload, dict):
        raise CentralUpgradeError(
            "GitLab project response is invalid"
        )

    returned_path = str(
        payload.get(
            "path_with_namespace"
        )
        or ""
    )

    if returned_path != selected_project:
        raise CentralUpgradeError(
            "GitLab returned another project path"
        )

    try:
        project_id = int(payload["id"])
    except (
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise CentralUpgradeError(
            "GitLab project has no numeric ID"
        ) from error

    if project_id < 1:
        raise CentralUpgradeError(
            "GitLab project ID is invalid"
        )

    default_branch = str(
        payload.get("default_branch")
        or ""
    )

    if default_branch != branch:
        raise CentralUpgradeError(
            "GitLab project default branch does "
            "not match the upgrade plan"
        )

    if payload.get("visibility") != "private":
        raise CentralUpgradeError(
            "Central GitLab project is not private"
        )

    return {
        "project": selected_project,
        "project_id": project_id,
        "default_branch": default_branch,
    }


def read_remote_file(
    client: GitLabCentralUpgradeClient,
    project: str,
    path: str,
    branch: str,
    *,
    allow_missing: bool,
) -> RemoteFile:
    selected_path = safe_path(path)
    metadata_path, raw_path = file_endpoints(
        project,
        selected_path,
    )
    metadata_result = client.get_json(
        metadata_path,
        params={"ref": branch},
        allow_not_found=allow_missing,
    )

    if metadata_result.status_code == 404:
        return RemoteFile(
            path=selected_path,
            exists=False,
        )

    metadata = metadata_result.payload

    if not isinstance(metadata, dict):
        raise CentralUpgradeError(
            "GitLab file metadata is invalid: "
            f"{selected_path}"
        )

    returned_path = str(
        metadata.get("file_path")
        or selected_path
    )

    if returned_path != selected_path:
        raise CentralUpgradeError(
            "GitLab returned another file path: "
            f"{selected_path}"
        )

    last_commit_id = str(
        metadata.get("last_commit_id")
        or ""
    ).casefold()

    if (
        COMMIT_PATTERN.fullmatch(
            last_commit_id
        )
        is None
    ):
        raise CentralUpgradeError(
            "GitLab file has an invalid last "
            f"commit ID: {selected_path}"
        )

    encoded_content = metadata.get("content")
    if encoded_content is not None:
        if metadata.get("encoding") != "base64" or not isinstance(
            encoded_content, str
        ):
            raise CentralUpgradeError(
                f"GitLab file encoding is invalid: {selected_path}"
            )
        try:
            content = base64.b64decode(
                "".join(encoded_content.split()),
                validate=True,
            )
        except ValueError as error:
            raise CentralUpgradeError(
                f"GitLab file content is invalid: {selected_path}"
            ) from error
    else:
        raw_result = client.get_bytes(
            raw_path,
            params={"ref": last_commit_id},
        )
        content = bytes(raw_result.payload)

    returned_digest = metadata.get("content_sha256")
    if returned_digest is not None and returned_digest != sha256_bytes(content):
        raise CentralUpgradeError(
            f"GitLab file content checksum mismatch: {selected_path}"
        )

    return RemoteFile(
        path=selected_path,
        exists=True,
        content=content,
        digest=sha256_bytes(content),
        last_commit_id=last_commit_id,
    )


def parse_ownership_manifest(
    content: bytes,
    *,
    project: str,
) -> dict[str, Any]:
    try:
        payload = json.loads(
            content.decode("utf-8")
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise CentralUpgradeError(
            "Central ownership manifest is invalid"
        ) from error

    if not isinstance(payload, dict):
        raise CentralUpgradeError(
            "Central ownership manifest is not "
            "an object"
        )

    if payload.get("owner") != "wintermute":
        raise CentralUpgradeError(
            "Central ownership manifest has "
            "another owner"
        )

    if payload.get("provider") != "gitlab":
        raise CentralUpgradeError(
            "Central ownership manifest has "
            "another provider"
        )

    if payload.get("repository") != project:
        raise CentralUpgradeError(
            "Central ownership manifest belongs "
            "to another repository"
        )

    if payload.get(
        "management_mode"
    ) not in {
        "initialize-only",
        "explicit-managed-upgrade",
    }:
        raise CentralUpgradeError(
            "Central ownership manifest has an "
            "unsupported management mode"
        )

    source_bundle_id = required_text(
        payload.get("source_bundle_id"),
        "Previous source bundle ID",
    )
    source_bundle_digest = required_text(
        payload.get(
            "source_bundle_digest"
        ),
        "Previous source bundle digest",
    )

    if (
        STABLE_DIGEST_PATTERN.fullmatch(
            source_bundle_digest
        )
        is None
    ):
        raise CentralUpgradeError(
            "Previous source bundle digest is invalid"
        )

    raw_files = payload.get(
        "managed_files"
    )

    if (
        not isinstance(raw_files, dict)
        or not raw_files
    ):
        raise CentralUpgradeError(
            "Central ownership manifest has no "
            "managed files"
        )

    managed_files: dict[str, str] = {}

    for raw_path, raw_digest in (
        raw_files.items()
    ):
        path = safe_path(
            str(raw_path)
        )
        digest = str(
            raw_digest or ""
        ).casefold()

        if (
            HEX_DIGEST_PATTERN.fullmatch(
                digest
            )
            is None
        ):
            raise CentralUpgradeError(
                "Managed-file digest is invalid: "
                f"{path}"
            )

        if path == OWNERSHIP_PATH:
            raise CentralUpgradeError(
                "Ownership manifest must not "
                "self-reference its checksum"
            )

        managed_files[path] = digest

    sequence = payload.get(
        "upgrade_sequence",
        0,
    )

    if (
        type(sequence) is not int
        or sequence < 0
    ):
        raise CentralUpgradeError(
            "Central upgrade sequence is invalid"
        )

    normalized = dict(payload)
    normalized[
        "source_bundle_id"
    ] = source_bundle_id
    normalized[
        "source_bundle_digest"
    ] = source_bundle_digest
    normalized[
        "managed_files"
    ] = dict(
        sorted(managed_files.items())
    )
    normalized[
        "upgrade_sequence"
    ] = sequence

    return normalized


def gitlab_bundle_files(
    bundle: LoadedCentralBundle,
) -> dict[str, bytes]:
    selected: dict[str, bytes] = {}

    for path, content in bundle.files.items():
        if (
            path
            == "registry/scan-registry.json"
            or path.startswith("templates/")
            or path == ".gitlab-ci.yml"
        ):
            selected[
                safe_path(path)
            ] = bytes(content)

    for required in (
        "registry/scan-registry.json",
        "templates/wintermute-security.yml",
    ):
        if required not in selected:
            raise CentralUpgradeError(
                "Central bundle is missing the "
                f"GitLab managed file: {required}"
            )

    return dict(
        sorted(selected.items())
    )


def desired_repository_files(
    bundle: LoadedCentralBundle,
    *,
    project: str,
    previous_manifest: dict[str, Any],
) -> dict[str, bytes]:
    core_files = gitlab_bundle_files(
        bundle
    )
    previous_files = set(
        previous_manifest[
            "managed_files"
        ]
    )
    removed_files = (
        previous_files
        - set(core_files)
    )

    if removed_files:
        raise CentralUpgradeError(
            "Managed-file removal is not supported: "
            + ", ".join(sorted(removed_files))
        )

    manifest = {
        "schema_version": 2,
        "owner": "wintermute",
        "management_mode": (
            "explicit-managed-upgrade"
        ),
        "provider": "gitlab",
        "repository": project,
        "source_bundle_id": (
            bundle.bundle_id
        ),
        "source_bundle_digest": (
            bundle.digest
        ),
        "previous_source_bundle_id": (
            previous_manifest[
                "source_bundle_id"
            ]
        ),
        "previous_source_bundle_digest": (
            previous_manifest[
                "source_bundle_digest"
            ]
        ),
        "upgrade_sequence": (
            int(
                previous_manifest.get(
                    "upgrade_sequence",
                    0,
                )
            )
            + 1
        ),
        "managed_files": {
            path: sha256_bytes(content)
            for path, content
            in core_files.items()
        },
    }

    return {
        **core_files,
        OWNERSHIP_PATH: json_bytes(
            manifest
        ),
    }


def action_descriptor(
    *,
    path: str,
    current: RemoteFile,
    desired: bytes,
) -> dict[str, Any] | None:
    desired_digest = sha256_bytes(
        desired
    )

    if (
        current.exists
        and current.digest
        == desired_digest
    ):
        return None

    return {
        "action": (
            "update"
            if current.exists
            else "create"
        ),
        "path": path,
        "expected_current_sha256": (
            current.digest
            if current.exists
            else ""
        ),
        "expected_last_commit_id": (
            current.last_commit_id
            if current.exists
            else ""
        ),
        "desired_sha256": (
            desired_digest
        ),
        "desired_size": len(desired),
    }


def inspect_upgrade_state(
    client: GitLabCentralUpgradeClient,
    *,
    project: str,
    branch: str,
    desired_files: dict[str, bytes],
    expected_current_bundle_digest: str = "",
) -> dict[str, Any]:
    project_state = resolve_project(
        client,
        project,
        branch,
    )
    ownership = read_remote_file(
        client,
        project,
        OWNERSHIP_PATH,
        branch,
        allow_missing=False,
    )
    manifest = parse_ownership_manifest(
        ownership.content,
        project=project,
    )
    current_bundle_digest = str(
        manifest[
            "source_bundle_digest"
        ]
    )

    if (
        expected_current_bundle_digest
        and current_bundle_digest
        != expected_current_bundle_digest
    ):
        raise CentralUpgradeError(
            "Current central bundle digest does "
            "not match the expected previous state"
        )

    desired_core_paths = (
        set(desired_files)
        - {OWNERSHIP_PATH}
    )
    previous_managed = dict(
        manifest["managed_files"]
    )
    removed = (
        set(previous_managed)
        - desired_core_paths
    )

    if removed:
        raise CentralUpgradeError(
            "Desired bundle omits previously managed "
            "files: "
            + ", ".join(sorted(removed))
        )

    current_files: dict[
        str,
        RemoteFile,
    ] = {
        OWNERSHIP_PATH: ownership,
    }

    for path in sorted(
        set(previous_managed)
        | desired_core_paths
    ):
        current = read_remote_file(
            client,
            project,
            path,
            branch,
            allow_missing=(
                path not in previous_managed
            ),
        )
        current_files[path] = current

        if path in previous_managed:
            if not current.exists:
                raise CentralUpgradeError(
                    "Previously managed file is "
                    f"missing: {path}"
                )

            if (
                current.digest
                != previous_managed[path]
            ):
                raise CentralUpgradeError(
                    "Customer-modified managed file "
                    "will not be overwritten: "
                    f"{path}"
                )
        elif current.exists:
            raise CentralUpgradeError(
                "New managed path already exists "
                "and is not owned by Wintermute: "
                f"{path}"
            )

    actions: list[
        dict[str, Any]
    ] = []

    for path, desired in sorted(
        desired_files.items()
    ):
        action = action_descriptor(
            path=path,
            current=current_files[path],
            desired=desired,
        )

        if action is not None:
            actions.append(action)

    file_observations = {
        path: {
            "owned_before": (
                path in previous_managed
                or path == OWNERSHIP_PATH
            ),
            "exists": current.exists,
            "recorded_sha256": (
                previous_managed.get(
                    path,
                    "",
                )
            ),
            "current_sha256": (
                current.digest
            ),
            "last_commit_id": (
                current.last_commit_id
            ),
            "desired_sha256": (
                sha256_bytes(
                    desired_files[path]
                )
                if path in desired_files
                else ""
            ),
        }
        for path, current
        in sorted(current_files.items())
    }
    observation = {
        **project_state,
        "ownership_path": (
            OWNERSHIP_PATH
        ),
        "ownership_sha256": (
            ownership.digest
        ),
        "ownership_last_commit_id": (
            ownership.last_commit_id
        ),
        "management_mode": (
            manifest[
                "management_mode"
            ]
        ),
        "current_source_bundle_id": (
            manifest["source_bundle_id"]
        ),
        "current_source_bundle_digest": (
            current_bundle_digest
        ),
        "upgrade_sequence": (
            manifest["upgrade_sequence"]
        ),
        "files": file_observations,
    }

    return {
        "observation": observation,
        "observation_digest": (
            stable_digest(observation)
        ),
        "actions": actions,
        "estimated_writes": (
            1 if actions else 0
        ),
        "current_files": current_files,
        "current_manifest": manifest,
    }


def build_upgrade_plan(
    client: GitLabCentralUpgradeClient,
    bundle: LoadedCentralBundle,
    *,
    project: str,
    branch: str,
    expected_new_bundle_digest: str,
    expected_current_bundle_digest: str = "",
) -> tuple[
    dict[str, Any],
    dict[str, bytes],
    dict[str, bytes],
]:
    selected_project = validate_project_path(
        project
    )

    if (
        bundle.digest
        != expected_new_bundle_digest
    ):
        raise CentralUpgradeError(
            "Expected new bundle digest does not "
            "match the verified bundle"
        )

    resolve_project(
        client,
        selected_project,
        branch,
    )
    ownership = read_remote_file(
        client,
        selected_project,
        OWNERSHIP_PATH,
        branch,
        allow_missing=False,
    )
    previous_manifest = (
        parse_ownership_manifest(
            ownership.content,
            project=selected_project,
        )
    )

    if (
        expected_current_bundle_digest
        and previous_manifest[
            "source_bundle_digest"
        ]
        != expected_current_bundle_digest
    ):
        raise CentralUpgradeError(
            "Expected current bundle digest does "
            "not match the ownership manifest"
        )

    desired_files = (
        desired_repository_files(
            bundle,
            project=selected_project,
            previous_manifest=(
                previous_manifest
            ),
        )
    )
    desired_core = gitlab_bundle_files(bundle)
    desired_digests = {
        path: sha256_bytes(content)
        for path, content in desired_core.items()
    }
    if (
        previous_manifest["source_bundle_digest"] == bundle.digest
        and previous_manifest["source_bundle_id"] == bundle.bundle_id
        and previous_manifest["managed_files"] == desired_digests
    ):
        desired_files = {
            **desired_core,
            OWNERSHIP_PATH: ownership.content,
        }

    inspection = inspect_upgrade_state(
        client,
        project=selected_project,
        branch=branch,
        desired_files=desired_files,
        expected_current_bundle_digest=(
            previous_manifest[
                "source_bundle_digest"
            ]
        ),
    )
    rollback_files = {
        action["path"]: (
            inspection[
                "current_files"
            ][action["path"]].content
        )
        for action in inspection["actions"]
        if action["action"] == "update"
    }
    plan = {
        "schema_version": 1,
        "plan_id": create_plan_id(),
        "created_at": now_text(),
        "status": "review-required",
        "mutation_allowed": False,
        "provider": "gitlab",
        "project": selected_project,
        "project_id": (
            inspection["observation"][
                "project_id"
            ]
        ),
        "branch": branch,
        "previous_source_bundle_id": (
            previous_manifest[
                "source_bundle_id"
            ]
        ),
        "previous_source_bundle_digest": (
            previous_manifest[
                "source_bundle_digest"
            ]
        ),
        "source_bundle_id": (
            bundle.bundle_id
        ),
        "source_bundle_digest": (
            bundle.digest
        ),
        "observation": (
            inspection["observation"]
        ),
        "observation_digest": (
            inspection[
                "observation_digest"
            ]
        ),
        "actions": (
            inspection["actions"]
        ),
        "changed_file_count": len(
            inspection["actions"]
        ),
        "estimated_writes": (
            inspection["estimated_writes"]
        ),
        "desired_files": [
            {
                "path": path,
                "sha256": (
                    sha256_bytes(content)
                ),
                "size": len(content),
            }
            for path, content
            in sorted(desired_files.items())
        ],
        "rollback_files": [
            {
                "path": path,
                "sha256": (
                    sha256_bytes(content)
                ),
                "size": len(content),
            }
            for path, content
            in sorted(
                rollback_files.items()
            )
        ],
        "review_requirements": [
            "review-current-bundle-identity",
            "review-managed-file-checksums",
            "review-new-bundle-identity",
            "review-atomic-commit-actions",
            "review-rollback-files",
            "confirm-explicit-managed-upgrade",
        ],
    }

    return (
        plan,
        desired_files,
        rollback_files,
    )


def write_upgrade_plan(
    root: str | Path,
    plan: dict[str, Any],
    desired_files: dict[str, bytes],
    rollback_files: dict[str, bytes],
) -> Path:
    root_path = Path(root)
    plan_id = required_text(
        plan.get("plan_id"),
        "Upgrade plan ID",
    )
    staging = (
        root_path / ".staging" / plan_id
    )
    destination = root_path / plan_id

    if destination.exists():
        raise CentralUpgradeError(
            "Central upgrade plan already exists: "
            f"{destination}"
        )

    if staging.exists():
        shutil.rmtree(staging)

    staging.mkdir(
        parents=True,
        exist_ok=False,
    )
    checksums: dict[str, str] = {}

    try:
        atomic_write_json(
            staging / "plan.json",
            plan,
        )
        checksums["plan.json"] = (
            sha256_file(
                staging / "plan.json"
            )
        )

        for category, values in (
            ("desired", desired_files),
            ("rollback", rollback_files),
        ):
            for relative, content in sorted(
                values.items()
            ):
                selected = safe_path(relative)
                path = (
                    staging
                    / "files"
                    / category
                    / selected
                )
                path.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )
                path.write_bytes(content)
                key = (
                    f"files/{category}/"
                    f"{selected}"
                )
                checksums[key] = (
                    sha256_file(path)
                )

        atomic_write_json(
            staging / "checksums.json",
            {
                "schema_version": 1,
                "sha256": checksums,
            },
        )
        root_path.mkdir(
            parents=True,
            exist_ok=True,
        )
        os.replace(
            staging,
            destination,
        )
        atomic_write_json(
            destination / "READY",
            {
                "schema_version": 1,
                "plan_id": plan_id,
                "ready_at": now_text(),
            },
        )

        return destination

    except BaseException:
        shutil.rmtree(
            staging,
            ignore_errors=True,
        )
        raise


def read_object(
    path: Path,
) -> dict[str, Any]:
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8")
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        raise CentralUpgradeError(
            f"Could not read {path}: {error}"
        ) from error

    if not isinstance(payload, dict):
        raise CentralUpgradeError(
            f"Artifact is not an object: {path}"
        )

    return payload


def load_descriptor_files(
    root: Path,
    plan: dict[str, Any],
    checksums: dict[str, Any],
    *,
    category: str,
    field: str,
) -> dict[str, bytes]:
    descriptors = plan.get(field)

    if (
        not isinstance(descriptors, list)
        or not all(
            isinstance(value, dict)
            for value in descriptors
        )
    ):
        raise CentralUpgradeError(
            f"Upgrade plan {field} are invalid"
        )

    values: dict[str, bytes] = {}

    for descriptor in descriptors:
        path = safe_path(
            str(
                descriptor.get("path")
                or ""
            )
        )
        key = (
            f"files/{category}/{path}"
        )

        if key not in checksums:
            raise CentralUpgradeError(
                "Missing upgrade artifact checksum: "
                f"{key}"
            )

        content = (root / key).read_bytes()
        digest = sha256_bytes(content)

        if (
            digest
            != descriptor.get("sha256")
        ):
            raise CentralUpgradeError(
                "Upgrade file descriptor does not "
                f"match: {path}"
            )

        values[path] = content

    return values


def load_verified_upgrade_plan(
    directory: str | Path,
) -> LoadedCentralUpgradePlan:
    root = Path(directory).expanduser()

    if not root.is_dir():
        raise CentralUpgradeError(
            "Central upgrade plan does not exist: "
            f"{root}"
        )

    ready = read_object(root / "READY")
    plan = read_object(root / "plan.json")
    checksums = read_object(
        root / "checksums.json"
    ).get("sha256")

    if not isinstance(checksums, dict):
        raise CentralUpgradeError(
            "Central upgrade checksums are invalid"
        )

    for raw_name, raw_digest in (
        checksums.items()
    ):
        name = safe_path(str(raw_name))
        expected = str(
            raw_digest or ""
        )

        if (
            HEX_DIGEST_PATTERN.fullmatch(
                expected
            )
            is None
        ):
            raise CentralUpgradeError(
                "Central upgrade checksum is "
                f"invalid: {name}"
            )

        path = root / name

        if (
            not path.is_file()
            or sha256_file(path) != expected
        ):
            raise CentralUpgradeError(
                "Central upgrade checksum "
                f"mismatch: {name}"
            )

    plan_id = str(
        plan.get("plan_id") or ""
    )

    if (
        not plan_id
        or ready.get("plan_id")
        != plan_id
    ):
        raise CentralUpgradeError(
            "Central upgrade plan identity "
            "is invalid"
        )

    if (
        plan.get("status")
        != "review-required"
        or plan.get("mutation_allowed")
        is not False
    ):
        raise CentralUpgradeError(
            "Central upgrade plan is not "
            "safely staged"
        )

    if plan.get("provider") != "gitlab":
        raise CentralUpgradeError(
            "Central upgrade provider is invalid"
        )

    desired_files = load_descriptor_files(
        root,
        plan,
        checksums,
        category="desired",
        field="desired_files",
    )
    rollback_files = load_descriptor_files(
        root,
        plan,
        checksums,
        category="rollback",
        field="rollback_files",
    )
    actions = plan.get("actions")

    if (
        not isinstance(actions, list)
        or not all(
            isinstance(value, dict)
            for value in actions
        )
    ):
        raise CentralUpgradeError(
            "Central upgrade actions are invalid"
        )

    for action in actions:
        kind = action.get("action")
        path = safe_path(
            str(action.get("path") or "")
        )

        if kind not in {
            "create",
            "update",
        }:
            raise CentralUpgradeError(
                "Central upgrade action is invalid"
            )

        if path not in desired_files:
            raise CentralUpgradeError(
                "Central upgrade action has no "
                f"desired file: {path}"
            )

        if (
            action.get("desired_sha256")
            != sha256_bytes(
                desired_files[path]
            )
        ):
            raise CentralUpgradeError(
                "Central upgrade action digest "
                f"does not match: {path}"
            )

        if (
            kind == "update"
            and path not in rollback_files
        ):
            raise CentralUpgradeError(
                "Central upgrade update has no "
                f"rollback file: {path}"
            )

        if (
            kind == "create"
            and path in rollback_files
        ):
            raise CentralUpgradeError(
                "Central upgrade create unexpectedly "
                f"has rollback content: {path}"
            )

    expected_writes = (
        1 if actions else 0
    )

    if (
        plan.get("changed_file_count")
        != len(actions)
        or plan.get("estimated_writes")
        != expected_writes
    ):
        raise CentralUpgradeError(
            "Central upgrade action counts do "
            "not reconcile"
        )

    return LoadedCentralUpgradePlan(
        directory=root,
        plan=plan,
        digest=stable_digest(
            {
                "plan": plan,
                "checksums": checksums,
            }
        ),
        desired_files=desired_files,
        rollback_files=rollback_files,
    )


def commit_upgrade(
    client: GitLabCentralUpgradeClient,
    loaded: LoadedCentralUpgradePlan,
    actions: list[dict[str, Any]],
) -> tuple[int, str]:
    commit_actions: list[
        dict[str, Any]
    ] = []

    for action in sorted(
        actions,
        key=lambda value: value["path"],
    ):
        path = action["path"]

        try:
            content = (
                loaded.desired_files[path]
                .decode("utf-8")
            )
        except UnicodeDecodeError as error:
            raise CentralUpgradeError(
                "Managed central files must "
                f"be UTF-8 text: {path}"
            ) from error

        commit_action: dict[str, Any] = {
            "action": action["action"],
            "file_path": path,
            "content": content,
            "encoding": "text",
        }

        if action["action"] == "update":
            commit_action[
                "last_commit_id"
            ] = action[
                "expected_last_commit_id"
            ]

        commit_actions.append(
            commit_action
        )

    if not commit_actions:
        return 0, ""

    result = client.mutate_json(
        "POST",
        (
            f"{project_endpoint(
                loaded.plan['project']
            )}/repository/commits"
        ),
        {
            "branch": loaded.plan["branch"],
            "commit_message": (
                "Upgrade Wintermute managed "
                "central scan files"
            ),
            "actions": commit_actions,
        },
        expected_statuses={201},
    )
    payload = result.payload

    if not isinstance(payload, dict):
        raise CentralUpgradeError(
            "GitLab commit response is invalid"
        )

    commit_id = str(
        payload.get("id")
        or payload.get("short_id")
        or ""
    ).casefold()

    if (
        COMMIT_PATTERN.fullmatch(commit_id)
        is None
    ):
        raise CentralUpgradeError(
            "GitLab upgrade commit ID is invalid"
        )

    return 1, commit_id


def rollback_receipt(
    loaded: LoadedCentralUpgradePlan,
    *,
    mode: str,
    commit_id: str,
) -> dict[str, Any]:
    actions: list[
        dict[str, Any]
    ] = []

    for action in reversed(
        loaded.plan["actions"]
    ):
        path = action["path"]

        if action["action"] == "create":
            actions.append(
                {
                    "action": "delete",
                    "path": path,
                    "expected_applied_commit_id": (
                        commit_id
                    ),
                }
            )
        else:
            content = (
                loaded.rollback_files[path]
            )
            actions.append(
                {
                    "action": "update",
                    "path": path,
                    "rollback_sha256": (
                        sha256_bytes(content)
                    ),
                    "rollback_size": len(content),
                    "expected_applied_commit_id": (
                        commit_id
                    ),
                }
            )

    return {
        "schema_version": 1,
        "status": (
            "available"
            if mode == "apply"
            and commit_id
            else "not-required"
        ),
        "execution_mode": mode,
        "plan_id": (
            loaded.plan["plan_id"]
        ),
        "plan_digest": loaded.digest,
        "project": (
            loaded.plan["project"]
        ),
        "branch": loaded.plan["branch"],
        "applied_commit_id": commit_id,
        "rollback_files_directory": str(
            loaded.directory
            / "files"
            / "rollback"
        ),
        "actions": actions,
    }


def write_upgrade_result(
    root: str | Path,
    result: dict[str, Any],
    rollback: dict[str, Any],
) -> Path:
    execution_id = required_text(
        result.get("execution_id"),
        "Upgrade execution ID",
    )
    root_path = Path(root)
    staging = (
        root_path
        / ".staging"
        / execution_id
    )
    destination = (
        root_path / execution_id
    )

    if destination.exists():
        raise CentralUpgradeError(
            "Central upgrade result already "
            f"exists: {destination}"
        )

    staging.mkdir(
        parents=True,
        exist_ok=False,
    )
    names = (
        "result.json",
        "rollback.json",
    )

    try:
        atomic_write_json(
            staging / "result.json",
            result,
        )
        atomic_write_json(
            staging / "rollback.json",
            rollback,
        )
        atomic_write_json(
            staging / "checksums.json",
            {
                "schema_version": 1,
                "sha256": {
                    name: sha256_file(
                        staging / name
                    )
                    for name in names
                },
            },
        )
        root_path.mkdir(
            parents=True,
            exist_ok=True,
        )
        os.replace(
            staging,
            destination,
        )
        atomic_write_json(
            destination / "READY",
            {
                "schema_version": 1,
                "execution_id": (
                    execution_id
                ),
                "ready_at": now_text(),
            },
        )

        return destination

    except BaseException:
        shutil.rmtree(
            staging,
            ignore_errors=True,
        )
        raise


def execute_upgrade_plan(
    loaded: LoadedCentralUpgradePlan,
    client: GitLabCentralUpgradeClient,
    *,
    mode: str,
    result_root: str | Path,
    maximum_writes: int = 1,
    confirm_apply: bool = False,
    expected_plan_digest: str = "",
) -> tuple[
    int,
    dict[str, Any],
    Path,
]:
    if mode not in {
        "dry-run",
        "apply",
    }:
        raise ValueError(
            "Central upgrade mode is invalid"
        )

    if maximum_writes < 0:
        raise ValueError(
            "Central upgrade write budget "
            "cannot be negative"
        )

    if mode == "apply":
        if not confirm_apply:
            raise ValueError(
                "Central upgrade apply requires "
                "confirmation"
            )

        if (
            not expected_plan_digest
            or expected_plan_digest
            != loaded.digest
        ):
            raise ValueError(
                "Expected central upgrade-plan "
                "digest does not match"
            )

    before = inspect_upgrade_state(
        client,
        project=loaded.plan["project"],
        branch=loaded.plan["branch"],
        desired_files=(
            loaded.desired_files
        ),
        expected_current_bundle_digest=(
            loaded.plan[
                "previous_source_bundle_digest"
            ]
        ),
    )
    actions = before["actions"]
    estimated_writes = (
        1 if actions else 0
    )
    writes = 0
    commit_id = ""
    after = None

    if (
        before["observation_digest"]
        != loaded.plan[
            "observation_digest"
        ]
        or actions != loaded.plan["actions"]
    ):
        status = "blocked"
        outcome = "stale-plan"
    elif (
        estimated_writes
        > maximum_writes
    ):
        status = "blocked"
        outcome = "budget-exhausted"
    elif mode == "dry-run":
        status = "ok"
        outcome = (
            "planned"
            if actions
            else "already-satisfied"
        )
    else:
        writes, commit_id = (
            commit_upgrade(
                client,
                loaded,
                actions,
            )
        )
        after = inspect_upgrade_state(
            client,
            project=loaded.plan["project"],
            branch=loaded.plan["branch"],
            desired_files=(
                loaded.desired_files
            ),
            expected_current_bundle_digest=(
                loaded.plan[
                    "source_bundle_digest"
                ]
            ),
        )
        verified = (
            after["actions"] == []
            and after[
                "current_manifest"
            ]["source_bundle_digest"]
            == loaded.plan[
                "source_bundle_digest"
            ]
        )
        status = (
            "ok"
            if verified
            else "failed"
        )
        outcome = (
            "applied"
            if verified
            else "verification-failed"
        )

    result = {
        "schema_version": 1,
        "execution_id": (
            create_execution_id()
        ),
        "plan_id": (
            loaded.plan["plan_id"]
        ),
        "plan_digest": loaded.digest,
        "project": loaded.plan["project"],
        "project_id": (
            loaded.plan["project_id"]
        ),
        "branch": loaded.plan["branch"],
        "mode": mode,
        "status": status,
        "outcome": outcome,
        "previous_source_bundle_digest": (
            loaded.plan[
                "previous_source_bundle_digest"
            ]
        ),
        "source_bundle_digest": (
            loaded.plan[
                "source_bundle_digest"
            ]
        ),
        "changed_file_count": len(
            actions
        ),
        "estimated_writes": (
            estimated_writes
        ),
        "writes": writes,
        "commit_id": commit_id,
        "requests": client.requests,
        "transport_writes": client.writes,
        "before": {
            "observation": (
                before["observation"]
            ),
            "observation_digest": (
                before[
                    "observation_digest"
                ]
            ),
            "actions": actions,
        },
        "after": (
            {
                "observation": (
                    after["observation"]
                ),
                "observation_digest": (
                    after[
                        "observation_digest"
                    ]
                ),
                "actions": (
                    after["actions"]
                ),
            }
            if after is not None
            else None
        ),
        "completed_at": now_text(),
    }
    rollback = rollback_receipt(
        loaded,
        mode=mode,
        commit_id=commit_id,
    )
    path = write_upgrade_result(
        result_root,
        result,
        rollback,
    )

    return (
        0 if status == "ok" else 1,
        result,
        path,
    )
