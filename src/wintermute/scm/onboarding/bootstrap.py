from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from wintermute.ai.models import stable_digest
from wintermute.ai.storage import (
    atomic_write_json,
    sha256_file,
)


class BootstrapArtifactError(RuntimeError):
    pass


@dataclass(frozen=True)
class LoadedCentralBundle:
    directory: Path
    bundle_id: str
    managed: dict[str, Any]
    digest: str
    files: dict[str, bytes]


@dataclass(frozen=True)
class LoadedBootstrapPlan:
    directory: Path
    plan: dict[str, Any]
    digest: str
    files: dict[
        str,
        dict[str, bytes],
    ]


@dataclass(frozen=True)
class GitHubBootstrapTarget:
    organization: str
    repository: str = (
        "wintermute-security-scans"
    )
    default_branch: str = "main"


@dataclass(frozen=True)
class GitLabBootstrapTarget:
    namespace: str = ""
    namespace_type: str = "group"
    project: str = (
        "wintermute-security-scans"
    )
    default_branch: str = "main"
    group: str = ""

    def resolved_namespace(self) -> str:
        selected_namespace = str(
            self.namespace or ""
        ).strip("/")
        selected_group = str(
            self.group or ""
        ).strip("/")

        if (
            selected_namespace
            and selected_group
            and selected_namespace.casefold()
            != selected_group.casefold()
        ):
            raise ValueError(
                "GitLab namespace and group "
                "values conflict"
            )

        selected = (
            selected_namespace
            or selected_group
        )

        return validate_namespace(selected)

    def resolved_namespace_type(self) -> str:
        selected = str(
            self.namespace_type or ""
        ).strip().casefold()

        if self.group and not self.namespace:
            selected = "group"

        if selected not in {
            "group",
            "user",
        }:
            raise ValueError(
                "GitLab namespace type must be "
                "group or user"
            )

        return selected


def now_text() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def safe_relative_path(value: str) -> str:
    selected = str(value or "").strip()
    path = PurePosixPath(selected)

    if (
        not selected
        or selected.startswith("/")
        or ".." in path.parts
        or "\\" in selected
    ):
        raise BootstrapArtifactError(
            f"Unsafe managed path: {value!r}"
        )

    return path.as_posix()


def read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8")
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        raise BootstrapArtifactError(
            f"Could not read {path}: {error}"
        ) from error

    if not isinstance(value, dict):
        raise BootstrapArtifactError(
            f"Artifact is not an object: {path}"
        )

    return value


def json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def load_verified_central_bundle(
    directory: str | Path,
) -> LoadedCentralBundle:
    root = Path(directory).expanduser()

    if not root.is_dir():
        raise BootstrapArtifactError(
            f"Central bundle does not exist: {root}"
        )

    ready = read_object(root / "READY")
    managed = read_object(
        root / "wintermute-managed.json"
    )
    checksums = read_object(
        root / "checksums.json"
    ).get("sha256")

    if not isinstance(checksums, dict):
        raise BootstrapArtifactError(
            "Central bundle checksums are invalid"
        )

    files: dict[str, bytes] = {}

    for raw_name, raw_digest in checksums.items():
        name = safe_relative_path(
            str(raw_name)
        )
        expected = str(
            raw_digest or ""
        )

        if not expected:
            raise BootstrapArtifactError(
                f"Missing checksum for {name}"
            )

        path = root / name

        try:
            actual = sha256_file(path)
            content = path.read_bytes()
        except OSError as error:
            raise BootstrapArtifactError(
                f"Could not read {name}: {error}"
            ) from error

        if actual != expected:
            raise BootstrapArtifactError(
                f"Checksum mismatch for {name}"
            )

        files[name] = content

    bundle_identifier = str(
        managed.get("bundle_id") or ""
    )

    if (
        not bundle_identifier
        or ready.get("bundle_id")
        != bundle_identifier
    ):
        raise BootstrapArtifactError(
            "Central bundle identity is invalid"
        )

    if (
        "registry/scan-registry.json"
        not in files
    ):
        raise BootstrapArtifactError(
            "Central bundle has no scan registry"
        )

    if managed.get(
        "management_mode"
    ) != "initialize-only":
        raise BootstrapArtifactError(
            "Central bundle management mode "
            "is not initialize-only"
        )

    return LoadedCentralBundle(
        directory=root,
        bundle_id=bundle_identifier,
        managed=managed,
        digest=stable_digest(
            {
                "managed": managed,
                "checksums": checksums,
            }
        ),
        files=files,
    )


def repository_manifest(
    bundle: LoadedCentralBundle,
    *,
    provider: str,
    repository: str,
    managed_files: dict[str, bytes],
) -> bytes:
    return json_bytes(
        {
            "schema_version": 1,
            "owner": "wintermute",
            "management_mode": (
                "initialize-only"
            ),
            "provider": provider,
            "repository": repository,
            "source_bundle_id": (
                bundle.bundle_id
            ),
            "source_bundle_digest": (
                bundle.digest
            ),
            "managed_files": {
                path: hashlib.sha256(
                    content
                ).hexdigest()
                for path, content
                in sorted(
                    managed_files.items()
                )
            },
        }
    )


def provider_files(
    bundle: LoadedCentralBundle,
    provider: str,
    repository: str,
) -> dict[str, bytes]:
    files = {
        "registry/scan-registry.json": (
            bundle.files[
                "registry/scan-registry.json"
            ]
        ),
    }

    if provider == "github":
        source = (
            ".github/workflows/"
            "wintermute-security.yml"
        )

        if source not in bundle.files:
            raise BootstrapArtifactError(
                "Central bundle has no GitHub "
                "workflow"
            )

        files[source] = bundle.files[source]

    elif provider == "gitlab":
        source = (
            "templates/"
            "wintermute-security.yml"
        )

        if source not in bundle.files:
            raise BootstrapArtifactError(
                "Central bundle has no GitLab "
                "template"
            )

        files[source] = bundle.files[source]

    else:
        raise BootstrapArtifactError(
            "Unsupported bootstrap provider"
        )

    files["wintermute-managed.json"] = (
        repository_manifest(
            bundle,
            provider=provider,
            repository=repository,
            managed_files=files,
        )
    )

    return files


def validate_repository_name(
    value: str,
) -> str:
    selected = str(value or "").strip()

    if (
        not selected
        or "/" in selected
        or selected in {".", ".."}
        or any(
            character.isspace()
            for character in selected
        )
    ):
        raise ValueError(
            "Central repository name is invalid"
        )

    return selected


def validate_namespace(
    value: str,
) -> str:
    selected = str(value or "").strip(
        "/"
    )

    if (
        not selected
        or any(
            not part
            or part in {".", ".."}
            for part in selected.split("/")
        )
    ):
        raise ValueError(
            "SCM namespace is invalid"
        )

    return selected


def build_bootstrap_plan(
    bundle: LoadedCentralBundle,
    *,
    github: (
        GitHubBootstrapTarget | None
    ) = None,
    gitlab: (
        GitLabBootstrapTarget | None
    ) = None,
) -> tuple[
    dict[str, Any],
    dict[str, dict[str, bytes]],
]:
    repositories: list[
        dict[str, Any]
    ] = []
    files: dict[
        str,
        dict[str, bytes],
    ] = {}

    if github is not None:
        organization = validate_namespace(
            github.organization
        )
        repository = validate_repository_name(
            github.repository
        )
        full_name = (
            f"{organization}/{repository}"
        )
        provider_content = provider_files(
            bundle,
            "github",
            full_name,
        )
        files["github"] = provider_content
        repositories.append(
            {
                "provider": "github",
                "namespace": organization,
                "namespace_type": (
                    "organization"
                ),
                "repository": repository,
                "name_with_owner": full_name,
                "visibility": "private",
                "default_branch": (
                    github.default_branch
                ),
                "management_mode": (
                    "initialize-only"
                ),
                "files": [
                    {
                        "path": path,
                        "sha256": hashlib.sha256(
                            content
                        ).hexdigest(),
                        "size": len(content),
                    }
                    for path, content
                    in sorted(
                        provider_content.items()
                    )
                ],
            }
        )

    if gitlab is not None:
        namespace = (
            gitlab.resolved_namespace()
        )
        namespace_type = (
            gitlab
            .resolved_namespace_type()
        )
        project = validate_repository_name(
            gitlab.project
        )
        full_name = (
            f"{namespace}/{project}"
        )
        provider_content = provider_files(
            bundle,
            "gitlab",
            full_name,
        )
        files["gitlab"] = provider_content
        repositories.append(
            {
                "provider": "gitlab",
                "namespace": namespace,
                "namespace_type": (
                    namespace_type
                ),
                "repository": project,
                "name_with_owner": full_name,
                "visibility": "private",
                "default_branch": (
                    gitlab.default_branch
                ),
                "management_mode": (
                    "initialize-only"
                ),
                "files": [
                    {
                        "path": path,
                        "sha256": hashlib.sha256(
                            content
                        ).hexdigest(),
                        "size": len(content),
                    }
                    for path, content
                    in sorted(
                        provider_content.items()
                    )
                ],
            }
        )

    if not repositories:
        raise ValueError(
            "At least one central repository "
            "target is required"
        )

    plan = {
        "schema_version": 1,
        "plan_id": (
            datetime.now(
                timezone.utc
            ).strftime("%Y%m%dT%H%M%SZ")
            + "-central-bootstrap-"
            + uuid.uuid4().hex[:12]
        ),
        "created_at": now_text(),
        "status": "review-required",
        "mutation_allowed": False,
        "source_bundle_id": (
            bundle.bundle_id
        ),
        "source_bundle_digest": (
            bundle.digest
        ),
        "repository_count": len(
            repositories
        ),
        "repositories": sorted(
            repositories,
            key=lambda value: (
                value["provider"],
                value["name_with_owner"],
            ),
        ),
        "review_requirements": [
            "review-central-repository-names",
            "review-managed-files",
            "review-write-budget",
            "confirm-initialize-only-bootstrap",
        ],
    }

    return plan, files


def write_bootstrap_plan(
    root: str | Path,
    plan: dict[str, Any],
    files: dict[
        str,
        dict[str, bytes],
    ],
) -> Path:
    root_path = Path(root)
    plan_id = str(
        plan.get("plan_id") or ""
    )
    staging = (
        root_path / ".staging" / plan_id
    )
    destination = root_path / plan_id

    if not plan_id:
        raise ValueError(
            "Bootstrap plan has no plan ID"
        )

    if destination.exists():
        raise RuntimeError(
            f"Bootstrap plan already exists: "
            f"{destination}"
        )

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

        for provider, provider_files_map in (
            sorted(files.items())
        ):
            for relative, content in sorted(
                provider_files_map.items()
            ):
                path = (
                    staging
                    / "files"
                    / provider
                    / relative
                )
                path.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )
                path.write_bytes(content)
                key = (
                    f"files/{provider}/"
                    f"{relative}"
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


def load_verified_bootstrap_plan(
    directory: str | Path,
) -> LoadedBootstrapPlan:
    root = Path(directory).expanduser()

    if not root.is_dir():
        raise BootstrapArtifactError(
            f"Bootstrap plan does not exist: "
            f"{root}"
        )

    ready = read_object(root / "READY")
    plan = read_object(root / "plan.json")
    checksums = read_object(
        root / "checksums.json"
    ).get("sha256")

    if not isinstance(checksums, dict):
        raise BootstrapArtifactError(
            "Bootstrap checksums are invalid"
        )

    for raw_name, raw_digest in checksums.items():
        name = safe_relative_path(
            str(raw_name)
        )
        expected = str(
            raw_digest or ""
        )

        try:
            actual = sha256_file(
                root / name
            )
        except OSError as error:
            raise BootstrapArtifactError(
                f"Could not read {name}: {error}"
            ) from error

        if actual != expected:
            raise BootstrapArtifactError(
                f"Checksum mismatch for {name}"
            )

    plan_id = str(
        plan.get("plan_id") or ""
    )

    if (
        not plan_id
        or ready.get("plan_id")
        != plan_id
    ):
        raise BootstrapArtifactError(
            "Bootstrap plan identity is invalid"
        )

    if (
        plan.get("status")
        != "review-required"
        or plan.get("mutation_allowed")
        is not False
    ):
        raise BootstrapArtifactError(
            "Bootstrap plan is not safely staged"
        )

    repositories = plan.get(
        "repositories"
    )

    if (
        not isinstance(repositories, list)
        or not repositories
    ):
        raise BootstrapArtifactError(
            "Bootstrap repository list "
            "is invalid"
        )

    files: dict[
        str,
        dict[str, bytes],
    ] = {}

    for repository in repositories:
        if not isinstance(repository, dict):
            raise BootstrapArtifactError(
                "Bootstrap repository is invalid"
            )

        provider = str(
            repository.get("provider")
            or ""
        )
        namespace_type = str(
            repository.get(
                "namespace_type"
            )
            or ""
        )

        if provider not in {
            "github",
            "gitlab",
        }:
            raise BootstrapArtifactError(
                "Bootstrap provider is invalid"
            )

        if (
            provider == "github"
            and namespace_type
            != "organization"
        ):
            raise BootstrapArtifactError(
                "GitHub namespace type is invalid"
            )

        if (
            provider == "gitlab"
            and namespace_type
            not in {"group", "user"}
        ):
            raise BootstrapArtifactError(
                "GitLab namespace type is invalid"
            )

        provider_files_map: dict[
            str,
            bytes,
        ] = {}

        for descriptor in repository.get(
            "files",
            [],
        ):
            if not isinstance(
                descriptor,
                dict,
            ):
                raise BootstrapArtifactError(
                    "Bootstrap file descriptor "
                    "is invalid"
                )

            relative = safe_relative_path(
                str(
                    descriptor.get("path")
                    or ""
                )
            )
            key = (
                f"files/{provider}/"
                f"{relative}"
            )

            if key not in checksums:
                raise BootstrapArtifactError(
                    "Missing bootstrap file "
                    f"checksum: {key}"
                )

            content = (
                root / key
            ).read_bytes()

            if (
                hashlib.sha256(
                    content
                ).hexdigest()
                != descriptor.get("sha256")
            ):
                raise BootstrapArtifactError(
                    "Bootstrap file descriptor "
                    f"does not match: {relative}"
                )

            provider_files_map[
                relative
            ] = content

        if (
            "wintermute-managed.json"
            not in provider_files_map
        ):
            raise BootstrapArtifactError(
                "Bootstrap ownership manifest "
                "is missing"
            )

        files[provider] = (
            provider_files_map
        )

    return LoadedBootstrapPlan(
        directory=root,
        plan=plan,
        digest=stable_digest(
            {
                "plan": plan,
                "checksums": checksums,
            }
        ),
        files=files,
    )
