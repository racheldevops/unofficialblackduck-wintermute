from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from wintermute.ai.models import stable_digest
from wintermute.ai.storage import (
    atomic_write_json,
    sha256_file,
)
from wintermute.scm.onboarding.artifacts import (
    write_execution_result,
)
from wintermute.scm.onboarding.http import (
    OnboardingHttpClient,
)


_SEGMENT = r"[^/?#]+"
POLICY_STATES = {
    "disabled",
    "pilot",
}
LINK_SCOPES = {
    "group",
    "project",
}
_POLICY_ROUTES = {
    "GET": (
        re.compile(
            rf"^/projects/{_SEGMENT}/"
            rf"repository/files/{_SEGMENT}$"
        ),
        re.compile(
            r"^/projects/[0-9]+/"
            r"security_policy_project$"
        ),
    ),
    "POST": (
        re.compile(
            r"^/groups/[0-9]+/"
            r"security_policy_project$"
        ),
        re.compile(
            r"^/projects/[0-9]+/"
            r"security_policy_project$"
        ),
        re.compile(
            rf"^/projects/{_SEGMENT}/"
            r"repository/commits$"
        ),
    ),
}


class PolicyPilotError(RuntimeError):
    pass


class GitLabPolicyClient(
    OnboardingHttpClient
):
    def _validate_route(
        self,
        method: str,
        path: str,
    ) -> None:
        patterns = _POLICY_ROUTES.get(
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
class PolicyConfiguration:
    link_scope: str
    target_project: str
    target_group: str
    policy_project: str
    policy_namespace_type: str
    central_project: str
    pilot_project: str
    policy_file: str = (
        ".gitlab/security-policies/"
        "policy.yml"
    )
    ownership_file: str = (
        "wintermute-managed.json"
    )
    template_file: str = (
        "templates/"
        "wintermute-security.yml"
    )
    template_ref: str = "main"
    policy_name: str = (
        "Wintermute Black Duck SCA Pilot"
    )
    default_branch: str = "main"
    state: str = "disabled"

    @property
    def policy_namespace(self) -> str:
        return self.policy_project.rsplit(
            "/",
            1,
        )[0]

    @property
    def policy_project_name(self) -> str:
        return self.policy_project.rsplit(
            "/",
            1,
        )[1]

    @property
    def link_target(self) -> str:
        return (
            self.target_project
            if self.link_scope == "project"
            else self.target_group
        )

    def validate(self) -> None:
        if self.link_scope not in LINK_SCOPES:
            raise ValueError(
                "Policy link scope must be "
                "group or project"
            )

        validate_project_path(
            self.policy_project,
            "policy_project",
        )
        validate_project_path(
            self.central_project,
            "central_project",
        )
        validate_project_path(
            self.pilot_project,
            "pilot_project",
        )

        if self.link_scope == "project":
            validate_project_path(
                self.target_project,
                "target_project",
            )

            if (
                self.target_project
                != self.pilot_project
            ):
                raise ValueError(
                    "Project-linked pilot policy "
                    "must target the pilot project"
                )
        else:
            validate_group_path(
                self.target_group,
                "target_group",
            )

        if (
            self.policy_namespace_type
            not in {"group", "user"}
        ):
            raise ValueError(
                "Policy namespace type must be "
                "group or user"
            )

        if self.state not in POLICY_STATES:
            raise ValueError(
                "Policy state must be disabled "
                "or pilot"
            )

        for name in (
            "policy_file",
            "ownership_file",
            "template_file",
        ):
            validate_file_path(
                getattr(self, name),
                name,
            )

        if not self.template_ref.strip():
            raise ValueError(
                "Template ref is required"
            )

        if not self.policy_name.strip():
            raise ValueError(
                "Policy name is required"
            )

        if not self.default_branch.strip():
            raise ValueError(
                "Policy default branch is required"
            )


@dataclass(frozen=True)
class LoadedPolicyPlan:
    directory: Path
    plan: dict[str, Any]
    files: dict[str, bytes]
    digest: str


def now_text() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def validate_segments(
    value: str,
    field: str,
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
            f"{field} is invalid"
        )

    return selected


def validate_group_path(
    value: str,
    field: str,
) -> str:
    return validate_segments(
        value,
        field,
    )


def validate_project_path(
    value: str,
    field: str,
) -> str:
    selected = validate_segments(
        value,
        field,
    )

    if selected.count("/") < 1:
        raise ValueError(
            f"{field} must use namespace/name"
        )

    return selected


def validate_file_path(
    value: str,
    field: str,
) -> str:
    selected = str(value or "").strip(
        "/"
    )
    path = Path(selected)

    if (
        not selected
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in selected
    ):
        raise ValueError(
            f"{field} is invalid"
        )

    return path.as_posix()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def policy_text(
    configuration: PolicyConfiguration,
    *,
    pilot_project_id: int,
) -> str:
    enabled = (
        "true"
        if configuration.state == "pilot"
        else "false"
    )

    return "\n".join(
        [
            "pipeline_execution_policy:",
            (
                "  - name: "
                + json.dumps(
                    configuration.policy_name
                )
            ),
            (
                "    description: "
                + json.dumps(
                    "Wintermute central "
                    "Black Duck scan pilot"
                )
            ),
            f"    enabled: {enabled}",
            (
                "    pipeline_config_strategy: "
                "inject_policy"
            ),
            "    policy_scope:",
            "      projects:",
            "        including:",
            (
                "          - id: "
                f"{pilot_project_id}"
            ),
            "    content:",
            "      include:",
            (
                "        - project: "
                + json.dumps(
                    configuration
                    .central_project
                )
            ),
            (
                "          file: "
                + json.dumps(
                    configuration
                    .template_file
                )
            ),
            (
                "          ref: "
                + json.dumps(
                    configuration
                    .template_ref
                )
            ),
            "    suffix: on_conflict",
            "    variables_override:",
            "      allowed: false",
            "",
        ]
    )


def ownership_manifest(
    configuration: PolicyConfiguration,
    *,
    link_target_id: int,
    pilot_project_id: int,
    policy_content: bytes,
) -> bytes:
    payload = {
        "schema_version": 2,
        "owner": "wintermute",
        "management_mode": (
            "explicit-policy-transition"
        ),
        "policy_state": (
            configuration.state
        ),
        "link_target": {
            "scope": (
                configuration.link_scope
            ),
            "path": (
                configuration.link_target
            ),
            "id": link_target_id,
        },
        "pilot_project": {
            "path": (
                configuration.pilot_project
            ),
            "id": pilot_project_id,
        },
        "central_project": (
            configuration.central_project
        ),
        "template_file": (
            configuration.template_file
        ),
        "template_ref": (
            configuration.template_ref
        ),
        "policy_file": (
            configuration.policy_file
        ),
        "managed_files": {
            configuration.policy_file: (
                sha256_bytes(
                    policy_content
                )
            ),
        },
    }

    return (
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def get_object(
    client: GitLabPolicyClient,
    path: str,
    *,
    allow_not_found: bool = False,
) -> dict[str, Any] | None:
    result = client.get_json(
        path,
        allow_not_found=allow_not_found,
    )

    if result.status_code == 404:
        return None

    if not isinstance(result.payload, dict):
        raise PolicyPilotError(
            f"GitLab response is invalid: "
            f"{path}"
        )

    return dict(result.payload)


def exact_project(
    client: GitLabPolicyClient,
    project_path: str,
    *,
    allow_not_found: bool = False,
) -> dict[str, Any] | None:
    payload = get_object(
        client,
        (
            f"/projects/"
            f"{quote(project_path, safe='')}"
        ),
        allow_not_found=allow_not_found,
    )

    if payload is None:
        return None

    if (
        str(
            payload.get(
                "path_with_namespace"
            )
            or ""
        )
        != project_path
    ):
        raise PolicyPilotError(
            "GitLab returned another project"
        )

    return payload


def exact_group(
    client: GitLabPolicyClient,
    group_path: str,
) -> dict[str, Any]:
    payload = get_object(
        client,
        (
            f"/groups/"
            f"{quote(group_path, safe='')}"
        ),
    )

    assert payload is not None

    returned = str(
        payload.get("full_path")
        or payload.get("path")
        or ""
    )

    if returned != group_path:
        raise PolicyPilotError(
            "GitLab returned another group"
        )

    return payload


def numeric_id(
    payload: dict[str, Any],
    field: str,
) -> int:
    try:
        selected = int(payload["id"])
    except (
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise PolicyPilotError(
            f"{field} has no numeric ID"
        ) from error

    if selected < 1:
        raise PolicyPilotError(
            f"{field} ID is invalid"
        )

    return selected


def link_target(
    client: GitLabPolicyClient,
    configuration: PolicyConfiguration,
) -> tuple[int, dict[str, Any]]:
    if configuration.link_scope == "project":
        payload = exact_project(
            client,
            configuration.target_project,
        )
        assert payload is not None

        return (
            numeric_id(
                payload,
                "Policy target project",
            ),
            payload,
        )

    payload = exact_group(
        client,
        configuration.target_group,
    )

    return (
        numeric_id(
            payload,
            "Policy target group",
        ),
        payload,
    )


def link_endpoint(
    configuration: PolicyConfiguration,
    link_target_id: int,
) -> str:
    return (
        f"/{configuration.link_scope}s/"
        f"{link_target_id}/"
        "security_policy_project"
    )


def linked_policy_project_id(
    client: GitLabPolicyClient,
    configuration: PolicyConfiguration,
    link_target_id: int,
) -> int | None:
    payload = get_object(
        client,
        link_endpoint(
            configuration,
            link_target_id,
        ),
        allow_not_found=True,
    )

    if payload is None:
        return None

    nested = payload.get(
        "security_policy_project"
    )

    if isinstance(nested, dict):
        payload = nested

    return numeric_id(
        payload,
        "Linked security-policy project",
    )


def file_paths(
    project_path: str,
    file_path: str,
) -> tuple[str, str]:
    base = (
        f"/projects/"
        f"{quote(project_path, safe='')}/"
        "repository/files/"
        f"{quote(file_path, safe='')}"
    )

    return base, f"{base}/raw"


def read_file(
    client: GitLabPolicyClient,
    project_path: str,
    file_path: str,
    branch: str,
) -> tuple[
    bytes,
    str,
] | None:
    metadata_path, raw_path = file_paths(
        project_path,
        file_path,
    )
    metadata_result = client.get_json(
        metadata_path,
        params={"ref": branch},
        allow_not_found=True,
    )

    if metadata_result.status_code == 404:
        return None

    if not isinstance(
        metadata_result.payload,
        dict,
    ):
        raise PolicyPilotError(
            "GitLab file metadata is invalid"
        )

    last_commit_id = str(
        metadata_result.payload.get(
            "last_commit_id"
        )
        or ""
    )

    if not last_commit_id:
        raise PolicyPilotError(
            "GitLab file has no last commit ID"
        )

    raw_result = client.get_bytes(
        raw_path,
        params={"ref": branch},
    )

    return (
        bytes(raw_result.payload),
        last_commit_id,
    )


def parse_manifest(
    content: bytes,
) -> dict[str, Any]:
    try:
        payload = json.loads(
            content.decode("utf-8")
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise PolicyPilotError(
            "Policy ownership manifest "
            "is invalid"
        ) from error

    if not isinstance(payload, dict):
        raise PolicyPilotError(
            "Policy ownership manifest "
            "is not an object"
        )

    return payload


def manifest_is_managed(
    manifest: dict[str, Any],
    policy_content: bytes,
    configuration: PolicyConfiguration,
) -> bool:
    return (
        manifest.get("owner")
        == "wintermute"
        and manifest.get(
            "management_mode"
        )
        == "explicit-policy-transition"
        and manifest.get(
            "managed_files",
            {},
        ).get(
            configuration.policy_file
        )
        == sha256_bytes(policy_content)
    )


def manifest_matches_identity(
    manifest: dict[str, Any],
    configuration: PolicyConfiguration,
    *,
    link_target_id: int,
    pilot_project_id: int,
) -> bool:
    return (
        manifest.get("link_target")
        == {
            "scope": (
                configuration.link_scope
            ),
            "path": (
                configuration.link_target
            ),
            "id": link_target_id,
        }
        and manifest.get(
            "pilot_project"
        )
        == {
            "path": (
                configuration.pilot_project
            ),
            "id": pilot_project_id,
        }
        and manifest.get(
            "central_project"
        )
        == configuration.central_project
        and manifest.get(
            "template_file"
        )
        == configuration.template_file
        and manifest.get(
            "template_ref"
        )
        == configuration.template_ref
        and manifest.get(
            "policy_file"
        )
        == configuration.policy_file
    )


def previous_link(
    manifest: dict[str, Any],
) -> tuple[str, str]:
    target = manifest.get(
        "link_target"
    )

    if isinstance(target, dict):
        scope = str(
            target.get("scope") or ""
        )
        path = str(
            target.get("path") or ""
        )

        if (
            scope in LINK_SCOPES
            and path
        ):
            return scope, path

    legacy_group = manifest.get(
        "target_group"
    )

    if isinstance(
        legacy_group,
        dict,
    ):
        path = str(
            legacy_group.get("path")
            or ""
        )

        if path:
            return "group", path

    return "", ""


def previous_link_conflicts(
    client: GitLabPolicyClient,
    manifest: dict[str, Any],
    configuration: PolicyConfiguration,
    policy_project_id: int,
) -> bool:
    previous_scope, previous_path = (
        previous_link(manifest)
    )

    if (
        not previous_scope
        or (
            previous_scope
            == configuration.link_scope
            and previous_path
            == configuration.link_target
        )
    ):
        return False

    try:
        if previous_scope == "project":
            target = exact_project(
                client,
                previous_path,
            )
        else:
            target = exact_group(
                client,
                previous_path,
            )
    except Exception:
        return True

    assert target is not None
    previous_id = numeric_id(
        target,
        "Previous policy link target",
    )
    previous_configuration = (
        PolicyConfiguration(
            link_scope=previous_scope,
            target_project=(
                previous_path
                if previous_scope
                == "project"
                else ""
            ),
            target_group=(
                previous_path
                if previous_scope
                == "group"
                else ""
            ),
            policy_project=(
                configuration.policy_project
            ),
            policy_namespace_type=(
                configuration
                .policy_namespace_type
            ),
            central_project=(
                configuration.central_project
            ),
            pilot_project=(
                configuration.pilot_project
            ),
            state="disabled",
        )
    )
    linked_id = (
        linked_policy_project_id(
            client,
            previous_configuration,
            previous_id,
        )
    )

    return (
        linked_id is not None
        and linked_id
        == policy_project_id
    )


def namespace_creation_id(
    client: GitLabPolicyClient,
    configuration: PolicyConfiguration,
) -> int | None:
    namespace = (
        configuration.policy_namespace
    )

    if (
        configuration
        .policy_namespace_type
        == "user"
    ):
        user = get_object(
            client,
            "/user",
        )
        assert user is not None
        username = str(
            user.get("username") or ""
        )

        if username != namespace:
            raise PolicyPilotError(
                "GitLab token user does not "
                "match the policy user namespace"
            )

        return None

    group = exact_group(
        client,
        namespace,
    )

    return numeric_id(
        group,
        "Policy namespace group",
    )


def desired_files(
    configuration: PolicyConfiguration,
    *,
    link_target_id: int,
    pilot_project_id: int,
) -> dict[str, bytes]:
    policy = policy_text(
        configuration,
        pilot_project_id=(
            pilot_project_id
        ),
    ).encode("utf-8")
    manifest = ownership_manifest(
        configuration,
        link_target_id=link_target_id,
        pilot_project_id=(
            pilot_project_id
        ),
        policy_content=policy,
    )

    return {
        configuration.policy_file: policy,
        configuration.ownership_file: (
            manifest
        ),
    }


def inspect_policy_state(
    client: GitLabPolicyClient,
    configuration: PolicyConfiguration,
) -> dict[str, Any]:
    configuration.validate()
    link_target_id, _ = link_target(
        client,
        configuration,
    )
    pilot_project = exact_project(
        client,
        configuration.pilot_project,
    )
    central_project = exact_project(
        client,
        configuration.central_project,
    )

    assert pilot_project is not None
    assert central_project is not None

    pilot_project_id = numeric_id(
        pilot_project,
        "Pilot project",
    )
    numeric_id(
        central_project,
        "Central project",
    )
    files = desired_files(
        configuration,
        link_target_id=link_target_id,
        pilot_project_id=(
            pilot_project_id
        ),
    )
    policy_project = exact_project(
        client,
        configuration.policy_project,
        allow_not_found=True,
    )
    linked_id = linked_policy_project_id(
        client,
        configuration,
        link_target_id,
    )
    actions: list[dict[str, Any]] = []
    status = "ready"
    reason = ""
    observed: dict[str, Any] = {
        "link_scope": (
            configuration.link_scope
        ),
        "link_target": (
            configuration.link_target
        ),
        "link_target_id": (
            link_target_id
        ),
        "pilot_project_id": (
            pilot_project_id
        ),
        "policy_project_exists": (
            policy_project is not None
        ),
        "linked_policy_project_id": (
            linked_id
        ),
    }

    if policy_project is None:
        if configuration.state == "pilot":
            status = "blocked"
            reason = (
                "Pilot activation requires an "
                "existing disabled policy project"
            )
        elif linked_id is not None:
            status = "conflict"
            reason = (
                "Policy target is linked to "
                "another security-policy project"
            )
        else:
            actions = [
                {
                    "kind": (
                        "gitlab.policy-project.create"
                    ),
                },
                {
                    "kind": (
                        "gitlab.policy-files."
                        "commit-create"
                    ),
                },
                {
                    "kind": (
                        "gitlab.policy-target.link"
                    ),
                    "link_target_id": (
                        link_target_id
                    ),
                },
            ]

    else:
        policy_project_id = numeric_id(
            policy_project,
            "Policy project",
        )
        observed["policy_project_id"] = (
            policy_project_id
        )

        if (
            policy_project.get("visibility")
            != "private"
        ):
            status = "conflict"
            reason = (
                "Policy project is not private"
            )
        elif (
            policy_project.get(
                "default_branch"
            )
            != configuration.default_branch
        ):
            status = "conflict"
            reason = (
                "Policy project uses another "
                "default branch"
            )
        elif (
            linked_id is not None
            and linked_id
            != policy_project_id
        ):
            status = "conflict"
            reason = (
                "Policy target is linked to "
                "another security-policy project"
            )
        else:
            current_policy = read_file(
                client,
                configuration.policy_project,
                configuration.policy_file,
                configuration.default_branch,
            )
            current_manifest = read_file(
                client,
                configuration.policy_project,
                configuration.ownership_file,
                configuration.default_branch,
            )

            if (
                current_policy is None
                or current_manifest is None
            ):
                status = "conflict"
                reason = (
                    "Existing policy project lacks "
                    "Wintermute-managed files"
                )
            else:
                (
                    policy_content,
                    policy_commit,
                ) = current_policy
                (
                    manifest_content,
                    manifest_commit,
                ) = current_manifest
                manifest = parse_manifest(
                    manifest_content
                )
                observed[
                    "current_policy_sha256"
                ] = sha256_bytes(
                    policy_content
                )
                observed[
                    "current_policy_state"
                ] = manifest.get(
                    "policy_state"
                )
                observed["last_commit_ids"] = {
                    configuration.policy_file: (
                        policy_commit
                    ),
                    configuration
                    .ownership_file: (
                        manifest_commit
                    ),
                }

                if not manifest_is_managed(
                    manifest,
                    policy_content,
                    configuration,
                ):
                    status = "conflict"
                    reason = (
                        "Customer-modified policy "
                        "file will not be overwritten"
                    )
                elif (
                    not manifest_matches_identity(
                        manifest,
                        configuration,
                        link_target_id=(
                            link_target_id
                        ),
                        pilot_project_id=(
                            pilot_project_id
                        ),
                    )
                    and manifest.get(
                        "policy_state"
                    )
                    != "disabled"
                ):
                    status = "conflict"
                    reason = (
                        "Active policy identity "
                        "cannot be retargeted"
                    )
                elif previous_link_conflicts(
                    client,
                    manifest,
                    configuration,
                    policy_project_id,
                ):
                    status = "conflict"
                    reason = (
                        "Policy project remains "
                        "linked to its previous target"
                    )
                elif (
                    policy_content
                    != files[
                        configuration.policy_file
                    ]
                    or manifest_content
                    != files[
                        configuration.ownership_file
                    ]
                ):
                    actions.append(
                        {
                            "kind": (
                                "gitlab.policy-files."
                                "commit-update"
                            ),
                            "last_commit_ids": {
                                configuration
                                .policy_file: (
                                    policy_commit
                                ),
                                configuration
                                .ownership_file: (
                                    manifest_commit
                                ),
                            },
                        }
                    )

            if (
                status == "ready"
                and linked_id is None
            ):
                actions.append(
                    {
                        "kind": (
                            "gitlab.policy-target.link"
                        ),
                        "link_target_id": (
                            link_target_id
                        ),
                        "policy_project_id": (
                            policy_project_id
                        ),
                    }
                )

    return {
        "status": status,
        "reason": reason,
        "state": configuration.state,
        "configuration": {
            "link_scope": (
                configuration.link_scope
            ),
            "target_project": (
                configuration.target_project
            ),
            "target_group": (
                configuration.target_group
            ),
            "policy_project": (
                configuration.policy_project
            ),
            "policy_namespace_type": (
                configuration
                .policy_namespace_type
            ),
            "central_project": (
                configuration.central_project
            ),
            "pilot_project": (
                configuration.pilot_project
            ),
            "policy_file": (
                configuration.policy_file
            ),
            "ownership_file": (
                configuration.ownership_file
            ),
            "template_file": (
                configuration.template_file
            ),
            "template_ref": (
                configuration.template_ref
            ),
            "policy_name": (
                configuration.policy_name
            ),
            "default_branch": (
                configuration.default_branch
            ),
        },
        "observed": observed,
        "observation_digest": (
            stable_digest(observed)
        ),
        "actions": actions,
        "estimated_writes": len(actions),
        "files": files,
    }


def configuration_from_dict(
    value: dict[str, Any],
    state: str,
) -> PolicyConfiguration:
    return PolicyConfiguration(
        link_scope=str(
            value["link_scope"]
        ),
        target_project=str(
            value.get("target_project")
            or ""
        ),
        target_group=str(
            value.get("target_group")
            or ""
        ),
        policy_project=str(
            value["policy_project"]
        ),
        policy_namespace_type=str(
            value["policy_namespace_type"]
        ),
        central_project=str(
            value["central_project"]
        ),
        pilot_project=str(
            value["pilot_project"]
        ),
        policy_file=str(
            value["policy_file"]
        ),
        ownership_file=str(
            value["ownership_file"]
        ),
        template_file=str(
            value["template_file"]
        ),
        template_ref=str(
            value["template_ref"]
        ),
        policy_name=str(
            value["policy_name"]
        ),
        default_branch=str(
            value["default_branch"]
        ),
        state=state,
    )


def build_policy_plan(
    client: GitLabPolicyClient,
    configuration: PolicyConfiguration,
) -> tuple[
    dict[str, Any],
    dict[str, bytes],
]:
    inspection = inspect_policy_state(
        client,
        configuration,
    )
    files = inspection.pop("files")
    plan = {
        "schema_version": 2,
        "plan_id": (
            datetime.now(
                timezone.utc
            ).strftime("%Y%m%dT%H%M%SZ")
            + "-gitlab-policy-"
            + uuid.uuid4().hex[:12]
        ),
        "created_at": now_text(),
        "status": inspection["status"],
        "reason": inspection["reason"],
        "mutation_allowed": False,
        "state": configuration.state,
        "configuration": inspection[
            "configuration"
        ],
        "observed": inspection[
            "observed"
        ],
        "observation_digest": (
            inspection[
                "observation_digest"
            ]
        ),
        "actions": inspection["actions"],
        "estimated_writes": (
            inspection["estimated_writes"]
        ),
        "review_requirements": [
            "review-policy-scope",
            "review-central-template",
            "review-policy-state",
            "confirm-policy-project-link",
        ],
    }

    return plan, files


def write_policy_plan(
    root: str | Path,
    plan: dict[str, Any],
    files: dict[str, bytes],
) -> Path:
    root_path = Path(root)
    plan_id = str(
        plan.get("plan_id") or ""
    )
    staging = (
        root_path / ".staging" / plan_id
    )
    destination = root_path / plan_id

    if destination.exists():
        raise RuntimeError(
            f"Policy plan already exists: "
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

        for relative, content in sorted(
            files.items()
        ):
            path = (
                staging
                / "files"
                / relative
            )
            path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            path.write_bytes(content)
            checksums[
                f"files/{relative}"
            ] = sha256_file(path)

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
        raise PolicyPilotError(
            f"Could not read {path}: {error}"
        ) from error

    if not isinstance(payload, dict):
        raise PolicyPilotError(
            f"Artifact is not an object: {path}"
        )

    return payload


def load_verified_policy_plan(
    directory: str | Path,
) -> LoadedPolicyPlan:
    root = Path(directory).expanduser()
    plan = read_object(
        root / "plan.json"
    )
    ready = read_object(root / "READY")
    checksums = read_object(
        root / "checksums.json"
    ).get("sha256")

    if not isinstance(checksums, dict):
        raise PolicyPilotError(
            "Policy-plan checksums are invalid"
        )

    for name, expected in checksums.items():
        path = root / name

        if (
            not path.is_file()
            or sha256_file(path)
            != expected
        ):
            raise PolicyPilotError(
                f"Policy-plan checksum mismatch: "
                f"{name}"
            )

    plan_id = str(
        plan.get("plan_id") or ""
    )

    if (
        not plan_id
        or ready.get("plan_id")
        != plan_id
    ):
        raise PolicyPilotError(
            "Policy-plan identity is invalid"
        )

    if plan.get("mutation_allowed") is not False:
        raise PolicyPilotError(
            "Policy plan unexpectedly allows "
            "mutation"
        )

    files: dict[str, bytes] = {}

    for name in checksums:
        if not name.startswith("files/"):
            continue

        relative = name.removeprefix(
            "files/"
        )
        files[relative] = (
            root / name
        ).read_bytes()

    configuration = (
        configuration_from_dict(
            plan["configuration"],
            str(plan["state"]),
        )
    )

    for expected_file in (
        configuration.policy_file,
        configuration.ownership_file,
    ):
        if expected_file not in files:
            raise PolicyPilotError(
                f"Policy-plan file is missing: "
                f"{expected_file}"
            )

    return LoadedPolicyPlan(
        directory=root,
        plan=plan,
        files=files,
        digest=stable_digest(
            {
                "plan": plan,
                "files": {
                    name: sha256_bytes(
                        content
                    )
                    for name, content
                    in sorted(files.items())
                },
            }
        ),
    )


def policy_project_create_body(
    client: GitLabPolicyClient,
    configuration: PolicyConfiguration,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": (
            configuration
            .policy_project_name
        ),
        "path": (
            configuration
            .policy_project_name
        ),
        "visibility": "private",
        "initialize_with_readme": True,
        "default_branch": (
            configuration.default_branch
        ),
        "description": (
            "Wintermute-managed GitLab "
            "security policies"
        ),
    }
    namespace_id = namespace_creation_id(
        client,
        configuration,
    )

    if namespace_id is not None:
        body["namespace_id"] = (
            namespace_id
        )

    return body


def commit_files(
    client: GitLabPolicyClient,
    configuration: PolicyConfiguration,
    files: dict[str, bytes],
    *,
    action: str,
    last_commit_ids: (
        dict[str, str] | None
    ) = None,
) -> None:
    actions: list[dict[str, Any]] = []

    for path, content in sorted(
        files.items()
    ):
        item: dict[str, Any] = {
            "action": action,
            "file_path": path,
            "content": content.decode(
                "utf-8"
            ),
            "encoding": "text",
        }

        if (
            action == "update"
            and last_commit_ids
        ):
            item["last_commit_id"] = (
                last_commit_ids[path]
            )

        actions.append(item)

    client.mutate_json(
        "POST",
        (
            f"/projects/"
            f"{quote(configuration.policy_project, safe='')}/"
            "repository/commits"
        ),
        {
            "branch": (
                configuration.default_branch
            ),
            "commit_message": (
                "Initialize Wintermute "
                "security policy"
                if action == "create"
                else (
                    "Transition Wintermute "
                    "security policy to "
                    f"{configuration.state}"
                )
            ),
            "actions": actions,
        },
        expected_statuses={201},
    )


def apply_policy_actions(
    client: GitLabPolicyClient,
    loaded: LoadedPolicyPlan,
    actions: list[dict[str, Any]],
) -> int:
    configuration = (
        configuration_from_dict(
            loaded.plan["configuration"],
            str(loaded.plan["state"]),
        )
    )
    writes = 0
    policy_project_id: int | None = None

    for action in actions:
        kind = str(action["kind"])

        if kind == (
            "gitlab.policy-project.create"
        ):
            payload = client.mutate_json(
                "POST",
                "/projects",
                policy_project_create_body(
                    client,
                    configuration,
                ),
                expected_statuses={201},
            ).payload

            if not isinstance(payload, dict):
                raise PolicyPilotError(
                    "Created policy project "
                    "response is invalid"
                )

            if (
                payload.get(
                    "path_with_namespace"
                )
                != configuration
                .policy_project
            ):
                raise PolicyPilotError(
                    "Created policy project path "
                    "does not match"
                )

            policy_project_id = numeric_id(
                payload,
                "Created policy project",
            )
            writes += 1

        elif kind == (
            "gitlab.policy-files."
            "commit-create"
        ):
            commit_files(
                client,
                configuration,
                loaded.files,
                action="create",
            )
            writes += 1

        elif kind == (
            "gitlab.policy-files."
            "commit-update"
        ):
            commit_files(
                client,
                configuration,
                loaded.files,
                action="update",
                last_commit_ids=action[
                    "last_commit_ids"
                ],
            )
            writes += 1

        elif kind == (
            "gitlab.policy-target.link"
        ):
            if policy_project_id is None:
                existing = exact_project(
                    client,
                    configuration
                    .policy_project,
                )
                assert existing is not None
                policy_project_id = (
                    numeric_id(
                        existing,
                        "Policy project",
                    )
                )

            client.mutate_json(
                "POST",
                link_endpoint(
                    configuration,
                    int(
                        action[
                            "link_target_id"
                        ]
                    ),
                ),
                {
                    "security_policy_project_id": (
                        policy_project_id
                    ),
                },
                expected_statuses={
                    200,
                    201,
                },
            )
            writes += 1

        else:
            raise PolicyPilotError(
                "Unsupported policy action: "
                f"{kind}"
            )

    return writes


def execute_policy_plan(
    loaded: LoadedPolicyPlan,
    read_client: GitLabPolicyClient,
    *,
    mode: str,
    action_client: (
        GitLabPolicyClient | None
    ) = None,
    confirm_apply: bool = False,
    maximum_writes: int = 3,
    result_root: str | Path,
) -> tuple[int, dict[str, Any], Path]:
    if mode not in {
        "dry-run",
        "apply",
    }:
        raise ValueError(
            "Policy execution mode is invalid"
        )

    if maximum_writes < 0:
        raise ValueError(
            "Policy write budget cannot be "
            "negative"
        )

    configuration = (
        configuration_from_dict(
            loaded.plan["configuration"],
            str(loaded.plan["state"]),
        )
    )
    inspection = inspect_policy_state(
        read_client,
        configuration,
    )
    actions = inspection["actions"]
    estimated_writes = len(actions)
    writes = 0
    after = None

    if (
        inspection["observation_digest"]
        != loaded.plan[
            "observation_digest"
        ]
        or actions
        != loaded.plan["actions"]
    ):
        status = "blocked"
        outcome = "stale-plan"
    elif inspection["status"] != "ready":
        status = "blocked"
        outcome = inspection["status"]
    elif estimated_writes > maximum_writes:
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
        if not confirm_apply:
            raise ValueError(
                "Policy apply requires "
                "confirmation"
            )

        if action_client is None:
            raise ValueError(
                "Policy apply requires an "
                "action client"
            )

        current = inspect_policy_state(
            action_client,
            configuration,
        )

        if (
            current["observation_digest"]
            != loaded.plan[
                "observation_digest"
            ]
            or current["actions"]
            != loaded.plan["actions"]
        ):
            status = "blocked"
            outcome = "stale-plan"
        else:
            writes = apply_policy_actions(
                action_client,
                loaded,
                current["actions"],
            )
            after = inspect_policy_state(
                action_client,
                configuration,
            )
            verified = (
                after["status"] == "ready"
                and after["actions"] == []
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
        "schema_version": 2,
        "execution_id": uuid.uuid4().hex,
        "plan_id": (
            loaded.plan["plan_id"]
        ),
        "plan_digest": loaded.digest,
        "state": loaded.plan["state"],
        "mode": mode,
        "status": status,
        "outcome": outcome,
        "estimated_writes": (
            estimated_writes
        ),
        "writes": writes,
        "before": inspection,
        "after": after,
        "completed_at": now_text(),
    }
    path = write_execution_result(
        result_root,
        result,
    )

    return (
        0 if status == "ok" else 1,
        result,
        path,
    )
