from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

from wintermute.ai.models import stable_digest
from wintermute.ai.storage import (
    atomic_write_json,
    sha256_file,
)
from wintermute.scm.onboarding.http import (
    OnboardingHttpClient,
)


_SEGMENT = r"[^/?#]+"
_DIGEST_PATTERN = re.compile(
    r"^[0-9a-f]{64}$"
)
_VARIABLE_ROUTES = {
    "GET": (
        re.compile(
            rf"^/projects/{_SEGMENT}/"
            rf"variables/{_SEGMENT}$"
        ),
        re.compile(
            rf"^/projects/{_SEGMENT}/"
            rf"protected_branches/{_SEGMENT}$"
        ),
    ),
    "POST": (
        re.compile(
            rf"^/projects/{_SEGMENT}/"
            r"variables$"
        ),
        re.compile(
            rf"^/projects/{_SEGMENT}/"
            r"protected_branches$"
        ),
    ),
    "PUT": (
        re.compile(
            rf"^/projects/{_SEGMENT}/"
            rf"variables/{_SEGMENT}$"
        ),
    ),
}


class CentralVariablesError(RuntimeError):
    pass


class GitLabCentralVariablesClient(
    OnboardingHttpClient
):
    def _validate_route(
        self,
        method: str,
        path: str,
    ) -> None:
        if any(
            pattern.fullmatch(path)
            for pattern in (
                _VARIABLE_ROUTES.get(
                    method,
                    (),
                )
            )
        ):
            return

        super()._validate_route(
            method,
            path,
        )


@dataclass(frozen=True)
class LoadedCentralVariablesPlan:
    directory: Path
    plan: dict[str, Any]
    digest: str


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
        + "-central-ci-variables-"
        + uuid.uuid4().hex[:12]
    )


def create_execution_id() -> str:
    return (
        datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ"
        )
        + "-central-ci-variables-result-"
        + uuid.uuid4().hex[:12]
    )


def sha256_text(
    value: str,
) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


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
            for part in parts
        )
    ):
        raise CentralVariablesError(
            "GitLab project path is invalid"
        )

    return selected


def normalize_blackduck_url(
    value: str,
) -> str:
    selected = str(value or "").strip()
    parsed = urlsplit(selected)

    if (
        parsed.scheme.casefold() != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise CentralVariablesError(
            "BLACKDUCK_URL must be an HTTPS URL "
            "without credentials, query, or fragment"
        )

    return urlunsplit(
        (
            "https",
            parsed.netloc.casefold(),
            parsed.path.rstrip("/"),
            "",
            "",
        )
    )


def validate_blackduck_token(
    value: str,
) -> str:
    selected = str(value or "").strip()

    if not selected:
        raise CentralVariablesError(
            "BLACKDUCK_API_TOKEN must be set"
        )

    if (
        len(selected) < 8
        or "\r" in selected
        or "\n" in selected
    ):
        raise CentralVariablesError(
            "BLACKDUCK_API_TOKEN is invalid"
        )

    return selected


def blackduck_variables(
    environment: (
        Mapping[str, str] | None
    ) = None,
) -> dict[str, dict[str, Any]]:
    selected = (
        os.environ
        if environment is None
        else environment
    )
    url = normalize_blackduck_url(
        str(
            selected.get(
                "BLACKDUCK_URL",
                "",
            )
        )
    )
    token = validate_blackduck_token(
        str(
            selected.get(
                "BLACKDUCK_API_TOKEN",
                "",
            )
        )
    )

    return {
        "BLACKDUCK_URL": {
            "key": "BLACKDUCK_URL",
            "value": url,
            "variable_type": "env_var",
            "protected": True,
            "masked": False,
            "raw": True,
            "environment_scope": "*",
        },
        "BLACKDUCK_API_TOKEN": {
            "key": "BLACKDUCK_API_TOKEN",
            "value": token,
            "variable_type": "env_var",
            "protected": True,
            "masked": True,
            "raw": True,
            "environment_scope": "*",
        },
    }


def launcher_variables(
    environment: Mapping[str, str] | None = None,
) -> dict[str, dict[str, Any]]:
    selected = os.environ if environment is None else environment

    # An optional dedicated credential is supported, but not required.
    token_value = ""
    for name in ("WINTERMUTE_GITLAB_READ_TOKEN", "GITLAB_TOKEN"):
        raw = selected.get(name, "")
        if not isinstance(raw, str):
            raise CentralVariablesError(f"{name} must be a string")
        if "\r" in raw or "\n" in raw:
            raise CentralVariablesError(f"{name} contains invalid characters")
        if raw.strip():
            token_value = raw.strip()
            break

    if not token_value:
        raise CentralVariablesError(
            "GITLAB_TOKEN must be set to provision launcher authentication"
        )

    if len(token_value) < 8 or any(
        character.isspace() for character in token_value
    ):
        raise CentralVariablesError(
            "Launcher credential must satisfy GitLab masked-variable requirements"
        )

    return {
        "WINTERMUTE_GITLAB_READ_TOKEN": {
            "key": "WINTERMUTE_GITLAB_READ_TOKEN",
            "value": token_value,
            "variable_type": "env_var",
            "protected": True,
            "masked": True,
            "raw": True,
            "environment_scope": "*",
        },
    }


def safe_descriptor(
    value: dict[str, Any],
) -> dict[str, Any]:
    return {
        "key": value["key"],
        "variable_type": (
            value["variable_type"]
        ),
        "protected": value["protected"],
        "masked": value["masked"],
        "raw": value["raw"],
        "environment_scope": (
            value["environment_scope"]
        ),
        "desired_value_sha256": (
            sha256_text(value["value"])
        ),
    }


def project_endpoint(
    project: str,
) -> str:
    return (
        f"/projects/"
        f"{quote(project, safe='')}"
    )


def exact_project(
    client: GitLabCentralVariablesClient,
    project: str,
    branch: str,
) -> dict[str, Any]:
    selected = validate_project_path(
        project
    )
    result = client.get_json(
        project_endpoint(selected)
    )
    payload = result.payload

    if not isinstance(payload, dict):
        raise CentralVariablesError(
            "GitLab project response is invalid"
        )

    if (
        str(
            payload.get(
                "path_with_namespace"
            )
            or ""
        )
        != selected
    ):
        raise CentralVariablesError(
            "GitLab returned another project"
        )

    try:
        project_id = int(payload["id"])
    except (
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise CentralVariablesError(
            "GitLab project has no numeric ID"
        ) from error

    if project_id < 1:
        raise CentralVariablesError(
            "GitLab project ID is invalid"
        )

    if payload.get("visibility") != "private":
        raise CentralVariablesError(
            "Central GitLab project is not private"
        )

    if str(
        payload.get("default_branch")
        or ""
    ) != branch:
        raise CentralVariablesError(
            "Central GitLab default branch does "
            "not match the setup configuration"
        )

    return {
        "path": selected,
        "id": project_id,
        "branch": branch,
    }


def protected_branch_path(
    project_id: int,
    branch: str,
) -> str:
    return (
        f"/projects/{project_id}/"
        "protected_branches/"
        f"{quote(branch, safe='')}"
    )


def variable_path(
    project_id: int,
    key: str,
) -> str:
    return (
        f"/projects/{project_id}/"
        "variables/"
        f"{quote(key, safe='')}"
    )


def read_variable(
    client: GitLabCentralVariablesClient,
    *,
    project_id: int,
    key: str,
) -> dict[str, Any] | None:
    result = client.get_json(
        variable_path(
            project_id,
            key,
        ),
        params={
            "filter[environment_scope]": "*",
        },
        allow_not_found=True,
    )

    if result.status_code == 404:
        return None

    if not isinstance(result.payload, dict):
        raise CentralVariablesError(
            "GitLab CI/CD variable response "
            f"is invalid: {key}"
        )

    returned_key = str(
        result.payload.get("key")
        or ""
    )

    if returned_key != key:
        raise CentralVariablesError(
            "GitLab returned another CI/CD "
            f"variable for {key}"
        )

    scope = str(
        result.payload.get(
            "environment_scope"
        )
        or "*"
    )

    if scope != "*":
        raise CentralVariablesError(
            "GitLab returned an unexpected "
            f"environment scope for {key}"
        )

    return dict(result.payload)


def variable_matches(
    current: dict[str, Any],
    desired: dict[str, Any],
) -> bool:
    current_value = current.get("value")

    if not isinstance(
        current_value,
        str,
    ):
        return False

    return (
        hmac.compare_digest(
            current_value,
            desired["value"],
        )
        and str(
            current.get(
                "variable_type"
            )
            or "env_var"
        )
        == desired["variable_type"]
        and current.get("protected")
        is desired["protected"]
        and current.get("masked")
        is desired["masked"]
        and current.get("raw")
        is desired["raw"]
        and str(
            current.get(
                "environment_scope"
            )
            or "*"
        )
        == desired[
            "environment_scope"
        ]
    )


def variable_observation(
    key: str,
    current: dict[str, Any] | None,
    desired: dict[str, Any],
) -> dict[str, Any]:
    return {
        "key": key,
        "exists": current is not None,
        "value_matches": (
            current is not None
            and isinstance(
                current.get("value"),
                str,
            )
            and hmac.compare_digest(
                current["value"],
                desired["value"],
            )
        ),
        "variable_type": (
            str(
                current.get(
                    "variable_type"
                )
                or ""
            )
            if current is not None
            else ""
        ),
        "protected": (
            current.get("protected")
            if current is not None
            else None
        ),
        "masked": (
            current.get("masked")
            if current is not None
            else None
        ),
        "raw": (
            current.get("raw")
            if current is not None
            else None
        ),
        "environment_scope": (
            str(
                current.get(
                    "environment_scope"
                )
                or ""
            )
            if current is not None
            else ""
        ),
    }


def inspect_variables(
    client: GitLabCentralVariablesClient,
    *,
    project: str,
    branch: str,
    desired_variables: dict[
        str,
        dict[str, Any],
    ],
) -> dict[str, Any]:
    target = exact_project(
        client,
        project,
        branch,
    )
    branch_result = client.get_json(
        protected_branch_path(
            target["id"],
            branch,
        ),
        allow_not_found=True,
    )
    branch_protected = (
        branch_result.status_code == 200
    )

    if (
        branch_protected
        and not isinstance(
            branch_result.payload,
            dict,
        )
    ):
        raise CentralVariablesError(
            "GitLab protected-branch response "
            "is invalid"
        )

    actions: list[
        dict[str, Any]
    ] = []

    if not branch_protected:
        actions.append(
            {
                "kind": (
                    "gitlab.default-branch.protect"
                ),
                "project_id": target["id"],
                "branch": branch,
            }
        )

    observations: list[
        dict[str, Any]
    ] = []

    for key in sorted(
        desired_variables
    ):
        desired = desired_variables[key]

        if desired.get("key") != key:
            raise CentralVariablesError(
                "Desired CI/CD variable key "
                "does not match its mapping"
            )

        current = read_variable(
            client,
            project_id=target["id"],
            key=key,
        )
        observation = variable_observation(
            key,
            current,
            desired,
        )
        observations.append(
            observation
        )

        if (
            current is None
            or not variable_matches(
                current,
                desired,
            )
        ):
            actions.append(
                {
                    "kind": (
                        "gitlab.variable.create"
                        if current is None
                        else "gitlab.variable.update"
                    ),
                    "project_id": target["id"],
                    **safe_descriptor(desired),
                }
            )

    observation = {
        "project": target["path"],
        "project_id": target["id"],
        "branch": target["branch"],
        "branch_protected": (
            branch_protected
        ),
        "variables": observations,
    }

    return {
        "observation": observation,
        "observation_digest": (
            stable_digest(observation)
        ),
        "actions": actions,
        "estimated_writes": len(actions),
    }


def build_variables_plan(
    client: GitLabCentralVariablesClient,
    *,
    project: str,
    branch: str,
    desired_variables: dict[
        str,
        dict[str, Any],
    ],
) -> dict[str, Any]:
    inspection = inspect_variables(
        client,
        project=project,
        branch=branch,
        desired_variables=(
            desired_variables
        ),
    )

    return {
        "schema_version": 1,
        "plan_id": create_plan_id(),
        "created_at": now_text(),
        "status": "review-required",
        "mutation_allowed": False,
        "provider": "gitlab",
        "project": (
            inspection["observation"][
                "project"
            ]
        ),
        "project_id": (
            inspection["observation"][
                "project_id"
            ]
        ),
        "branch": branch,
        "variable_names": sorted(
            desired_variables
        ),
        "desired_variables": [
            safe_descriptor(
                desired_variables[key]
            )
            for key in sorted(
                desired_variables
            )
        ],
        "observation": (
            inspection["observation"]
        ),
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
            "review-central-project",
            "review-protected-default-branch",
            "review-variable-names-and-metadata",
            "confirm-secret-values-remain-outside-artifacts",
        ],
    }


def write_variables_plan(
    root: str | Path,
    plan: dict[str, Any],
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
        raise CentralVariablesError(
            "Central variable plan has no ID"
        )

    if destination.exists():
        raise CentralVariablesError(
            "Central variable plan already exists"
        )

    staging.mkdir(
        parents=True,
        exist_ok=False,
    )

    try:
        atomic_write_json(
            staging / "plan.json",
            plan,
        )
        atomic_write_json(
            staging / "checksums.json",
            {
                "schema_version": 1,
                "sha256": {
                    "plan.json": sha256_file(
                        staging / "plan.json"
                    ),
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
        raise CentralVariablesError(
            f"Could not read {path}: {error}"
        ) from error

    if not isinstance(payload, dict):
        raise CentralVariablesError(
            f"Artifact is not an object: {path}"
        )

    return payload


def load_variables_plan(
    directory: str | Path,
) -> LoadedCentralVariablesPlan:
    root = Path(directory).expanduser()

    if not root.is_dir():
        raise CentralVariablesError(
            "Central variable plan does not exist"
        )

    plan = read_object(
        root / "plan.json"
    )
    ready = read_object(root / "READY")
    checksums = read_object(
        root / "checksums.json"
    ).get("sha256")

    if not isinstance(checksums, dict):
        raise CentralVariablesError(
            "Central variable checksums are invalid"
        )

    expected = str(
        checksums.get("plan.json") or ""
    )

    if (
        _DIGEST_PATTERN.fullmatch(
            expected
        )
        is None
        or sha256_file(
            root / "plan.json"
        )
        != expected
    ):
        raise CentralVariablesError(
            "Central variable plan checksum mismatch"
        )

    plan_id = str(
        plan.get("plan_id") or ""
    )

    if (
        not plan_id
        or ready.get("plan_id")
        != plan_id
    ):
        raise CentralVariablesError(
            "Central variable plan identity is invalid"
        )

    if (
        plan.get("status")
        != "review-required"
        or plan.get("mutation_allowed")
        is not False
    ):
        raise CentralVariablesError(
            "Central variable plan is not safely staged"
        )

    variable_names = plan.get(
        "variable_names"
    )
    desired_variables = plan.get(
        "desired_variables"
    )
    actions = plan.get("actions")

    if (
        not isinstance(variable_names, list)
        or not variable_names
        or not all(isinstance(name, str) for name in variable_names)
        or len(variable_names) != len(set(variable_names))
        or set(variable_names) not in (
            {"BLACKDUCK_API_TOKEN", "BLACKDUCK_URL"},
            {"WINTERMUTE_GITLAB_READ_TOKEN"},
            {
                "BLACKDUCK_API_TOKEN",
                "BLACKDUCK_URL",
                "WINTERMUTE_GITLAB_READ_TOKEN",
            },
        )
    ):
        raise CentralVariablesError(
            "Central variable names are invalid"
        )

    if (
        not isinstance(desired_variables, list)
        or not all(
            isinstance(value, dict)
            for value in desired_variables
        )
        or not isinstance(actions, list)
        or not all(
            isinstance(value, dict)
            for value in actions
        )
    ):
        raise CentralVariablesError(
            "Central variable plan contents are invalid"
        )

    rendered = json.dumps(
        plan,
        sort_keys=True,
    )

    for forbidden in (
        "value\": \"",
        "BLACKDUCK_API_TOKEN=",
    ):
        if forbidden in rendered:
            raise CentralVariablesError(
                "Central variable plan may contain "
                "a secret value"
            )

    return LoadedCentralVariablesPlan(
        directory=root,
        plan=plan,
        digest=stable_digest(plan),
    )


def variable_body(
    desired: dict[str, Any],
) -> dict[str, Any]:
    return {
        "key": desired["key"],
        "value": desired["value"],
        "variable_type": (
            desired["variable_type"]
        ),
        "protected": desired["protected"],
        "masked": desired["masked"],
        "raw": desired["raw"],
        "environment_scope": (
            desired["environment_scope"]
        ),
    }


def apply_actions(
    client: GitLabCentralVariablesClient,
    actions: list[dict[str, Any]],
    *,
    desired_variables: dict[
        str,
        dict[str, Any],
    ],
) -> int:
    writes = 0

    for action in actions:
        kind = str(
            action.get("kind") or ""
        )
        project_id = int(
            action["project_id"]
        )

        if kind == (
            "gitlab.default-branch.protect"
        ):
            client.mutate_json(
                "POST",
                (
                    f"/projects/{project_id}/"
                    "protected_branches"
                ),
                {
                    "name": action["branch"],
                    "push_access_level": 40,
                    "merge_access_level": 40,
                    "allow_force_push": False,
                },
                expected_statuses={201},
            )
            writes += 1
            continue

        key = str(
            action.get("key") or ""
        )
        desired = desired_variables.get(key)

        if desired is None:
            raise CentralVariablesError(
                "Central variable action references "
                f"an unknown variable: {key}"
            )

        if (
            action.get(
                "desired_value_sha256"
            )
            != sha256_text(
                desired["value"]
            )
        ):
            raise CentralVariablesError(
                "Central variable value changed "
                f"after planning: {key}"
            )

        if kind == (
            "gitlab.variable.create"
        ):
            client.mutate_json(
                "POST",
                (
                    f"/projects/{project_id}/"
                    "variables"
                ),
                variable_body(desired),
                expected_statuses={201},
            )
            writes += 1
        elif kind == (
            "gitlab.variable.update"
        ):
            client.mutate_json(
                "PUT",
                variable_path(
                    project_id,
                    key,
                ),
                variable_body(desired),
                expected_statuses={200},
            )
            writes += 1
        else:
            raise CentralVariablesError(
                "Unsupported central variable "
                f"action: {kind}"
            )

    return writes


def write_variables_result(
    root: str | Path,
    result: dict[str, Any],
) -> Path:
    root_path = Path(root)
    execution_id = str(
        result.get("execution_id") or ""
    )
    staging = (
        root_path
        / ".staging"
        / execution_id
    )
    destination = (
        root_path / execution_id
    )

    if not execution_id:
        raise CentralVariablesError(
            "Central variable result has no ID"
        )

    staging.mkdir(
        parents=True,
        exist_ok=False,
    )

    try:
        atomic_write_json(
            staging / "result.json",
            result,
        )
        atomic_write_json(
            staging / "checksums.json",
            {
                "schema_version": 1,
                "sha256": {
                    "result.json": sha256_file(
                        staging / "result.json"
                    ),
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


def execute_variables_plan(
    loaded: LoadedCentralVariablesPlan,
    client: GitLabCentralVariablesClient,
    *,
    desired_variables: dict[
        str,
        dict[str, Any],
    ],
    mode: str,
    result_root: str | Path,
    maximum_writes: int,
    confirm_apply: bool = False,
    expected_plan_digest: str = "",
) -> tuple[int, dict[str, Any], Path]:
    if mode not in {
        "dry-run",
        "apply",
    }:
        raise ValueError(
            "Central variable mode is invalid"
        )

    if maximum_writes < 0:
        raise ValueError(
            "Central variable write budget "
            "cannot be negative"
        )

    if mode == "apply":
        if not confirm_apply:
            raise ValueError(
                "Central variable apply requires "
                "confirmation"
            )

        if (
            expected_plan_digest
            != loaded.digest
        ):
            raise ValueError(
                "Expected central variable plan "
                "digest does not match"
            )

    current = inspect_variables(
        client,
        project=loaded.plan["project"],
        branch=loaded.plan["branch"],
        desired_variables=(
            desired_variables
        ),
    )
    actions = current["actions"]
    writes = 0
    after = None

    if (
        current["observation_digest"]
        != loaded.plan[
            "observation_digest"
        ]
        or actions != loaded.plan["actions"]
    ):
        status = "blocked"
        outcome = "stale-plan"
    elif len(actions) > maximum_writes:
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
        writes = apply_actions(
            client,
            actions,
            desired_variables=(
                desired_variables
            ),
        )
        after = inspect_variables(
            client,
            project=(
                loaded.plan["project"]
            ),
            branch=(
                loaded.plan["branch"]
            ),
            desired_variables=(
                desired_variables
            ),
        )
        verified = (
            after["actions"] == []
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
        "mode": mode,
        "status": status,
        "outcome": outcome,
        "project": loaded.plan["project"],
        "project_id": (
            loaded.plan["project_id"]
        ),
        "branch": loaded.plan["branch"],
        "variable_names": (
            loaded.plan["variable_names"]
        ),
        "protected_variables": True,
        "secret_values_recorded": False,
        "estimated_writes": len(actions),
        "writes": writes,
        "requests": client.requests,
        "transport_writes": client.writes,
        "before": current[
            "observation"
        ],
        "after": (
            after["observation"]
            if after is not None
            else None
        ),
        "completed_at": now_text(),
    }
    path = write_variables_result(
        result_root,
        result,
    )

    return (
        0 if status == "ok" else 1,
        result,
        path,
    )
