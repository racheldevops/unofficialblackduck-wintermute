from __future__ import annotations

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
from wintermute.scm.onboarding.http import (
    OnboardingHttpClient,
    OnboardingHttpError,
)


_SEGMENT = r"[^/?#]+"
_PROJECT_ACCESS_ROUTES = {
    "GET": (
        re.compile(
            rf"^/projects/{_SEGMENT}/"
            r"job_token_scope$"
        ),
        re.compile(
            rf"^/projects/{_SEGMENT}/"
            r"job_token_scope/allowlist$"
        ),
    ),
    "PATCH": (
        re.compile(
            rf"^/projects/{_SEGMENT}/"
            r"job_token_scope$"
        ),
    ),
    "POST": (
        re.compile(
            rf"^/projects/{_SEGMENT}/"
            r"job_token_scope/allowlist$"
        ),
    ),
}


class ProjectAccessError(RuntimeError):
    pass


class GitLabProjectAccessClient(
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
                _PROJECT_ACCESS_ROUTES.get(
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
class LoadedProjectAccessPlan:
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
        + "-gitlab-project-access-"
        + uuid.uuid4().hex[:12]
    )


def create_execution_id() -> str:
    return (
        datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ"
        )
        + "-gitlab-project-access-result-"
        + uuid.uuid4().hex[:12]
    )


def project_path(
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
        raise ProjectAccessError(
            "GitLab project path is invalid"
        )

    return selected


def exact_project(
    client: GitLabProjectAccessClient,
    path: str,
) -> dict[str, Any]:
    selected = project_path(path)
    result = client.get_json(
        f"/projects/{quote(selected, safe='')}"
    )
    payload = result.payload

    if not isinstance(payload, dict):
        raise ProjectAccessError(
            "GitLab project response is invalid"
        )

    returned = str(
        payload.get(
            "path_with_namespace"
        )
        or ""
    )

    if returned != selected:
        raise ProjectAccessError(
            "GitLab returned another project"
        )

    try:
        project_id = int(payload["id"])
    except (
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise ProjectAccessError(
            "GitLab project has no numeric ID"
        ) from error

    if project_id < 1:
        raise ProjectAccessError(
            "GitLab project ID is invalid"
        )

    return {
        "path": selected,
        "id": project_id,
    }


def scope_enabled(
    payload: Any,
) -> bool:
    if not isinstance(payload, dict):
        raise ProjectAccessError(
            "GitLab job-token scope response "
            "is invalid"
        )

    for name in (
        "inbound_enabled",
        "enabled",
    ):
        value = payload.get(name)

        if type(value) is bool:
            return value

    raise ProjectAccessError(
        "GitLab job-token scope did not report "
        "the restrictive inbound state"
    )


def allowed_project_ids(
    payload: Any,
) -> set[int]:
    if isinstance(payload, dict):
        values = (
            payload.get("items")
            or payload.get("projects")
        )
    else:
        values = payload

    if not isinstance(values, list):
        raise ProjectAccessError(
            "GitLab project allowlist response "
            "is invalid"
        )

    result: set[int] = set()

    for value in values:
        if not isinstance(value, dict):
            continue

        nested = value.get(
            "source_project"
        )
        raw_id = (
            value.get("source_project_id")
            or (
                nested.get("id")
                if isinstance(nested, dict)
                else None
            )
            or value.get("id")
        )

        try:
            selected = int(raw_id)
        except (
            TypeError,
            ValueError,
        ):
            continue

        if selected > 0:
            result.add(selected)

    return result


def inspect_project_access(
    client: GitLabProjectAccessClient,
    *,
    source_project: str,
    target_projects: tuple[str, ...],
) -> dict[str, Any]:
    source = exact_project(
        client,
        source_project,
    )
    targets = {
        project_path(value)
        for value in target_projects
    }

    if not targets:
        raise ProjectAccessError(
            "At least one target project is required"
        )

    actions: list[dict[str, Any]] = []
    observations: list[
        dict[str, Any]
    ] = []

    for target_path in sorted(targets):
        target = exact_project(
            client,
            target_path,
        )

        if target["id"] == source["id"]:
            continue

        scope_path = (
            f"/projects/{target['id']}/"
            "job_token_scope"
        )
        allowlist_path = (
            f"{scope_path}/allowlist"
        )
        scope_result = client.get_json(
            scope_path,
            allow_not_found=True,
        )

        if scope_result.status_code == 404:
            raise ProjectAccessError(
                "GitLab project job-token scope API "
                f"is unavailable for {target_path}"
            )

        enabled = scope_enabled(
            scope_result.payload
        )

        try:
            allowlist = client.paged_list(
                allowlist_path
            )
        except OnboardingHttpError as error:
            if error.status_code == 404:
                raise ProjectAccessError(
                    "GitLab project job-token "
                    "allowlist API is unavailable "
                    f"for {target_path}"
                ) from error

            raise

        allowed_ids = allowed_project_ids(
            allowlist
        )

        if not enabled:
            actions.append(
                {
                    "kind": (
                        "gitlab.job-token-scope.enable"
                    ),
                    "target_project": target_path,
                    "target_project_id": (
                        target["id"]
                    ),
                    "source_project": (
                        source["path"]
                    ),
                    "source_project_id": (
                        source["id"]
                    ),
                }
            )

        if source["id"] not in allowed_ids:
            actions.append(
                {
                    "kind": (
                        "gitlab.job-token-project-"
                        "allowlist.add"
                    ),
                    "target_project": target_path,
                    "target_project_id": (
                        target["id"]
                    ),
                    "source_project": (
                        source["path"]
                    ),
                    "source_project_id": (
                        source["id"]
                    ),
                }
            )

        observations.append(
            {
                "target_project": target_path,
                "target_project_id": (
                    target["id"]
                ),
                "source_project": (
                    source["path"]
                ),
                "source_project_id": (
                    source["id"]
                ),
                "scope_enabled": enabled,
                "source_allowlisted": (
                    source["id"] in allowed_ids
                ),
                "allowlisted_project_ids": (
                    sorted(allowed_ids)
                ),
            }
        )

    observation = {
        "source_project": source["path"],
        "source_project_id": source["id"],
        "targets": observations,
    }

    return {
        "observation": observation,
        "observation_digest": (
            stable_digest(observation)
        ),
        "actions": sorted(
            actions,
            key=lambda value: (
                value["target_project"],
                value["kind"],
            ),
        ),
        "estimated_writes": len(actions),
    }


def build_project_access_plan(
    client: GitLabProjectAccessClient,
    *,
    source_project: str,
    target_projects: tuple[str, ...],
) -> dict[str, Any]:
    inspection = inspect_project_access(
        client,
        source_project=source_project,
        target_projects=target_projects,
    )

    return {
        "schema_version": 1,
        "plan_id": create_plan_id(),
        "created_at": now_text(),
        "status": "review-required",
        "mutation_allowed": False,
        "access_mode": (
            "only-project-and-allowlist"
        ),
        "source_project": (
            inspection["observation"][
                "source_project"
            ]
        ),
        "source_project_id": (
            inspection["observation"][
                "source_project_id"
            ]
        ),
        "target_projects": list(
            sorted(
                {
                    project_path(value)
                    for value in target_projects
                }
            )
        ),
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
            "review-source-launcher-project",
            "review-target-resource-projects",
            "confirm-restrictive-inbound-scope",
            "confirm-project-job-token-allowlist",
        ],
    }


def write_plan(
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
        raise ProjectAccessError(
            "Project-access plan has no ID"
        )

    if destination.exists():
        raise ProjectAccessError(
            "Project-access plan already exists"
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
        raise ProjectAccessError(
            f"Could not read {path}: {error}"
        ) from error

    if not isinstance(payload, dict):
        raise ProjectAccessError(
            f"Artifact is not an object: {path}"
        )

    return payload


def load_plan(
    directory: str | Path,
) -> LoadedProjectAccessPlan:
    root = Path(directory).expanduser()

    if not root.is_dir():
        raise ProjectAccessError(
            "Project-access plan does not exist"
        )

    plan = read_object(
        root / "plan.json"
    )
    ready = read_object(root / "READY")
    expected = str(
        read_object(
            root / "checksums.json"
        ).get("sha256", {}).get(
            "plan.json"
        )
        or ""
    )

    if (
        not expected
        or sha256_file(
            root / "plan.json"
        )
        != expected
    ):
        raise ProjectAccessError(
            "Project-access plan checksum mismatch"
        )

    plan_id = str(
        plan.get("plan_id") or ""
    )

    if (
        not plan_id
        or ready.get("plan_id")
        != plan_id
    ):
        raise ProjectAccessError(
            "Project-access plan identity is invalid"
        )

    if (
        plan.get("status")
        != "review-required"
        or plan.get("mutation_allowed")
        is not False
    ):
        raise ProjectAccessError(
            "Project-access plan is not safely staged"
        )

    return LoadedProjectAccessPlan(
        directory=root,
        plan=plan,
        digest=stable_digest(plan),
    )


def apply_actions(
    client: GitLabProjectAccessClient,
    actions: list[dict[str, Any]],
) -> int:
    writes = 0

    for action in actions:
        project_id = int(
            action["target_project_id"]
        )
        scope_path = (
            f"/projects/{project_id}/"
            "job_token_scope"
        )
        kind = action["kind"]

        if kind == (
            "gitlab.job-token-scope.enable"
        ):
            client.mutate_json(
                "PATCH",
                scope_path,
                {"enabled": True},
                expected_statuses={200},
            )
            writes += 1
        elif kind == (
            "gitlab.job-token-project-"
            "allowlist.add"
        ):
            client.mutate_json(
                "POST",
                f"{scope_path}/allowlist",
                {
                    "target_project_id": (
                        action[
                            "source_project_id"
                        ]
                    ),
                },
                expected_statuses={201},
            )
            writes += 1
        else:
            raise ProjectAccessError(
                "Unsupported project-access action: "
                f"{kind}"
            )

    return writes


def write_result(
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
        raise ProjectAccessError(
            "Project-access result has no ID"
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


def execute_plan(
    loaded: LoadedProjectAccessPlan,
    client: GitLabProjectAccessClient,
    *,
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
            "Project-access mode is invalid"
        )

    if maximum_writes < 0:
        raise ValueError(
            "Project-access write budget "
            "cannot be negative"
        )

    if mode == "apply":
        if not confirm_apply:
            raise ValueError(
                "Project-access apply requires "
                "confirmation"
            )

        if (
            expected_plan_digest
            != loaded.digest
        ):
            raise ValueError(
                "Expected project-access plan "
                "digest does not match"
            )

    current = inspect_project_access(
        client,
        source_project=(
            loaded.plan["source_project"]
        ),
        target_projects=tuple(
            loaded.plan["target_projects"]
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
        or actions
        != loaded.plan["actions"]
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
        )
        after = inspect_project_access(
            client,
            source_project=(
                loaded.plan[
                    "source_project"
                ]
            ),
            target_projects=tuple(
                loaded.plan[
                    "target_projects"
                ]
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
        "source_project": (
            loaded.plan["source_project"]
        ),
        "source_project_id": (
            loaded.plan[
                "source_project_id"
            ]
        ),
        "target_projects": (
            loaded.plan["target_projects"]
        ),
        "estimated_writes": len(actions),
        "writes": writes,
        "requests": client.requests,
        "transport_writes": client.writes,
        "before": current,
        "after": after,
        "completed_at": now_text(),
    }
    path = write_result(
        result_root,
        result,
    )

    return (
        0 if status == "ok" else 1,
        result,
        path,
    )
