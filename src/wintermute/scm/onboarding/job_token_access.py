from __future__ import annotations

import json
import os
import re
import shutil
import uuid
from collections.abc import Iterable
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
MAX_CONSUMER_GROUPS = 100

_ACCESS_ROUTES = {
    "GET": (
        re.compile(
            rf"^/projects/{_SEGMENT}/"
            r"job_token_scope$"
        ),
        re.compile(
            rf"^/projects/{_SEGMENT}/"
            r"job_token_scope/"
            r"groups_allowlist$"
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
            r"job_token_scope/"
            r"groups_allowlist$"
        ),
    ),
}


class GitLabJobTokenAccessClient(
    OnboardingHttpClient
):
    def _validate_route(
        self,
        method: str,
        path: str,
    ) -> None:
        patterns = _ACCESS_ROUTES.get(
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


class JobTokenAccessError(RuntimeError):
    pass


@dataclass(frozen=True)
class LoadedAccessPlan:
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
        + "-gitlab-job-token-access-"
        + uuid.uuid4().hex[:12]
    )


def create_execution_id() -> str:
    return (
        datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ"
        )
        + "-gitlab-job-token-execution-"
        + uuid.uuid4().hex[:12]
    )


def validate_project_path(
    value: str,
) -> str:
    selected = str(value or "").strip(
        "/"
    )

    if (
        selected.count("/") < 1
        or any(
            not part
            or part in {".", ".."}
            for part in selected.split("/")
        )
    ):
        raise ValueError(
            "GitLab project path is invalid"
        )

    return selected


def validate_group_path(
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
            "GitLab consumer group is invalid"
        )

    return selected


def normalize_consumer_groups(
    values: Iterable[str] | str,
) -> tuple[str, ...]:
    raw_values = (
        [values]
        if isinstance(values, str)
        else list(values)
    )
    selected: dict[str, str] = {}

    for raw_value in raw_values:
        group = validate_group_path(
            str(raw_value)
        )
        selected.setdefault(
            group.casefold(),
            group,
        )

    if not selected:
        raise ValueError(
            "At least one GitLab consumer group "
            "is required"
        )

    if len(selected) > MAX_CONSUMER_GROUPS:
        raise ValueError(
            "GitLab consumer group count exceeds "
            f"{MAX_CONSUMER_GROUPS}"
        )

    return tuple(
        sorted(
            selected.values(),
            key=lambda value: (
                value.casefold(),
                value,
            ),
        )
    )


def planned_consumer_groups(
    plan: dict[str, Any],
) -> tuple[str, ...]:
    values = plan.get(
        "consumer_groups"
    )

    if isinstance(values, list):
        return normalize_consumer_groups(
            [
                str(value)
                for value in values
            ]
        )

    legacy = str(
        plan.get("consumer_group") or ""
    )

    if legacy:
        return normalize_consumer_groups(
            [legacy]
        )

    raise JobTokenAccessError(
        "Access plan has no consumer groups"
    )


def build_access_plan(
    *,
    bootstrap_plan_id: str,
    bootstrap_plan_digest: str,
    central_project: str,
    image_project: str,
    consumer_groups: (
        Iterable[str] | str
    ) = (),
    consumer_group: str = "",
) -> dict[str, Any]:
    central = validate_project_path(
        central_project
    )
    image = validate_project_path(
        image_project
    )
    raw_groups: list[str] = []

    if isinstance(consumer_groups, str):
        if consumer_groups:
            raw_groups.append(
                consumer_groups
            )
    else:
        raw_groups.extend(
            str(value)
            for value in consumer_groups
        )

    if consumer_group:
        raw_groups.append(
            consumer_group
        )

    groups = normalize_consumer_groups(
        raw_groups
    )
    projects: dict[
        str,
        dict[str, Any],
    ] = {
        central: {
            "project": central,
            "roles": [
                "central-template-registry"
            ],
            "may_be_created_by_bootstrap": (
                True
            ),
        },
        image: {
            "project": image,
            "roles": [
                "scan-image-registry"
            ],
            "may_be_created_by_bootstrap": (
                False
            ),
        },
    }

    if central == image:
        projects[central]["roles"] = [
            "central-template-registry",
            "scan-image-registry",
        ]
        projects[central][
            "may_be_created_by_bootstrap"
        ] = True

    return {
        "schema_version": 2,
        "plan_id": create_plan_id(),
        "created_at": now_text(),
        "status": "review-required",
        "mutation_allowed": False,
        "bootstrap_plan_id": (
            bootstrap_plan_id
        ),
        "bootstrap_plan_digest": (
            bootstrap_plan_digest
        ),
        "consumer_groups": list(groups),
        "access_mode": (
            "only-project-and-allowlist"
        ),
        "projects": [
            projects[key]
            for key in sorted(projects)
        ],
        "review_requirements": [
            "review-consumer-groups",
            "review-central-projects",
            "confirm-inbound-job-token-allowlist",
        ],
    }


def write_access_plan(
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
        raise ValueError(
            "Access plan has no plan ID"
        )

    if destination.exists():
        raise RuntimeError(
            f"Access plan already exists: "
            f"{destination}"
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
        value = json.loads(
            path.read_text(encoding="utf-8")
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        raise JobTokenAccessError(
            f"Could not read {path}: {error}"
        ) from error

    if not isinstance(value, dict):
        raise JobTokenAccessError(
            f"Artifact is not an object: {path}"
        )

    return value


def load_verified_access_plan(
    directory: str | Path,
) -> LoadedAccessPlan:
    root = Path(directory).expanduser()

    if not root.is_dir():
        raise JobTokenAccessError(
            f"Access plan does not exist: {root}"
        )

    plan = read_object(
        root / "plan.json"
    )
    ready = read_object(root / "READY")
    checksums = read_object(
        root / "checksums.json"
    ).get("sha256")

    if not isinstance(checksums, dict):
        raise JobTokenAccessError(
            "Access-plan checksums are invalid"
        )

    expected = str(
        checksums.get("plan.json") or ""
    )

    if (
        not expected
        or sha256_file(
            root / "plan.json"
        )
        != expected
    ):
        raise JobTokenAccessError(
            "Access-plan checksum mismatch"
        )

    plan_id = str(
        plan.get("plan_id") or ""
    )

    if (
        not plan_id
        or ready.get("plan_id")
        != plan_id
    ):
        raise JobTokenAccessError(
            "Access-plan identity is invalid"
        )

    if (
        plan.get("status")
        != "review-required"
        or plan.get("mutation_allowed")
        is not False
    ):
        raise JobTokenAccessError(
            "Access plan is not safely staged"
        )

    projects = plan.get("projects")

    if (
        not isinstance(projects, list)
        or not projects
        or not all(
            isinstance(value, dict)
            for value in projects
        )
    ):
        raise JobTokenAccessError(
            "Access-plan projects are invalid"
        )

    project_paths: set[str] = set()

    for project in projects:
        project_path = validate_project_path(
            str(project.get("project") or "")
        )

        if project_path in project_paths:
            raise JobTokenAccessError(
                "Access plan contains a duplicate "
                "project"
            )

        project_paths.add(project_path)

    planned_consumer_groups(plan)

    return LoadedAccessPlan(
        directory=root,
        plan=plan,
        digest=stable_digest(plan),
    )


def enabled_value(
    payload: dict[str, Any],
) -> bool | None:
    for name in (
        "inbound_enabled",
        "enabled",
    ):
        value = payload.get(name)

        if type(value) is bool:
            return value

    return None


def group_ids(
    payload: Any,
) -> set[int]:
    if isinstance(payload, dict):
        values = payload.get("items")

        if not isinstance(values, list):
            values = payload.get("groups")
    else:
        values = payload

    if not isinstance(values, list):
        raise JobTokenAccessError(
            "GitLab job-token group allowlist "
            "response is invalid"
        )

    result: set[int] = set()

    for value in values:
        if not isinstance(value, dict):
            continue

        raw_id = (
            value.get("id")
            or value.get("target_group_id")
            or value.get("source_id")
        )

        try:
            group_id = int(raw_id)
        except (
            TypeError,
            ValueError,
        ):
            continue

        if group_id > 0:
            result.add(group_id)

    return result


def resolve_consumer_groups(
    client: GitLabJobTokenAccessClient,
    groups: tuple[str, ...],
) -> dict[str, int]:
    resolved: dict[str, int] = {}
    seen_ids: set[int] = set()

    for group in groups:
        payload = client.get_json(
            (
                f"/groups/"
                f"{quote(group, safe='')}"
            )
        ).payload

        if not isinstance(payload, dict):
            raise JobTokenAccessError(
                "GitLab consumer group response "
                f"is invalid: {group}"
            )

        returned_path = str(
            payload.get("full_path")
            or payload.get("path")
            or ""
        )

        if (
            returned_path.casefold()
            != group.casefold()
        ):
            raise JobTokenAccessError(
                "GitLab returned another "
                f"consumer group for {group}"
            )

        try:
            group_id = int(
                payload["id"]
            )
        except (
            KeyError,
            TypeError,
            ValueError,
        ) as error:
            raise JobTokenAccessError(
                "GitLab consumer group has no "
                f"numeric ID: {group}"
            ) from error

        if group_id < 1:
            raise JobTokenAccessError(
                "GitLab consumer group ID "
                f"is invalid: {group}"
            )

        if group_id in seen_ids:
            raise JobTokenAccessError(
                "Multiple consumer group paths "
                "resolved to the same group ID"
            )

        seen_ids.add(group_id)
        resolved[group] = group_id

    return resolved


def access_paths(
    project_id: int,
) -> tuple[str, str]:
    base = (
        f"/projects/{project_id}/"
        "job_token_scope"
    )

    return (
        base,
        f"{base}/groups_allowlist",
    )


def pending_actions(
    project_path: str,
    group_ids_by_path: dict[str, int],
) -> list[dict[str, Any]]:
    return [
        {
            "kind": (
                "gitlab.job-token-scope.enable"
            ),
            "project": project_path,
            "project_id": None,
        },
        *[
            {
                "kind": (
                    "gitlab.job-token-group-"
                    "allowlist.add"
                ),
                "project": project_path,
                "project_id": None,
                "consumer_group": group,
                "target_group_id": group_id,
            }
            for group, group_id
            in group_ids_by_path.items()
        ],
    ]


def probe_access(
    loaded: LoadedAccessPlan,
    client: GitLabJobTokenAccessClient,
    *,
    allow_pending_projects: bool,
) -> dict[str, Any]:
    plan = loaded.plan
    groups = planned_consumer_groups(
        plan
    )
    group_ids_by_path = (
        resolve_consumer_groups(
            client,
            groups,
        )
    )
    actions: list[dict[str, Any]] = []
    project_results: list[
        dict[str, Any]
    ] = []
    blocked_reasons: list[str] = []

    for target in plan["projects"]:
        project_path = str(
            target["project"]
        )
        result = client.get_json(
            (
                f"/projects/"
                f"{quote(project_path, safe='')}"
            ),
            allow_not_found=True,
        )

        if result.status_code == 404:
            may_be_created = bool(
                target.get(
                    "may_be_created_by_bootstrap"
                )
            )

            if (
                allow_pending_projects
                and may_be_created
            ):
                actions.extend(
                    pending_actions(
                        project_path,
                        group_ids_by_path,
                    )
                )
                project_results.append(
                    {
                        "project": project_path,
                        "status": (
                            "pending-bootstrap"
                        ),
                        "scope_enabled": None,
                        "expected_groups": list(
                            groups
                        ),
                        "allowlisted_groups": [],
                        "missing_groups": list(
                            groups
                        ),
                    }
                )
                continue

            blocked_reasons.append(
                "Required GitLab access project "
                f"does not exist: {project_path}"
            )
            project_results.append(
                {
                    "project": project_path,
                    "status": "missing",
                    "expected_groups": list(
                        groups
                    ),
                }
            )
            continue

        project_payload = result.payload

        if not isinstance(
            project_payload,
            dict,
        ):
            raise JobTokenAccessError(
                "GitLab project response "
                "is invalid"
            )

        try:
            project_id = int(
                project_payload["id"]
            )
        except (
            KeyError,
            TypeError,
            ValueError,
        ) as error:
            raise JobTokenAccessError(
                "GitLab project has no "
                "numeric ID"
            ) from error

        scope_path, allowlist_path = (
            access_paths(project_id)
        )
        scope_result = client.get_json(
            scope_path,
            allow_not_found=True,
        )

        if scope_result.status_code == 404:
            blocked_reasons.append(
                "GitLab job-token scope API "
                f"is unavailable for {project_path}"
            )
            project_results.append(
                {
                    "project": project_path,
                    "status": "unsupported",
                    "expected_groups": list(
                        groups
                    ),
                }
            )
            continue

        scope_payload = (
            scope_result.payload
        )

        if not isinstance(
            scope_payload,
            dict,
        ):
            raise JobTokenAccessError(
                "GitLab job-token scope response "
                "is invalid"
            )

        scope_enabled = enabled_value(
            scope_payload
        )

        if scope_enabled is None:
            blocked_reasons.append(
                "GitLab job-token scope did not "
                "report inbound state for "
                f"{project_path}"
            )
            project_results.append(
                {
                    "project": project_path,
                    "status": "unsupported",
                    "expected_groups": list(
                        groups
                    ),
                }
            )
            continue

        try:
            allowlist = (
                client.paged_list(
                    allowlist_path
                )
            )
        except OnboardingHttpError as error:
            if error.status_code == 404:
                blocked_reasons.append(
                    "GitLab group job-token "
                    "allowlist API is unavailable "
                    f"for {project_path}"
                )
                project_results.append(
                    {
                        "project": project_path,
                        "status": (
                            "unsupported"
                        ),
                        "expected_groups": list(
                            groups
                        ),
                    }
                )
                continue

            raise

        allowed_group_ids = group_ids(
            allowlist
        )
        allowlisted_groups = [
            group
            for group, group_id
            in group_ids_by_path.items()
            if group_id
            in allowed_group_ids
        ]
        missing_groups = [
            group
            for group, group_id
            in group_ids_by_path.items()
            if group_id
            not in allowed_group_ids
        ]

        if not scope_enabled:
            actions.append(
                {
                    "kind": (
                        "gitlab.job-token-scope.enable"
                    ),
                    "project": project_path,
                    "project_id": (
                        project_id
                    ),
                }
            )

        for group in missing_groups:
            actions.append(
                {
                    "kind": (
                        "gitlab.job-token-group-"
                        "allowlist.add"
                    ),
                    "project": project_path,
                    "project_id": (
                        project_id
                    ),
                    "consumer_group": group,
                    "target_group_id": (
                        group_ids_by_path[group]
                    ),
                }
            )

        project_results.append(
            {
                "project": project_path,
                "project_id": project_id,
                "status": "available",
                "scope_enabled": (
                    scope_enabled
                ),
                "expected_groups": list(
                    groups
                ),
                "allowlisted_groups": (
                    allowlisted_groups
                ),
                "missing_groups": (
                    missing_groups
                ),
            }
        )

    return {
        "status": (
            "blocked"
            if blocked_reasons
            else "ready"
        ),
        "consumer_groups": list(groups),
        "consumer_group_ids": {
            group: group_id
            for group, group_id
            in group_ids_by_path.items()
        },
        "access_mode": (
            "only-project-and-allowlist"
        ),
        "actions": actions,
        "estimated_writes": len(actions),
        "projects": project_results,
        "reasons": blocked_reasons,
    }


def apply_access_actions(
    client: GitLabJobTokenAccessClient,
    actions: list[dict[str, Any]],
) -> int:
    writes = 0

    for action in actions:
        project_id = action.get(
            "project_id"
        )

        if type(project_id) is not int:
            raise JobTokenAccessError(
                "Access action has no resolved "
                "project ID"
            )

        scope_path, allowlist_path = (
            access_paths(project_id)
        )
        kind = str(action["kind"])

        if kind == (
            "gitlab.job-token-scope.enable"
        ):
            client.mutate_json(
                "PATCH",
                scope_path,
                {
                    "enabled": True,
                },
                expected_statuses={200},
            )
            writes += 1
        elif kind == (
            "gitlab.job-token-group-"
            "allowlist.add"
        ):
            client.mutate_json(
                "POST",
                allowlist_path,
                {
                    "target_group_id": (
                        action[
                            "target_group_id"
                        ]
                    ),
                },
                expected_statuses={201},
            )
            writes += 1
        else:
            raise JobTokenAccessError(
                "Unsupported GitLab job-token "
                f"access action: {kind}"
            )

    return writes


def write_access_result(
    root: str | Path,
    result: dict[str, Any],
) -> Path:
    result_id = str(
        result.get("execution_id") or ""
    )
    root_path = Path(root)
    staging = (
        root_path / ".staging" / result_id
    )
    destination = root_path / result_id

    if not result_id:
        raise ValueError(
            "Access result has no execution ID"
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
                "execution_id": result_id,
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


def execute_access_plan(
    loaded: LoadedAccessPlan,
    client: GitLabJobTokenAccessClient,
    *,
    mode: str,
    confirm_apply: bool = False,
    expected_plan_digest: str = "",
    maximum_writes: int = 4,
    allow_pending_projects: bool = False,
    result_root: str | Path,
) -> tuple[int, dict[str, Any], Path]:
    if mode not in {
        "dry-run",
        "apply",
    }:
        raise ValueError(
            "Access execution mode is invalid"
        )

    if maximum_writes < 0:
        raise ValueError(
            "Access write budget cannot "
            "be negative"
        )

    if mode == "apply":
        if not confirm_apply:
            raise ValueError(
                "Access apply requires "
                "confirmation"
            )

        if (
            not expected_plan_digest
            or expected_plan_digest
            != loaded.digest
        ):
            raise ValueError(
                "Expected access-plan digest "
                "does not match"
            )

    before = probe_access(
        loaded,
        client,
        allow_pending_projects=(
            allow_pending_projects
        ),
    )
    actions = before["actions"]
    estimated_writes = len(actions)
    writes = 0
    after = None

    if before["status"] != "ready":
        status = "blocked"
        outcome = "capability-blocked"
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
        current = probe_access(
            loaded,
            client,
            allow_pending_projects=False,
        )

        if current["status"] != "ready":
            status = "blocked"
            outcome = "capability-blocked"
        elif (
            len(current["actions"])
            > maximum_writes
        ):
            status = "blocked"
            outcome = "budget-exhausted"
        else:
            writes = apply_access_actions(
                client,
                current["actions"],
            )
            after = probe_access(
                loaded,
                client,
                allow_pending_projects=False,
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
        "estimated_writes": (
            estimated_writes
        ),
        "writes": writes,
        "requests": client.requests,
        "transport_writes": (
            client.writes
        ),
        "before": before,
        "after": after,
        "completed_at": now_text(),
    }
    path = write_access_result(
        result_root,
        result,
    )

    return (
        0 if status == "ok" else 1,
        result,
        path,
    )
