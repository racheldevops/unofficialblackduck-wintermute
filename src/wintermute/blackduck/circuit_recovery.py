from __future__ import annotations

import json
import os
import sys
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, TypeVar

from wintermute.blackduck.request_control import (
    BlackDuckCircuitOpenError,
    CircuitSnapshot,
)
from wintermute.paths import ensure_parent_dir, output_root


DEFAULT_RECOVERY_DELAY_SECONDS = 600
DEFAULT_RECOVERY_ATTEMPTS = 1
QUARANTINE_SCHEMA_VERSION = 1

_RECOVERY_ATTEMPT: ContextVar[bool] = ContextVar(
    "wintermute_blackduck_recovery_attempt",
    default=False,
)

ResultT = TypeVar("ResultT")


def now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def epoch_iso(value: float) -> str:
    return (
        datetime.fromtimestamp(
            value,
            timezone.utc,
        )
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def default_quarantine_path() -> Path:
    return (
        output_root()
        / "jira"
        / "state"
        / "blackduck-circuit-quarantine.json"
    )


@dataclass(frozen=True)
class QuarantinedTarget:
    child_project: str
    child_version: str
    child_version_href: str
    parent_projects: tuple[str, ...]
    retry_after_epoch: float
    retry_after: str
    failure_count: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "child_project": self.child_project,
            "child_version": self.child_version,
            "child_version_href": (
                self.child_version_href
            ),
            "parent_projects": list(
                self.parent_projects
            ),
            "retry_after_epoch": (
                self.retry_after_epoch
            ),
            "retry_after": self.retry_after,
            "failure_count": self.failure_count,
        }


def recovery_attempt_active() -> bool:
    return bool(_RECOVERY_ATTEMPT.get())


def classify_target(
    snapshot: CircuitSnapshot,
    *,
    retry_after_epoch: float,
) -> QuarantinedTarget | None:
    if not snapshot.failures:
        return None

    contexts = [
        failure.context
        for failure in snapshot.failures
    ]
    hrefs = [
        str(
            context.get("child_version_href")
            or ""
        ).strip()
        for context in contexts
    ]

    if (
        not all(hrefs)
        or len(set(hrefs)) != 1
    ):
        return None

    child_projects = {
        str(
            context.get("child_project")
            or ""
        ).strip()
        for context in contexts
        if str(
            context.get("child_project")
            or ""
        ).strip()
    }
    child_versions = {
        str(
            context.get("child_version")
            or ""
        ).strip()
        for context in contexts
        if str(
            context.get("child_version")
            or ""
        ).strip()
    }
    parent_projects: set[str] = set()

    for context in contexts:
        raw = str(
            context.get("parent_projects")
            or context.get("parent_project")
            or ""
        )

        parent_projects.update(
            value.strip()
            for value in raw.split(";")
            if value.strip()
        )

    return QuarantinedTarget(
        child_project=(
            next(iter(child_projects))
            if len(child_projects) == 1
            else ""
        ),
        child_version=(
            next(iter(child_versions))
            if len(child_versions) == 1
            else ""
        ),
        child_version_href=hrefs[0],
        parent_projects=tuple(
            sorted(parent_projects)
        ),
        retry_after_epoch=retry_after_epoch,
        retry_after=epoch_iso(
            retry_after_epoch
        ),
        failure_count=snapshot.failure_count,
    )


def atomic_write_json(
    path: Path,
    payload: dict[str, Any],
) -> None:
    ensure_parent_dir(path)
    temporary = path.with_name(
        f"{path.name}.{uuid.uuid4().hex}.tmp"
    )

    try:
        temporary.write_text(
            json.dumps(
                payload,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_quarantine(
    path: Path,
    error: BlackDuckCircuitOpenError,
    *,
    delay_seconds: int,
) -> QuarantinedTarget | None:
    timestamp = time.time()
    retry_after_epoch = (
        timestamp + delay_seconds
    )
    target = classify_target(
        error.snapshot,
        retry_after_epoch=retry_after_epoch,
    )

    if target is None:
        print(
            "Black Duck circuit failures span "
            "multiple or unattributed targets; "
            "no target was quarantined.",
            file=sys.stderr,
        )
        return None

    atomic_write_json(
        path,
        {
            "schema_version": (
                QUARANTINE_SCHEMA_VERSION
            ),
            "status": "active",
            "created_at": now_iso(),
            "created_at_epoch": timestamp,
            "classification": (
                "single-child-project-version"
            ),
            "target": target.as_dict(),
            "circuit": error.snapshot.as_dict(),
        },
    )

    print(
        "Temporarily quarantined Black Duck child "
        f"project version until {target.retry_after}: "
        f"{target.child_project} / "
        f"{target.child_version}",
        file=sys.stderr,
    )
    return target


def load_active_quarantine(
    path: Path,
    *,
    current_time: float | None = None,
) -> QuarantinedTarget | None:
    if recovery_attempt_active():
        return None

    if not path.is_file():
        return None

    try:
        payload = json.loads(
            path.read_text(encoding="utf-8")
        )
    except (
        OSError,
        json.JSONDecodeError,
    ):
        return None

    if (
        not isinstance(payload, dict)
        or payload.get("status") != "active"
    ):
        return None

    target = payload.get("target")

    if not isinstance(target, dict):
        return None

    try:
        retry_after_epoch = float(
            target["retry_after_epoch"]
        )
    except (
        KeyError,
        TypeError,
        ValueError,
    ):
        return None

    now = (
        time.time()
        if current_time is None
        else current_time
    )

    if retry_after_epoch <= now:
        return None

    href = str(
        target.get("child_version_href")
        or ""
    ).strip()

    if not href:
        return None

    return QuarantinedTarget(
        child_project=str(
            target.get("child_project") or ""
        ),
        child_version=str(
            target.get("child_version") or ""
        ),
        child_version_href=href,
        parent_projects=tuple(
            str(value)
            for value in (
                target.get("parent_projects")
                or []
            )
            if str(value)
        ),
        retry_after_epoch=retry_after_epoch,
        retry_after=str(
            target.get("retry_after") or ""
        ),
        failure_count=int(
            target.get("failure_count") or 0
        ),
    )


def mark_quarantine_recovered(
    path: Path,
) -> None:
    if not path.is_file():
        return

    try:
        payload = json.loads(
            path.read_text(encoding="utf-8")
        )
    except (
        OSError,
        json.JSONDecodeError,
    ):
        return

    if not isinstance(payload, dict):
        return

    payload["status"] = "recovered"
    payload["recovered_at"] = now_iso()
    payload["recovered_at_epoch"] = (
        time.time()
    )
    atomic_write_json(path, payload)


def run_with_circuit_recovery(
    operation: Callable[[], ResultT],
    *,
    quarantine_path: Path | None = None,
    delay_seconds: int = (
        DEFAULT_RECOVERY_DELAY_SECONDS
    ),
    recovery_attempts: int = (
        DEFAULT_RECOVERY_ATTEMPTS
    ),
    sleeper: Callable[[float], None] = time.sleep,
) -> ResultT:
    if delay_seconds < 0:
        raise ValueError(
            "Circuit recovery delay cannot be negative"
        )

    if recovery_attempts < 0:
        raise ValueError(
            "Circuit recovery attempts cannot be negative"
        )

    path = (
        quarantine_path
        or default_quarantine_path()
    )
    retry_number = 0
    quarantine_written = False

    while True:
        token = _RECOVERY_ATTEMPT.set(
            retry_number > 0
        )

        try:
            result = operation()
        except BlackDuckCircuitOpenError as error:
            target = write_quarantine(
                path,
                error,
                delay_seconds=delay_seconds,
            )
            quarantine_written = (
                quarantine_written
                or target is not None
            )

            if retry_number >= recovery_attempts:
                raise

            retry_number += 1
            print(
                "Black Duck circuit breaker opened. "
                f"Keeping the pipeline lock and waiting "
                f"{delay_seconds}s before recovery attempt "
                f"{retry_number}/{recovery_attempts}.",
                file=sys.stderr,
            )
            sleeper(delay_seconds)
            error.reset_circuit()
        else:
            if (
                retry_number > 0
                and quarantine_written
                and (
                    not isinstance(result, int)
                    or result == 0
                )
            ):
                mark_quarantine_recovered(path)

            return result
        finally:
            _RECOVERY_ATTEMPT.reset(token)
