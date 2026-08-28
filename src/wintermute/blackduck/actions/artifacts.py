from __future__ import annotations

import json
import os
import shutil
import uuid
from hashlib import sha256
from pathlib import Path
from typing import Any

from wintermute.blackduck.actions.models import (
    ActionPlan,
    canonical_json,
)


PLAN_FILE = "plan.json"
CHECKSUMS_FILE = "checksums.json"
READY_FILE = "READY"
RESERVED_FILES = {
    PLAN_FILE,
    CHECKSUMS_FILE,
    READY_FILE,
}


class ActionArtifactError(RuntimeError):
    pass


def sha256_bytes(value: bytes) -> str:
    return (
        "sha256:"
        + sha256(value).hexdigest()
    )


def sha256_file(path: Path) -> str:
    digest = sha256()

    with path.open("rb") as input_file:
        while chunk := input_file.read(
            1024 * 1024
        ):
            digest.update(chunk)

    return f"sha256:{digest.hexdigest()}"


def json_bytes(value: Any) -> bytes:
    return canonical_json(value) + b"\n"


def write_bytes(
    path: Path,
    value: bytes,
) -> None:
    temporary = path.with_name(
        f"{path.name}.{uuid.uuid4().hex}.tmp"
    )

    try:
        with temporary.open("wb") as output_file:
            output_file.write(value)
            output_file.flush()
            os.fsync(output_file.fileno())

        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def attachment_name(value: str) -> str:
    name = str(value or "").strip()

    if (
        not name
        or name in RESERVED_FILES
        or Path(name).name != name
        or name in {".", ".."}
    ):
        raise ValueError(
            f"Invalid attachment name: {value!r}"
        )

    return name


def write_action_plan(
    root: str | os.PathLike[str],
    plan: ActionPlan,
    *,
    attachments: dict[str, Any] | None = None,
) -> Path:
    plan.validate()
    root_path = Path(root).expanduser()
    root_path.mkdir(
        parents=True,
        exist_ok=True,
    )
    destination = root_path / plan.plan_id

    if destination.exists():
        raise ActionArtifactError(
            f"Action plan already exists: "
            f"{destination}"
        )

    staging = root_path / (
        f".{plan.plan_id}."
        f"{uuid.uuid4().hex}.tmp"
    )
    staging.mkdir()

    try:
        write_bytes(
            staging / PLAN_FILE,
            json_bytes(plan.as_dict()),
        )

        for raw_name, payload in (
            attachments or {}
        ).items():
            name = attachment_name(raw_name)
            write_bytes(
                staging / name,
                json_bytes(payload),
            )

        protected = sorted(
            path.name
            for path in staging.iterdir()
        )
        checksums = {
            "schema_version": 1,
            "plan_id": plan.plan_id,
            "files": {
                name: sha256_file(
                    staging / name
                )
                for name in protected
            },
        }
        checksum_data = json_bytes(checksums)

        write_bytes(
            staging / CHECKSUMS_FILE,
            checksum_data,
        )
        write_bytes(
            staging / READY_FILE,
            (
                sha256_bytes(checksum_data)
                + "\n"
            ).encode("utf-8"),
        )
        os.replace(staging, destination)
        return destination
    except BaseException:
        shutil.rmtree(
            staging,
            ignore_errors=True,
        )
        raise


def read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8")
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        raise ActionArtifactError(
            f"Could not read {path.name}: {error}"
        ) from error

    if not isinstance(value, dict):
        raise ActionArtifactError(
            f"{path.name} must contain an object"
        )

    return value


def load_verified_action_plan(
    path: str | os.PathLike[str],
    *,
    require_unexpired: bool = True,
) -> ActionPlan:
    plan_path = Path(path).expanduser()

    if (
        not plan_path.is_dir()
        or plan_path.is_symlink()
    ):
        raise ActionArtifactError(
            f"Invalid action-plan directory: "
            f"{plan_path}"
        )

    for name in RESERVED_FILES:
        candidate = plan_path / name

        if (
            not candidate.is_file()
            or candidate.is_symlink()
        ):
            raise ActionArtifactError(
                f"Missing action-plan file: {name}"
            )

    for child in plan_path.iterdir():
        if child.is_symlink() or not child.is_file():
            raise ActionArtifactError(
                f"Invalid action-plan entry: "
                f"{child.name}"
            )

    checksum_path = plan_path / CHECKSUMS_FILE
    checksum_data = checksum_path.read_bytes()
    ready = (
        plan_path / READY_FILE
    ).read_text(encoding="utf-8")

    if ready != (
        sha256_bytes(checksum_data) + "\n"
    ):
        raise ActionArtifactError(
            "READY checksum does not match"
        )

    checksum_payload = read_object(
        checksum_path
    )

    if checksum_payload.get(
        "schema_version"
    ) != 1:
        raise ActionArtifactError(
            "Unsupported checksum schema"
        )

    files = checksum_payload.get("files")

    if not isinstance(files, dict):
        raise ActionArtifactError(
            "Checksum file map is missing"
        )

    actual_files = {
        child.name
        for child in plan_path.iterdir()
        if child.name
        not in {
            CHECKSUMS_FILE,
            READY_FILE,
        }
    }

    if actual_files != set(files):
        raise ActionArtifactError(
            "Protected file set does not match"
        )

    for name, expected in files.items():
        if (
            name != PLAN_FILE
            and attachment_name(name) != name
        ):
            raise ActionArtifactError(
                f"Invalid checksum entry: {name}"
            )

        if sha256_file(
            plan_path / name
        ) != str(expected):
            raise ActionArtifactError(
                f"Checksum mismatch: {name}"
            )

    try:
        plan = ActionPlan.from_dict(
            read_object(plan_path / PLAN_FILE)
        )

        if require_unexpired:
            plan.assert_not_expired()
    except (TypeError, ValueError) as error:
        raise ActionArtifactError(
            str(error)
        ) from error

    if (
        checksum_payload.get("plan_id")
        != plan.plan_id
    ):
        raise ActionArtifactError(
            "Plan ID does not match checksums"
        )

    return plan
