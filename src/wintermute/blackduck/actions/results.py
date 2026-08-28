from __future__ import annotations

import json
import os
import shutil
import uuid
from hashlib import sha256
from pathlib import Path
from typing import Any

from wintermute.blackduck.actions.executor import (
    ExecutionResult,
)
from wintermute.blackduck.actions.models import (
    canonical_json,
)


RESULT_FILE = "result.json"
CHECKSUMS_FILE = "checksums.json"
COMPLETE_FILE = "COMPLETE"


class ActionResultError(RuntimeError):
    pass


def digest_bytes(value: bytes) -> str:
    return (
        "sha256:"
        + sha256(value).hexdigest()
    )


def digest_file(path: Path) -> str:
    digest = sha256()

    with path.open("rb") as input_file:
        while chunk := input_file.read(
            1024 * 1024
        ):
            digest.update(chunk)

    return f"sha256:{digest.hexdigest()}"


def write_file(
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


def write_execution_result(
    root: str | os.PathLike[str],
    result: ExecutionResult,
) -> Path:
    root_path = Path(root).expanduser()
    root_path.mkdir(
        parents=True,
        exist_ok=True,
    )
    destination = (
        root_path / result.execution_id
    )

    if destination.exists():
        raise ActionResultError(
            f"Execution result already exists: "
            f"{destination}"
        )

    staging = root_path / (
        f".{result.execution_id}."
        f"{uuid.uuid4().hex}.tmp"
    )
    staging.mkdir()

    try:
        result_data = (
            canonical_json(result.as_dict())
            + b"\n"
        )
        write_file(
            staging / RESULT_FILE,
            result_data,
        )
        checksums = {
            "schema_version": 1,
            "execution_id": (
                result.execution_id
            ),
            "files": {
                RESULT_FILE: digest_file(
                    staging / RESULT_FILE
                ),
            },
        }
        checksum_data = (
            canonical_json(checksums) + b"\n"
        )
        write_file(
            staging / CHECKSUMS_FILE,
            checksum_data,
        )
        write_file(
            staging / COMPLETE_FILE,
            (
                digest_bytes(checksum_data)
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
        payload = json.loads(
            path.read_text(encoding="utf-8")
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        raise ActionResultError(
            f"Could not read {path.name}: {error}"
        ) from error

    if not isinstance(payload, dict):
        raise ActionResultError(
            f"{path.name} must contain an object"
        )

    return payload


def load_verified_execution_result(
    path: str | os.PathLike[str],
) -> ExecutionResult:
    result_path = Path(path).expanduser()

    if (
        not result_path.is_dir()
        or result_path.is_symlink()
    ):
        raise ActionResultError(
            f"Invalid result directory: "
            f"{result_path}"
        )

    required = {
        RESULT_FILE,
        CHECKSUMS_FILE,
        COMPLETE_FILE,
    }

    if {
        child.name
        for child in result_path.iterdir()
    } != required:
        raise ActionResultError(
            "Execution result file set is invalid"
        )

    for child in result_path.iterdir():
        if child.is_symlink() or not child.is_file():
            raise ActionResultError(
                f"Invalid result entry: "
                f"{child.name}"
            )

    checksum_path = (
        result_path / CHECKSUMS_FILE
    )
    checksum_data = checksum_path.read_bytes()
    complete = (
        result_path / COMPLETE_FILE
    ).read_text(encoding="utf-8")

    if complete != (
        digest_bytes(checksum_data) + "\n"
    ):
        raise ActionResultError(
            "COMPLETE checksum does not match"
        )

    checksums = read_object(checksum_path)

    if (
        checksums.get("schema_version") != 1
        or set(checksums.get("files", {}))
        != {RESULT_FILE}
    ):
        raise ActionResultError(
            "Execution result checksums are invalid"
        )

    expected = checksums["files"][
        RESULT_FILE
    ]
    actual = digest_file(
        result_path / RESULT_FILE
    )

    if expected != actual:
        raise ActionResultError(
            "Execution result checksum mismatch"
        )

    try:
        result = ExecutionResult.from_dict(
            read_object(
                result_path / RESULT_FILE
            )
        )
    except (TypeError, ValueError) as error:
        raise ActionResultError(
            str(error)
        ) from error

    if (
        checksums.get("execution_id")
        != result.execution_id
    ):
        raise ActionResultError(
            "Execution ID does not match"
        )

    return result
