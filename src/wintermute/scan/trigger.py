from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import time
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote, urlsplit

from wintermute.ai.models import (
    stable_digest,
)
from wintermute.ai.storage import (
    atomic_write_json,
    sha256_file,
)
from wintermute.paths import output_root
from wintermute.scm.onboarding.http import (
    HttpResult,
    OnboardingHttpClient,
)
from wintermute.scm.providers.detection import (
    gitlab_rest_url,
)


COMMIT_PATTERN = re.compile(
    r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
)
_SEGMENT = r"[^/?#]+"
_TRIGGER_ROUTES = {
    "GET": (
        re.compile(
            rf"^/projects/{_SEGMENT}/"
            rf"repository/commits/{_SEGMENT}$"
        ),
        re.compile(
            r"^/projects/[0-9]+/"
            r"pipelines/[0-9]+$"
        ),
        re.compile(
            r"^/projects/[0-9]+/"
            r"pipelines/[0-9]+/jobs$"
        ),
        re.compile(
            r"^/projects/[0-9]+/"
            r"jobs/[0-9]+/artifacts$"
        ),
    ),
    "POST": (
        re.compile(
            r"^/projects/[0-9]+/pipeline$"
        ),
    ),
}
TERMINAL_PIPELINE_STATUSES = {
    "success",
    "failed",
    "canceled",
    "skipped",
}
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_FILES = 1000


class LauncherTriggerError(RuntimeError):
    pass


class GitLabLauncherTriggerClient(
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
                _TRIGGER_ROUTES.get(
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


def now_text() -> str:
    return (
        __import__("datetime")
        .datetime.now(
            __import__("datetime")
            .timezone.utc
        )
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def trigger_id() -> str:
    return (
        time.strftime(
            "%Y%m%dT%H%M%SZ",
            time.gmtime(),
        )
        + "-gitlab-launcher-dry-run-"
        + uuid.uuid4().hex[:12]
    )


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
        raise LauncherTriggerError(
            "GitLab project path is invalid"
        )

    return selected


def validate_commit(
    value: str,
) -> str:
    selected = str(value or "").strip().casefold()

    if COMMIT_PATTERN.fullmatch(
        selected
    ) is None:
        raise LauncherTriggerError(
            "Commit SHA must be a full "
            "Git object ID"
        )

    return selected


def exact_project(
    client: GitLabLauncherTriggerClient,
    path: str,
) -> dict[str, Any]:
    selected = validate_project_path(
        path
    )
    result = client.get_json(
        f"/projects/{quote(selected, safe='')}"
    )
    payload = result.payload

    if not isinstance(payload, dict):
        raise LauncherTriggerError(
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
        raise LauncherTriggerError(
            "GitLab returned another project"
        )

    try:
        project_id = int(payload["id"])
    except (
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise LauncherTriggerError(
            "GitLab project has no numeric ID"
        ) from error

    if project_id < 1:
        raise LauncherTriggerError(
            "GitLab project ID is invalid"
        )

    if payload.get("archived") is True:
        raise LauncherTriggerError(
            "Archived projects cannot be scanned"
        )

    return {
        "id": project_id,
        "path": selected,
        "default_branch": str(
            payload.get("default_branch")
            or ""
        ),
        "web_url": str(
            payload.get("web_url")
            or ""
        ),
    }


def exact_commit(
    client: GitLabLauncherTriggerClient,
    project_id: int,
    revision: str,
) -> dict[str, str]:
    selected_revision = str(
        revision or ""
    ).strip()

    if not selected_revision:
        raise LauncherTriggerError(
            "Target revision must not be empty"
        )

    result = client.get_json(
        (
            f"/projects/{project_id}/"
            "repository/commits/"
            f"{quote(selected_revision, safe='')}"
        )
    )
    payload = result.payload

    if not isinstance(payload, dict):
        raise LauncherTriggerError(
            "GitLab commit response is invalid"
        )

    commit = validate_commit(
        str(payload.get("id") or "")
    )

    if COMMIT_PATTERN.fullmatch(
        selected_revision.casefold()
    ):
        expected = validate_commit(
            selected_revision
        )

        if commit != expected:
            raise LauncherTriggerError(
                "GitLab returned another commit"
            )

    return {
        "commit_sha": commit,
        "title": str(
            payload.get("title")
            or ""
        ),
        "web_url": str(
            payload.get("web_url")
            or ""
        ),
    }


def pipeline_variables(
    *,
    target_project_id: int,
    commit_sha: str,
    target_ref: str,
) -> list[dict[str, str]]:
    return [
        {
            "key": "TARGET_PROJECT_ID",
            "variable_type": "env_var",
            "value": str(
                target_project_id
            ),
        },
        {
            "key": "TARGET_COMMIT_SHA",
            "variable_type": "env_var",
            "value": validate_commit(
                commit_sha
            ),
        },
        {
            "key": "TARGET_REF",
            "variable_type": "env_var",
            "value": str(
                target_ref or ""
            ),
        },
        {
            "key": "WINTERMUTE_SCAN_MODE",
            "variable_type": "env_var",
            "value": "dry-run",
        },
        {
            "key": (
                "WINTERMUTE_SCAN_CONFIRMATION"
            ),
            "variable_type": "env_var",
            "value": "",
        },
    ]


def trigger_pipeline(
    client: GitLabLauncherTriggerClient,
    *,
    central_project_id: int,
    central_ref: str,
    target_project_id: int,
    commit_sha: str,
    target_ref: str,
) -> dict[str, Any]:
    result = client.mutate_json(
        "POST",
        (
            f"/projects/{central_project_id}/"
            "pipeline"
        ),
        {
            "ref": central_ref,
            "variables": pipeline_variables(
                target_project_id=(
                    target_project_id
                ),
                commit_sha=commit_sha,
                target_ref=target_ref,
            ),
        },
        expected_statuses={201},
    )
    payload = result.payload

    if not isinstance(payload, dict):
        raise LauncherTriggerError(
            "GitLab pipeline response is invalid"
        )

    try:
        pipeline_id = int(payload["id"])
    except (
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise LauncherTriggerError(
            "GitLab pipeline has no numeric ID"
        ) from error

    if pipeline_id < 1:
        raise LauncherTriggerError(
            "GitLab pipeline ID is invalid"
        )

    if str(
        payload.get("ref") or ""
    ) != central_ref:
        raise LauncherTriggerError(
            "GitLab created the pipeline "
            "on another ref"
        )

    return dict(payload)


def pipeline_summary(
    payload: dict[str, Any],
) -> dict[str, Any]:
    return {
        name: payload.get(name)
        for name in (
            "id",
            "status",
            "ref",
            "sha",
            "web_url",
            "created_at",
            "updated_at",
        )
    }


def job_summary(
    payload: dict[str, Any],
) -> dict[str, Any]:
    return {
        name: payload.get(name)
        for name in (
            "id",
            "name",
            "stage",
            "status",
            "ref",
            "web_url",
            "created_at",
            "started_at",
            "finished_at",
            "duration",
            "artifacts_file",
        )
    }


def wait_for_pipeline(
    client: GitLabLauncherTriggerClient,
    *,
    central_project_id: int,
    pipeline_id: int,
    timeout: float,
    poll_interval: float,
) -> dict[str, Any]:
    import math

    for name, value in (
        ("timeout", timeout),
        ("poll_interval", poll_interval),
    ):
        if (
            type(value) not in {int, float}
            or not math.isfinite(value)
            or value <= 0
        ):
            raise LauncherTriggerError(
                f"{name} must be finite and positive"
            )

    for name, value in (
        ("central_project_id", central_project_id),
        ("pipeline_id", pipeline_id),
    ):
        if type(value) is not int or value < 1:
            raise LauncherTriggerError(f"{name} must be a positive integer")

    original_timeout = client.timeout
    original_retries = client.retries
    if (
        not math.isfinite(float(original_timeout))
        or original_timeout <= 0
    ):
        raise LauncherTriggerError("Client timeout must be finite and positive")

    deadline = time.monotonic() + timeout
    path = f"/projects/{central_project_id}/pipelines/{pipeline_id}"
    active_statuses = {
        "created",
        "waiting_for_resource",
        "preparing",
        "pending",
        "running",
        "scheduled",
        "canceling",
    }

    try:
        client.retries = 0

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LauncherTriggerError(
                    "Central launcher pipeline timed out; "
                    "the remote pipeline was not canceled"
                )

            client.timeout = min(float(original_timeout), remaining)
            result = client.get_json(path)
            payload = result.payload

            if not isinstance(payload, dict):
                raise LauncherTriggerError(
                    "GitLab pipeline status is invalid"
                )

            if (
                type(payload.get("id")) is not int
                or payload["id"] != pipeline_id
                or type(payload.get("project_id")) is not int
                or payload["project_id"] != central_project_id
            ):
                raise LauncherTriggerError(
                    "GitLab returned another pipeline identity"
                )

            status = str(payload.get("status") or "").casefold()

            if time.monotonic() > deadline:
                raise LauncherTriggerError(
                    "Central launcher pipeline wait budget was exceeded; "
                    "the remote pipeline was not canceled"
                )

            if status in TERMINAL_PIPELINE_STATUSES:
                if status != "success":
                    raise LauncherTriggerError(
                        "Central launcher pipeline finished with status "
                        f"{status} (pipeline {pipeline_id})"
                    )
                return dict(payload)

            if status == "manual":
                raise LauncherTriggerError(
                    "Central launcher pipeline requires manual intervention "
                    f"(pipeline {pipeline_id})"
                )

            if status not in active_statuses:
                raise LauncherTriggerError(
                    f"GitLab returned an unsupported pipeline status: {status!r}"
                )

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LauncherTriggerError(
                    "Central launcher pipeline timed out; "
                    "the remote pipeline was not canceled"
                )
            time.sleep(min(poll_interval, remaining))
    finally:
        client.timeout = original_timeout
        client.retries = original_retries



def launcher_job(
    client: GitLabLauncherTriggerClient,
    *,
    central_project_id: int,
    pipeline_id: int,
) -> dict[str, Any]:
    jobs = client.paged_list(
        (
            f"/projects/{central_project_id}/"
            f"pipelines/{pipeline_id}/jobs"
        )
    )
    matches = [
        job
        for job in jobs
        if str(
            job.get("name") or ""
        )
        == "wintermute_central_scan"
    ]

    if len(matches) != 1:
        raise LauncherTriggerError(
            "Central launcher pipeline did not "
            "contain exactly one launcher job"
        )

    job = matches[0]

    if job.get("status") != "success":
        raise LauncherTriggerError(
            "Central launcher job did not succeed"
        )

    artifact = job.get(
        "artifacts_file"
    )

    if not isinstance(artifact, dict):
        raise LauncherTriggerError(
            "Central launcher job has no artifact"
        )

    try:
        size = int(
            artifact.get("size") or 0
        )
    except (
        TypeError,
        ValueError,
    ) as error:
        raise LauncherTriggerError(
            "Central launcher artifact size "
            "is invalid"
        ) from error

    if size < 1:
        raise LauncherTriggerError(
            "Central launcher artifact is empty"
        )

    return dict(job)


def safe_artifact_path(
    value: str,
) -> PurePosixPath:
    selected = str(value or "")

    if "\\" in selected:
        raise LauncherTriggerError(
            "Artifact archive contains "
            "an unsafe path"
        )

    path = PurePosixPath(selected)

    if (
        path.is_absolute()
        or not path.parts
        or ".." in path.parts
    ):
        raise LauncherTriggerError(
            "Artifact archive contains "
            "an unsafe path"
        )

    return path


def download_artifact(
    client: GitLabLauncherTriggerClient,
    *,
    central_project_id: int,
    job_id: int,
    retries: int = 6,
) -> bytes:
    path = (
        f"/projects/{central_project_id}/"
        f"jobs/{job_id}/artifacts"
    )

    for attempt in range(retries):
        result = client.get_bytes(
            path,
            allow_not_found=True,
        )

        if result.status_code == 200:
            content = bytes(result.payload)

            if not content:
                raise LauncherTriggerError(
                    "Launcher artifact download "
                    "was empty"
                )

            if (
                len(content)
                > MAX_ARTIFACT_BYTES
            ):
                raise LauncherTriggerError(
                    "Launcher artifact exceeded "
                    "the size limit"
                )

            return content

        if attempt + 1 < retries:
            time.sleep(2)

    raise LauncherTriggerError(
        "Launcher artifact was not available"
    )


def verify_launcher_artifact(
    content: bytes,
    *,
    provider_instance: str,
    project_id: int,
    commit_sha: str,
    expected_registry_sha256: str = "",
    expected_bridge_sha256: str = "",
    expected_contract_id: str = "",
) -> tuple[dict[str, Any], bytes, bytes]:
    import io

    from wintermute.scan.security import sha256_digest

    if not content or len(content) > MAX_ARTIFACT_BYTES:
        raise LauncherTriggerError("Launcher artifact has an invalid size")

    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            members = archive.infolist()
            if len(members) > MAX_ARTIFACT_FILES:
                raise LauncherTriggerError(
                    "Launcher artifact contains too many files"
                )

            by_name: dict[str, zipfile.ZipInfo] = {}
            total_size = 0

            for member in members:
                selected = safe_artifact_path(member.filename)
                rendered = selected.as_posix()

                if rendered in by_name:
                    raise LauncherTriggerError(
                        "Launcher artifact contains a duplicate path"
                    )
                by_name[rendered] = member

                mode = (member.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(mode)
                if (
                    member.flag_bits & 0x1
                    or file_type not in {0, stat.S_IFREG, stat.S_IFDIR}
                ):
                    raise LauncherTriggerError(
                        "Launcher artifact contains a link, special, or encrypted file"
                    )

                total_size += member.file_size
                if (
                    member.file_size < 0
                    or member.file_size > MAX_ARTIFACT_BYTES
                    or total_size > MAX_ARTIFACT_BYTES
                ):
                    raise LauncherTriggerError(
                        "Launcher artifact exceeded the expanded size limit"
                    )

            receipts = [
                name
                for name, member in by_name.items()
                if not member.is_dir()
                and PurePosixPath(name).name == "launcher-receipt.json"
            ]
            if len(receipts) != 1:
                raise LauncherTriggerError(
                    "Launcher artifact must contain exactly one launcher receipt"
                )

            receipt_name = receipts[0]
            checksum_name = (
                PurePosixPath(receipt_name)
                .with_name("checksums.json")
                .as_posix()
            )
            if (
                checksum_name not in by_name
                or by_name[checksum_name].is_dir()
            ):
                raise LauncherTriggerError(
                    "Launcher artifact has no receipt checksum"
                )

            receipt_bytes = archive.read(by_name[receipt_name])
            checksum_bytes = archive.read(by_name[checksum_name])

    except (OSError, zipfile.BadZipFile, KeyError, RuntimeError, NotImplementedError) as error:
        if isinstance(error, LauncherTriggerError):
            raise
        raise LauncherTriggerError("Launcher artifact is invalid") from error

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON object key")
            result[key] = value
        return result

    try:
        receipt = json.loads(
            receipt_bytes.decode("utf-8"),
            object_pairs_hook=unique_object,
        )
        checksums = json.loads(
            checksum_bytes.decode("utf-8"),
            object_pairs_hook=unique_object,
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise LauncherTriggerError(
            "Launcher receipt is invalid JSON"
        ) from error

    if not isinstance(receipt, dict) or not isinstance(checksums, dict):
        raise LauncherTriggerError(
            "Launcher receipt artifacts must be objects"
        )

    if (
        type(receipt.get("schema_version")) is not int
        or receipt["schema_version"] != 1
        or type(checksums.get("schema_version")) is not int
        or checksums["schema_version"] != 1
    ):
        raise LauncherTriggerError("Launcher receipt schema is invalid")

    checksum_map = checksums.get("sha256")
    if not isinstance(checksum_map, dict):
        raise LauncherTriggerError(
            "Launcher receipt checksum map is invalid"
        )

    expected = checksum_map.get("launcher-receipt.json")
    actual = hashlib.sha256(receipt_bytes).hexdigest()
    if not isinstance(expected, str) or expected != actual:
        raise LauncherTriggerError("Launcher receipt checksum mismatch")

    expected_values = {
        "status": "succeeded",
        "mode": "dry-run",
        "provider": "gitlab",
        "provider_instance": provider_instance,
        "project_id": str(project_id),
        "commit_sha": validate_commit(commit_sha),
        "scan_exit_code": 0,
        "workspace_deleted": True,
        "target_repository_modified": False,
    }
    for field, expected_value in expected_values.items():
        value = receipt.get(field)
        if type(value) is not type(expected_value) or value != expected_value:
            raise LauncherTriggerError(
                f"Launcher receipt field {field!r} did not verify"
            )

    contract_id = receipt.get("scan_contract_id")
    if not isinstance(contract_id, str) or not contract_id.strip():
        raise LauncherTriggerError(
            "Launcher receipt has no scan contract ID"
        )

    for field in ("registry_sha256", "bridge_sha256", "archive_sha256"):
        value = receipt.get(field)
        if not isinstance(value, str):
            raise LauncherTriggerError(
                f"Launcher receipt field {field!r} is invalid"
            )
        try:
            sha256_digest(value)
        except ValueError as error:
            raise LauncherTriggerError(
                f"Launcher receipt field {field!r} is invalid"
            ) from error

    for field, expected_digest in (
        ("registry_sha256", expected_registry_sha256),
        ("bridge_sha256", expected_bridge_sha256),
    ):
        if expected_digest and sha256_digest(receipt[field]) != sha256_digest(
            expected_digest
        ):
            raise LauncherTriggerError(
                f"Launcher receipt field {field!r} differs from expected identity"
            )

    if expected_contract_id and contract_id != expected_contract_id:
        raise LauncherTriggerError("Launcher receipt scan contract differs")

    return receipt, receipt_bytes, checksum_bytes


def write_trigger_result(
    root: Path,
    identifier: str,
    result: dict[str, Any],
    *,
    launcher_receipt: bytes = b"",
    launcher_checksums: bytes = b"",
) -> Path:
    from wintermute.scan.security import redact_payload

    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", identifier) is None:
        raise LauncherTriggerError("Launcher trigger result ID is invalid")

    staging = root / ".staging" / identifier
    destination = root / identifier
    if destination.exists():
        raise LauncherTriggerError("Launcher trigger result already exists")

    staging.mkdir(parents=True, exist_ok=False)
    names = ["result.json"]

    try:
        atomic_write_json(
            staging / "result.json",
            redact_payload(result),
        )

        if launcher_receipt:
            (staging / "launcher-receipt.json").write_bytes(launcher_receipt)
            names.append("launcher-receipt.json")

        if launcher_checksums:
            (staging / "launcher-checksums.json").write_bytes(
                launcher_checksums
            )
            names.append("launcher-checksums.json")

        atomic_write_json(
            staging / "checksums.json",
            {
                "schema_version": 1,
                "sha256": {
                    name: sha256_file(staging / name)
                    for name in names
                },
            },
        )
        root.mkdir(parents=True, exist_ok=True)
        os.replace(staging, destination)
        atomic_write_json(
            destination / "READY",
            {
                "schema_version": 1,
                "trigger_id": identifier,
                "ready_at": now_text(),
            },
        )
        return destination
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def run(args: argparse.Namespace) -> int:
    import math

    from wintermute.scan.security import redact_payload, redact_text, sha256_digest

    if not getattr(args, "confirm_trigger", False):
        raise LauncherTriggerError(
            "Creating a launcher pipeline requires --confirm-trigger"
        )

    expected_registry = sha256_digest(args.expected_registry_sha256)
    expected_bridge = sha256_digest(args.expected_bridge_sha256)
    expected_contract = str(args.expected_contract_id or "").strip()
    if not expected_contract:
        raise LauncherTriggerError("Expected scan contract ID is required")

    for name in ("timeout", "wait_timeout", "poll_interval"):
        value = float(getattr(args, name))
        if not math.isfinite(value) or value <= 0:
            raise LauncherTriggerError(f"{name} must be finite and positive")
    for name in ("retry_delay", "request_interval_seconds"):
        value = float(getattr(args, name))
        if not math.isfinite(value) or value < 0:
            raise LauncherTriggerError(f"{name} must be finite and nonnegative")
    if type(args.retries) is not int or args.retries < 0:
        raise LauncherTriggerError("retries must be a nonnegative integer")

    read_token = os.getenv("GITLAB_TOKEN", "").strip()
    from wintermute.scm.onboarding.credentials import gitlab_action_token
    mutation_token = gitlab_action_token()
    if not read_token:
        raise LauncherTriggerError("GITLAB_TOKEN must be set")
    if not mutation_token:
        raise LauncherTriggerError("GITLAB_ACTION_TOKEN must be set")

    central_path = validate_project_path(args.central_project)
    target_path = validate_project_path(args.target_project)
    central_ref = str(args.central_ref or "").strip()
    if not central_ref:
        raise LauncherTriggerError("Central ref must not be empty")
    if args.commit_sha:
        validate_commit(args.commit_sha)

    base_url = gitlab_rest_url(args.gitlab_url)
    provider_instance = urlsplit(base_url).netloc.casefold()
    client = GitLabLauncherTriggerClient(
        "gitlab",
        base_url,
        read_token,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        request_interval_seconds=args.request_interval_seconds,
        insecure=args.insecure,
        ca_bundle=args.ca_bundle,
    )
    action_client = GitLabLauncherTriggerClient(
        "gitlab",
        base_url,
        mutation_token,
        timeout=args.timeout,
        retries=0,
        retry_delay=0,
        request_interval_seconds=args.request_interval_seconds,
        insecure=args.insecure,
        ca_bundle=args.ca_bundle,
    )

    identifier = trigger_id()
    result_root = Path(args.result_root).expanduser().resolve()
    central: dict[str, Any] = {}
    target: dict[str, Any] = {}
    commit: dict[str, Any] = {}
    pipeline: dict[str, Any] = {}
    job: dict[str, Any] = {}
    target_ref = str(args.target_ref or "").strip()

    try:
        central = exact_project(client, central_path)
        target = exact_project(client, target_path)
        target_ref = target_ref or target["default_branch"]
        revision = args.commit_sha or target_ref
        if not revision:
            raise LauncherTriggerError(
                "Supply an exact commit or a target ref"
            )

        commit = exact_commit(client, target["id"], revision)
        pipeline = trigger_pipeline(
            action_client,
            central_project_id=central["id"],
            central_ref=central_ref,
            target_project_id=target["id"],
            commit_sha=commit["commit_sha"],
            target_ref=target_ref,
        )
        pipeline_id = int(pipeline["id"])
        completed_pipeline = wait_for_pipeline(
            client,
            central_project_id=central["id"],
            pipeline_id=pipeline_id,
            timeout=args.wait_timeout,
            poll_interval=args.poll_interval,
        )
        pipeline = completed_pipeline
        job = launcher_job(
            client,
            central_project_id=central["id"],
            pipeline_id=pipeline_id,
        )
        artifact = download_artifact(
            client,
            central_project_id=central["id"],
            job_id=int(job["id"]),
        )
        receipt, receipt_bytes, checksum_bytes = verify_launcher_artifact(
            artifact,
            provider_instance=provider_instance,
            project_id=target["id"],
            commit_sha=commit["commit_sha"],
            expected_registry_sha256=expected_registry,
            expected_bridge_sha256=expected_bridge,
            expected_contract_id=expected_contract,
        )

        result = {
            "schema_version": 1,
            "trigger_id": identifier,
            "created_at": now_text(),
            "status": "succeeded",
            "mode": "dry-run",
            "provider": "gitlab",
            "provider_instance": provider_instance,
            "central_project": central["path"],
            "central_project_id": central["id"],
            "central_ref": central_ref,
            "target_project": target["path"],
            "target_project_id": target["id"],
            "target_ref": target_ref,
            "target_commit_sha": commit["commit_sha"],
            "pipeline": pipeline_summary(pipeline),
            "job": job_summary(job),
            "scan_contract_id": receipt["scan_contract_id"],
            "registry_sha256": receipt["registry_sha256"],
            "bridge_sha256": receipt["bridge_sha256"],
            "archive_sha256": receipt["archive_sha256"],
            "workspace_deleted": True,
            "target_source_modified": False,
            "writes": action_client.writes,
            "requests": client.requests + action_client.requests,
        }
        directory = write_trigger_result(
            result_root,
            identifier,
            result,
            launcher_receipt=receipt_bytes,
            launcher_checksums=checksum_bytes,
        )
    except BaseException as error:
        failure = {
            "schema_version": 1,
            "trigger_id": identifier,
            "created_at": now_text(),
            "status": (
                "interrupted" if isinstance(error, KeyboardInterrupt) else "failed"
            ),
            "mode": "dry-run",
            "provider": "gitlab",
            "provider_instance": provider_instance,
            "central_project": central.get("path", central_path),
            "central_project_id": central.get("id"),
            "central_ref": central_ref,
            "target_project": target.get("path", target_path),
            "target_project_id": target.get("id"),
            "target_ref": target_ref,
            "target_commit_sha": commit.get("commit_sha", ""),
            "pipeline": pipeline_summary(pipeline) if pipeline else None,
            "job": job_summary(job) if job else None,
            "error": redact_text(str(error)),
            "target_source_modified": False,
            "writes": action_client.writes,
            "requests": client.requests + action_client.requests,
        }
        directory = write_trigger_result(result_root, identifier, failure)
        if isinstance(error, KeyboardInterrupt):
            raise
        if not isinstance(error, Exception):
            raise
        raise LauncherTriggerError(
            f"{redact_text(str(error))}; trigger receipt: {directory}"
        ) from error

    print(json.dumps(
        redact_payload({**result, "result_directory": str(directory)}),
        indent=2,
        sort_keys=True,
    ))
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    import math

    from wintermute.scan.security import sha256_digest

    parser = argparse.ArgumentParser(
        description=(
            "Explicitly trigger one central GitLab launcher dry run "
            "and verify its persisted receipt against expected identities."
        )
    )
    parser.add_argument("--gitlab-url", required=True)
    parser.add_argument("--central-project", required=True)
    parser.add_argument("--central-ref", default="main")
    parser.add_argument("--target-project", required=True)
    parser.add_argument("--target-ref", default="")
    parser.add_argument(
        "--commit-sha",
        default="",
        help=(
            "Exact target commit. If omitted, resolve the target ref "
            "to a full SHA before creating the pipeline."
        ),
    )
    parser.add_argument(
        "--confirm-trigger",
        action="store_true",
        help="Authorize creation of one GitLab pipeline; scanner mode stays dry-run.",
    )
    parser.add_argument("--expected-registry-sha256", required=True)
    parser.add_argument("--expected-bridge-sha256", required=True)
    parser.add_argument("--expected-contract-id", required=True)
    parser.add_argument(
        "--result-root",
        default=str(output_root() / "scan" / "launcher-triggers"),
    )
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--retry-delay", type=float, default=1)
    parser.add_argument("--request-interval-seconds", type=float, default=0.5)
    parser.add_argument("--wait-timeout", type=float, default=5400)
    parser.add_argument("--poll-interval", type=float, default=15)
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument("--insecure", action="store_true")
    tls.add_argument("--ca-bundle")
    args = parser.parse_args(argv)

    for field in ("timeout", "wait_timeout", "poll_interval"):
        value = getattr(args, field)
        if not math.isfinite(value) or value <= 0:
            parser.error(
                f"--{field.replace('_', '-')} must be finite and positive"
            )
    for field in ("retry_delay", "request_interval_seconds"):
        value = getattr(args, field)
        if not math.isfinite(value) or value < 0:
            parser.error(
                f"--{field.replace('_', '-')} must be finite and nonnegative"
            )
    if args.retries < 0:
        parser.error("--retries cannot be negative")
    if not args.confirm_trigger:
        parser.error("Creating a pipeline requires --confirm-trigger")
    if not args.expected_contract_id.strip():
        parser.error("--expected-contract-id must not be empty")

    try:
        validate_project_path(args.central_project)
        validate_project_path(args.target_project)
        sha256_digest(args.expected_registry_sha256)
        sha256_digest(args.expected_bridge_sha256)
        if args.commit_sha:
            validate_commit(args.commit_sha)
    except (ValueError, LauncherTriggerError) as error:
        parser.error(str(error))

    return args


def main(argv: list[str] | None = None) -> int:
    from wintermute.scan.security import redact_text

    try:
        return run(parse_args(argv))
    except KeyboardInterrupt:
        return 130
    except (OSError, RuntimeError, ValueError) as error:
        print(f"ERROR: {redact_text(str(error))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
