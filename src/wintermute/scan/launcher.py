from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import signal
import ssl
import subprocess
import sys
import tarfile
import tempfile
import uuid
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)

from wintermute.ai.storage import atomic_write_json
from wintermute.paths import output_root
from wintermute.scan.contracts import load_registry, resolve_scan
from wintermute.scan.engine import executable_path, validate_executable


COMMIT_PATTERN = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_EXTRACTED_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100000
EXECUTION_CONFIRMATION = "EXECUTE_APPROVED_SCAN"
ARCHIVE_CONTENT_TYPES = {
    "application/gzip",
    "application/x-gzip",
    "application/octet-stream",
    "application/x-compressed-tar",
}


class LauncherError(RuntimeError):
    pass


class RejectRedirects(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        response: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        raise LauncherError(
            "GitLab redirect refused; credentials were not forwarded"
        )


def normalized_api_url(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())
    if (
        parsed.scheme.casefold() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise LauncherError(
            "GitLab API URL must be HTTPS without credentials, query, or fragment"
        )
    try:
        parsed.port
    except ValueError as error:
        raise LauncherError("GitLab API port is invalid") from error

    path = parsed.path.rstrip("/")
    if not path.endswith("/api/v4"):
        raise LauncherError("GitLab API URL must end in /api/v4")
    return urlunsplit(("https", parsed.netloc.casefold(), path, "", ""))


def validated_project_id(value: str) -> str:
    selected = str(value or "").strip()
    if re.fullmatch(r"[1-9][0-9]*", selected) is None:
        raise LauncherError("Target project ID must be a positive integer")
    return selected


def validated_commit(value: str) -> str:
    selected = str(value or "").strip().casefold()
    if COMMIT_PATTERN.fullmatch(selected) is None:
        raise LauncherError("Target commit must be a full Git object ID")
    return selected


def validated_digest(value: str, field: str) -> str:
    selected = str(value or "").strip().removeprefix("sha256:").casefold()
    if re.fullmatch(r"[0-9a-f]{64}", selected) is None:
        raise LauncherError(f"{field} must be a SHA-256 digest")
    return selected


def positive_timeout(value: Any, field: str) -> float:
    try:
        selected = float(value)
    except (TypeError, ValueError) as error:
        raise LauncherError(f"{field} must be finite and positive") from error
    if not math.isfinite(selected) or selected <= 0:
        raise LauncherError(f"{field} must be finite and positive")
    return selected


def redact(value: str) -> str:
    rendered = str(value)
    secrets = {
        secret
        for name, secret in os.environ.items()
        if secret
        and any(
            marker in name.upper()
            for marker in ("TOKEN", "PASSWORD", "SECRET", "API_KEY")
        )
    }
    for secret in sorted(secrets, key=len, reverse=True):
        rendered = rendered.replace(secret, "[REDACTED]")
    return rendered


def tls_context(
    *,
    insecure: bool,
    ca_bundle: str | None,
) -> ssl.SSLContext | None:
    if type(insecure) is not bool:
        raise LauncherError("insecure must be boolean")
    if insecure and ca_bundle:
        raise LauncherError("Use either insecure mode or a CA bundle")
    if insecure:
        return ssl._create_unverified_context()
    if ca_bundle:
        path = Path(ca_bundle).expanduser()
        if not path.is_file():
            raise LauncherError(f"CA bundle does not exist: {path}")
        return ssl.create_default_context(cafile=str(path))
    return None


def request_headers(
    job_token: str = "",
    *,
    accept: str,
    api_token: str | None = None,
) -> dict[str, str]:
    if api_token is not None and job_token:
        raise LauncherError("Use one authentication method per GitLab request")

    if api_token is not None:
        raw = api_token
        variable = "WINTERMUTE_GITLAB_READ_TOKEN"
        header = "PRIVATE-TOKEN"
    else:
        raw = job_token
        variable = "CI_JOB_TOKEN"
        header = "JOB-TOKEN"

    if not isinstance(raw, str):
        raise LauncherError(f"{variable} must be a string")
    if "\r" in raw or "\n" in raw:
        raise LauncherError(f"{variable} contains invalid characters")

    token = raw.strip()
    if not token:
        raise LauncherError(f"{variable} must be set")

    return {
        "Accept": accept,
        header: token,
        "User-Agent": "blackduck-wintermute-launcher",
    }


def open_response(
    request: Request,
    *,
    context: ssl.SSLContext | None,
    timeout: float,
):
    parsed = urlsplit(request.full_url)
    if (
        parsed.scheme.casefold() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise LauncherError("GitLab request URL is invalid")

    opener = build_opener(
        HTTPSHandler(context=context),
        RejectRedirects(),
    )
    return opener.open(request, timeout=timeout)


def response_content_type(response: Any) -> str:
    return str(
        response.headers.get("Content-Type") or ""
    ).split(";", 1)[0].strip().casefold()


def check_response(response: Any, *, maximum_bytes: int) -> None:
    status = int(getattr(response, "status", 200))
    if status != 200:
        raise LauncherError(f"GitLab request returned HTTP {status}")

    raw_length = response.headers.get("Content-Length")
    if raw_length is not None:
        try:
            length = int(raw_length)
        except (TypeError, ValueError) as error:
            raise LauncherError("GitLab Content-Length is invalid") from error
        if length < 0 or length > maximum_bytes:
            raise LauncherError("GitLab response exceeded the size limit")


def request_json(
    url: str,
    *,
    job_token: str = "",
    api_token: str | None = None,
    context: ssl.SSLContext | None,
    timeout: float,
) -> dict[str, Any]:
    request = Request(
        url,
        headers=request_headers(
            job_token,
            api_token=api_token,
            accept="application/json",
        ),
        method="GET",
    )
    purpose = (
        "commit"
        if "/repository/commits/" in urlsplit(url).path
        else "project metadata"
    )

    try:
        with open_response(request, context=context, timeout=timeout) as response:
            check_response(response, maximum_bytes=MAX_JSON_BYTES)
            if response_content_type(response) != "application/json":
                raise LauncherError("GitLab response is not application/json")
            content = response.read(MAX_JSON_BYTES + 1)
    except HTTPError as error:
        status = error.code
        error.close()
        raise LauncherError(
            f"GitLab {purpose} request failed with HTTP {status}"
        ) from error
    except (URLError, TimeoutError, OSError) as error:
        raise LauncherError(
            f"GitLab {purpose} request failed: {redact(str(error))}"
        ) from error

    if len(content) > MAX_JSON_BYTES:
        raise LauncherError("GitLab JSON response exceeded the size limit")

    try:
        payload = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LauncherError("GitLab returned invalid JSON") from error

    if not isinstance(payload, dict):
        raise LauncherError("GitLab JSON response is not an object")
    return payload


def validate_project(
    payload: dict[str, Any],
    *,
    project_id: str,
    provider_instance: str,
) -> dict[str, str]:
    if str(payload.get("id") or "") != project_id:
        raise LauncherError("GitLab returned another project ID")
    if type(payload.get("archived")) is not bool:
        raise LauncherError("GitLab project archived state is unavailable")
    if payload["archived"]:
        raise LauncherError("Archived GitLab projects cannot be scanned")

    web_url = str(payload.get("web_url") or "")
    parsed = urlsplit(web_url)
    if (
        parsed.scheme.casefold() != "https"
        or parsed.netloc.casefold() != provider_instance
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise LauncherError(
            "Target project URL is invalid or belongs to another provider instance"
        )

    project_path = str(payload.get("path_with_namespace") or "")
    parts = project_path.split("/")
    if (
        len(parts) < 2
        or any(
            not part
            or part in {".", ".."}
            or "\\" in part
            or any(character.isspace() for character in part)
            for part in parts
        )
    ):
        raise LauncherError("GitLab project path is invalid")

    return {
        "project_id": project_id,
        "project_path": project_path,
        "web_url": web_url,
        "default_branch": str(payload.get("default_branch") or ""),
    }


def validate_commit_response(
    payload: dict[str, Any],
    expected_commit: str,
) -> None:
    expected = validated_commit(expected_commit)
    returned = str(payload.get("id") or "").strip().casefold()
    if returned != expected:
        raise LauncherError("GitLab did not return the exact requested commit")


def download_archive(
    url: str,
    destination: Path,
    *,
    job_token: str = "",
    api_token: str | None = None,
    context: ssl.SSLContext | None,
    timeout: float,
) -> str:
    request = Request(
        url,
        headers=request_headers(
            job_token,
            api_token=api_token,
            accept=", ".join(sorted(ARCHIVE_CONTENT_TYPES)),
        ),
        method="GET",
    )
    digest = hashlib.sha256()
    total = 0
    created = False

    try:
        with open_response(request, context=context, timeout=timeout) as response:
            check_response(response, maximum_bytes=MAX_ARCHIVE_BYTES)
            if response_content_type(response) not in ARCHIVE_CONTENT_TYPES:
                raise LauncherError(
                    "GitLab archive has an unexpected content type"
                )

            with destination.open("xb") as output_file:
                created = True
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_ARCHIVE_BYTES:
                        raise LauncherError(
                            "GitLab source archive exceeded the download size limit"
                        )
                    digest.update(chunk)
                    output_file.write(chunk)
                output_file.flush()
                os.fsync(output_file.fileno())

        if total == 0:
            raise LauncherError("GitLab source archive was empty")
        return digest.hexdigest()

    except BaseException as error:
        if created:
            destination.unlink(missing_ok=True)
        if isinstance(error, HTTPError):
            status = error.code
            error.close()
            raise LauncherError(
                f"GitLab archive request failed with HTTP {status}"
            ) from error
        if isinstance(error, (URLError, TimeoutError, OSError)):
            raise LauncherError(
                f"GitLab archive request failed: {redact(str(error))}"
            ) from error
        raise


def safe_member_path(value: str) -> PurePosixPath:
    selected = str(value or "").rstrip("/")
    parts = selected.split("/")
    if (
        not selected
        or "\\" in selected
        or any(ord(character) < 32 or ord(character) == 127 for character in selected)
        or any(part in {"", ".", ".."} or ":" in part for part in parts)
    ):
        raise LauncherError("Source archive contains an unsafe path")

    path = PurePosixPath(selected)
    if path.is_absolute():
        raise LauncherError("Source archive contains an unsafe path")
    return path


def extract_archive(
    archive_path: Path,
    destination: Path,
) -> tuple[Path, int, int]:
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    total_bytes = 0
    file_count = 0
    seen: set[str] = set()
    top_level: str | None = None

    try:
        with tarfile.open(archive_path, mode="r|gz") as archive:
            for index, member in enumerate(archive, start=1):
                # Streaming mode avoids a complete getmembers() allocation.
                archive.members.clear()
                if index > MAX_ARCHIVE_MEMBERS:
                    raise LauncherError(
                        "Source archive exceeded the member-count limit"
                    )

                relative = safe_member_path(member.name)
                rendered = relative.as_posix()
                if rendered in seen:
                    raise LauncherError(
                        f"Source archive contains a duplicate path: {rendered}"
                    )
                seen.add(rendered)

                if top_level is None:
                    top_level = relative.parts[0]
                elif top_level != relative.parts[0]:
                    raise LauncherError(
                        "GitLab source archive must contain one top-level directory"
                    )

                if not member.isdir() and not member.isfile():
                    raise LauncherError(
                        "Source archive contains a link or special device"
                    )
                if getattr(member, "sparse", None) is not None:
                    raise LauncherError("Source archive contains a sparse file")

                target = destination.joinpath(*relative.parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                if len(relative.parts) < 2:
                    raise LauncherError(
                        "GitLab source archive must contain one top-level directory"
                    )
                if member.size < 0:
                    raise LauncherError("Source archive contains an invalid file size")

                total_bytes += member.size
                if total_bytes > MAX_EXTRACTED_BYTES:
                    raise LauncherError(
                        "Source archive exceeded the extracted size limit"
                    )
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                source = archive.extractfile(member)
                if source is None:
                    raise LauncherError("Source archive file could not be read")

                remaining = member.size
                with source, target.open("xb") as output_file:
                    while remaining:
                        chunk = source.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise LauncherError("Source archive file is truncated")
                        output_file.write(chunk)
                        remaining -= len(chunk)
                target.chmod(0o700 if member.mode & 0o111 else 0o600)
                file_count += 1

        children = list(destination.iterdir())
        if len(children) != 1 or not children[0].is_dir():
            raise LauncherError(
                "GitLab source archive must contain one top-level directory"
            )
        return children[0], file_count, total_bytes
    except BaseException as error:
        shutil.rmtree(destination, ignore_errors=True)
        if isinstance(error, (tarfile.TarError, OSError, EOFError)):
            raise LauncherError(
                f"Could not extract source archive: {redact(str(error))}"
            ) from error
        raise


def scanner_environment(temporary_root: Path) -> dict[str, str]:
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.upper().startswith(
            (
                "CI_",
                "GITLAB_",
                "GITHUB_",
                "GIT_",
                "PYTHON",
                "WINTERMUTE_GITLAB_",
            )
        )
    }
    for name, relative in (
        ("HOME", "home"),
        ("TMPDIR", "tmp"),
        ("XDG_CACHE_HOME", "cache"),
        ("XDG_CONFIG_HOME", "config"),
    ):
        path = temporary_root / relative
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        environment[name] = str(path)
    return environment


def stop_process_tree(process: subprocess.Popen) -> None:
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        process.kill()

    process.wait()


def run_scan(
    args: argparse.Namespace,
    source_root: Path,
    *,
    provider_instance: str,
    project_id: str,
    commit: str,
) -> int:
    if args.mode == "execute" and args.confirmation != EXECUTION_CONFIRMATION:
        raise LauncherError(
            f"Execute mode requires exact confirmation: {EXECUTION_CONFIRMATION}"
        )

    scan_receipt_root = Path(args.receipt_root).resolve()
    scan_receipt_root.mkdir(parents=True, exist_ok=True)
    temporary_root = Path(args.launcher_temporary_root)
    command = [
        sys.executable,
        "-I",
        "-m",
        "wintermute.scan.cli",
        "--registry",
        str(Path(args.registry).resolve()),
        "--expected-registry-sha256",
        args.expected_registry_sha256,
        "--scm-provider",
        "gitlab",
        "--scm-provider-instance",
        provider_instance,
        "--scm-repository-id",
        project_id,
        "--commit-sha",
        commit,
        "--source-root",
        str(source_root),
        "--bridge-executable",
        args.bridge_executable,
        "--expected-bridge-sha256",
        args.expected_bridge_sha256,
        "--mode",
        args.mode,
        "--receipt-root",
        str(scan_receipt_root),
    ]
    if args.mode == "execute":
        command.append("--confirm-execute")

    environment = scanner_environment(temporary_root)
    environment["WINTERMUTE_OUTPUT_DIR"] = str(scan_receipt_root)

    process = subprocess.Popen(
        command,
        cwd=temporary_root,
        env=environment,
        stdin=subprocess.DEVNULL,
        start_new_session=(os.name == "posix"),
    )
    try:
        code = process.wait(timeout=args.scan_timeout)
        return code if code >= 0 else 128 - code
    except subprocess.TimeoutExpired as error:
        raise LauncherError("Scanner exceeded the launcher timeout") from error
    finally:
        stop_process_tree(process)


def run(args: argparse.Namespace) -> int:
    launcher_id = "gitlab-launcher-" + uuid.uuid4().hex
    receipt_directory = (
        Path(args.receipt_root).expanduser().resolve() / launcher_id
    )
    receipt_directory.mkdir(parents=True, exist_ok=False)
    receipt_path = receipt_directory / "launcher-receipt.json"
    temporary_root: Path | None = None
    scan_exit_code = 2

    receipt: dict[str, Any] = {
        "schema_version": 1,
        "launcher_id": launcher_id,
        "status": "failed",
        "error": "",
        "mode": args.mode,
        "provider": "gitlab",
        "provider_instance": "",
        "project_id": "",
        "project_path": "",
        "commit_sha": "",
        "scan_contract_id": "",
        "registry_sha256": "",
        "bridge_sha256": "",
        "archive_sha256": "",
        "extracted_file_count": 0,
        "extracted_byte_count": 0,
        "scan_exit_code": 2,
        "workspace_deleted": True,
        "target_repository_modified": False,
        "scan_receipt_directory": "scan",
    }

    try:
        if args.mode not in {"dry-run", "execute"}:
            raise LauncherError("Launcher mode is invalid")
        if args.mode == "execute" and args.confirmation != EXECUTION_CONFIRMATION:
            raise LauncherError(
                f"Execute mode requires exact confirmation: {EXECUTION_CONFIRMATION}"
            )
        timeout = positive_timeout(args.timeout, "timeout")
        scan_timeout = positive_timeout(args.scan_timeout, "scan timeout")
        api_url = normalized_api_url(args.gitlab_api_url)
        configured_ci_api = os.getenv("CI_API_V4_URL", "").strip()
        if configured_ci_api and normalized_api_url(configured_ci_api) != api_url:
            raise LauncherError("GitLab API URL does not match the CI instance")

        provider_instance = urlsplit(api_url).netloc.casefold()
        project_id = validated_project_id(args.project_id)
        commit = validated_commit(args.commit_sha)
        registry_digest = validated_digest(
            args.expected_registry_sha256,
            "Expected registry checksum",
        )
        from wintermute.scan.security import resolve_bridge_checksum

        bridge_digest = resolve_bridge_checksum(
            args.expected_bridge_sha256
        )
        receipt.update({
            "provider_instance": provider_instance,
            "project_id": project_id,
            "commit_sha": commit,
            "registry_sha256": registry_digest,
            "bridge_sha256": bridge_digest,
        })

        registry_path = Path(args.registry).expanduser().resolve()
        registry = load_registry(
            registry_path,
            expected_sha256=registry_digest,
        )
        resolved = resolve_scan(
            registry,
            provider="gitlab",
            provider_instance=provider_instance,
            repository_id=project_id,
        )
        receipt["scan_contract_id"] = resolved.contract_id

        bridge = executable_path(
            getattr(args, "bridge_executable", "")
            or os.getenv("BLACKDUCK_BRIDGE_PATH", "")
            or "bridge"
        )
        validate_executable(bridge, bridge_digest)

        api_token = os.getenv("WINTERMUTE_GITLAB_READ_TOKEN", "")
        request_headers(api_token=api_token, accept="application/json")
        context = tls_context(
            insecure=args.insecure,
            ca_bundle=args.ca_bundle,
        )
        project_url = f"{api_url}/projects/{quote(project_id, safe='')}"
        project = validate_project(
            request_json(
                project_url,
                api_token=api_token,
                context=context,
                timeout=timeout,
            ),
            project_id=project_id,
            provider_instance=provider_instance,
        )
        receipt["project_path"] = project["project_path"]
        validate_commit_response(
            request_json(
                f"{project_url}/repository/commits/{commit}",
                api_token=api_token,
                context=context,
                timeout=timeout,
            ),
            commit,
        )

        temporary_root = Path(
            tempfile.mkdtemp(prefix="wintermute-launcher-")
        )
        archive_path = temporary_root / "source.tar.gz"
        receipt["archive_sha256"] = download_archive(
            f"{project_url}/repository/archive.tar.gz?"
            + urlencode({"sha": commit}),
            archive_path,
            api_token=api_token,
            context=context,
            timeout=timeout,
        )
        source_root, files, size = extract_archive(
            archive_path,
            temporary_root / "workspace",
        )
        receipt["extracted_file_count"] = files
        receipt["extracted_byte_count"] = size

        scan_args = argparse.Namespace(**vars(args))
        scan_args.registry = str(registry_path)
        scan_args.expected_registry_sha256 = registry_digest
        scan_args.expected_bridge_sha256 = bridge_digest
        scan_args.bridge_executable = str(bridge)
        scan_args.scan_timeout = scan_timeout
        scan_args.receipt_root = str(receipt_directory / "scan")
        scan_args.launcher_temporary_root = str(temporary_root)

        scan_exit_code = run_scan(
            scan_args,
            source_root,
            provider_instance=provider_instance,
            project_id=project_id,
            commit=commit,
        )
        receipt["status"] = (
            "succeeded" if scan_exit_code == 0 else "scan-failed"
        )
    except KeyboardInterrupt:
        scan_exit_code = 130
        receipt["status"] = "interrupted"
        receipt["error"] = "Launcher interrupted"
    except Exception as error:
        scan_exit_code = 2
        receipt["error"] = redact(str(error))
    finally:
        if temporary_root is not None:
            try:
                shutil.rmtree(temporary_root)
            except FileNotFoundError:
                pass
            except OSError as error:
                receipt["error"] = redact(
                    f"{receipt['error']} Workspace cleanup failed: {error}"
                ).strip()

            receipt["workspace_deleted"] = not temporary_root.exists()
            if not receipt["workspace_deleted"]:
                receipt["status"] = "cleanup-failed"
                if scan_exit_code == 0:
                    scan_exit_code = 2

    receipt["scan_exit_code"] = scan_exit_code
    atomic_write_json(receipt_path, receipt)
    atomic_write_json(
        receipt_directory / "checksums.json",
        {
            "schema_version": 1,
            "sha256": {
                receipt_path.name: hashlib.sha256(
                    receipt_path.read_bytes()
                ).hexdigest(),
            },
        },
    )
    print(json.dumps(
        {**receipt, "receipt_path": str(receipt_path)},
        indent=2,
        sort_keys=True,
    ))
    return scan_exit_code


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch and scan one exact approved GitLab project commit "
            "from a central launcher."
        )
    )
    parser.add_argument("--gitlab-api-url", required=True)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--registry", required=True)
    parser.add_argument("--expected-registry-sha256", required=True)
    parser.add_argument("--expected-bridge-sha256", required=True)
    parser.add_argument(
        "--bridge-executable",
        default=os.getenv("BLACKDUCK_BRIDGE_PATH", "").strip() or "bridge",
    )
    parser.add_argument(
        "--mode",
        choices=("dry-run", "execute"),
        default="dry-run",
    )
    parser.add_argument("--confirmation", default="")
    parser.add_argument(
        "--receipt-root",
        default=str(output_root() / "scan" / "receipts"),
    )
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--scan-timeout", type=float, default=5400)
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument("--insecure", action="store_true")
    tls.add_argument("--ca-bundle")
    args = parser.parse_args(argv)

    try:
        positive_timeout(args.timeout, "timeout")
        positive_timeout(args.scan_timeout, "scan timeout")
    except LauncherError as error:
        parser.error(str(error))

    if args.mode == "execute" and args.confirmation != EXECUTION_CONFIRMATION:
        parser.error(
            f"Execute mode requires exact confirmation: {EXECUTION_CONFIRMATION}"
        )
    return args


def main(argv: list[str] | None = None) -> int:
    try:
        return run(parse_args(argv))
    except KeyboardInterrupt:
        return 130
    except (OSError, RuntimeError, ValueError) as error:
        print(f"ERROR: {redact(str(error))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
