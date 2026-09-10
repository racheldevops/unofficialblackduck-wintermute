from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from wintermute.scan.contracts import (
    ResolvedScan,
)


PRODUCT_STAGES = {
    "blackduck-sca": "blackducksca",
    "coverity": "coverity",
    "polaris": "polaris",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as input_file:
        for chunk in iter(
            lambda: input_file.read(
                1024 * 1024
            ),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def executable_path(value: str) -> Path:
    selected = str(value or "").strip()

    if not selected:
        raise ValueError(
            "Bridge executable is required"
        )

    resolved = shutil.which(selected)

    if resolved:
        return Path(resolved).resolve()

    path = Path(selected).expanduser()

    if not path.is_file():
        raise ValueError(
            f"Bridge executable does not exist: "
            f"{path}"
        )

    return path.resolve()


def validate_executable(
    path: Path,
    expected_sha256: str,
) -> None:
    from wintermute.scan.security import resolve_bridge_checksum

    expected = resolve_bridge_checksum(expected_sha256)
    if sha256_file(path) != expected:
        raise ValueError("Bridge executable checksum mismatch")



def scan_environment(
    resolved: ResolvedScan,
    commit_sha: str,
    environment: dict[str, str],
) -> dict[str, str]:
    selected = dict(environment)
    parameters = resolved.contract[
        "runtime_parameters"
    ]
    project_name = (
        f"{resolved.provider}-"
        f"{resolved.provider_instance}-"
        f"{resolved.repository_id}"
    )
    version_name = (
        str(commit_sha or "").strip()
        or "unknown"
    )

    selected[
        "WINTERMUTE_SCAN_CONTRACT_ID"
    ] = resolved.contract_id
    selected[
        "WINTERMUTE_SCM_PROVIDER"
    ] = resolved.provider
    selected[
        "WINTERMUTE_SCM_PROVIDER_INSTANCE"
    ] = resolved.provider_instance
    selected[
        "WINTERMUTE_SCM_REPOSITORY_ID"
    ] = resolved.repository_id
    selected[
        "WINTERMUTE_SCM_COMMIT_SHA"
    ] = version_name

    if "blackduck-sca" in (
        resolved.contract["products"]
    ):
        blackduck_url = selected.get(
            "BLACKDUCK_URL",
            "",
        )
        blackduck_token = selected.get(
            "BLACKDUCK_API_TOKEN",
            "",
        )

        if not blackduck_url:
            raise ValueError(
                "BLACKDUCK_URL must be set"
            )

        if not blackduck_token:
            raise ValueError(
                "BLACKDUCK_API_TOKEN must be set"
            )

        selected["BLACKDUCKSCA_URL"] = (
            blackduck_url
        )
        selected["BLACKDUCKSCA_TOKEN"] = (
            blackduck_token
        )
        selected[
            "BLACKDUCKSCA_PROJECT_NAME"
        ] = project_name
        selected[
            "BLACKDUCKSCA_PROJECT_VERSION"
        ] = version_name
        selected[
            "BLACKDUCKSCA_SCAN_FULL"
        ] = "true"
        selected[
            "BLACKDUCKSCA_WAITFORSCAN"
        ] = "true"

    selected[
        "DETECT_DETECTOR_SEARCH_DEPTH"
    ] = str(
        parameters.get(
            "detector_search_depth",
            3,
        )
    )
    selected[
        "WINTERMUTE_SCAN_BUILDLESS"
    ] = (
        "true"
        if parameters.get(
            "buildless",
            False,
        )
        else "false"
    )
    selected[
        "WINTERMUTE_SCAN_BINARY"
    ] = (
        "true"
        if parameters.get(
            "binary_scan",
            False,
        )
        else "false"
    )

    return selected


def planned_commands(
    bridge: Path,
    resolved: ResolvedScan,
) -> list[list[str]]:
    commands: list[list[str]] = []

    for product in resolved.contract[
        "products"
    ]:
        stage = PRODUCT_STAGES.get(product)

        if not stage:
            raise ValueError(
                f"No Bridge stage exists for "
                f"{product}"
            )

        commands.append(
            [
                str(bridge),
                "--stage",
                stage,
            ]
        )

    return commands


def run_scan(
    resolved: ResolvedScan,
    *,
    source_root: Path,
    commit_sha: str,
    bridge_executable: str,
    bridge_sha256: str,
    execute: bool,
    confirm_execute: bool,
) -> dict[str, Any]:
    import re

    from wintermute.scan.contracts import validate_contract
    from wintermute.scan.security import redact_text

    if type(execute) is not bool or type(confirm_execute) is not bool:
        raise ValueError("Execution and confirmation flags must be boolean")

    if execute and not confirm_execute:
        raise ValueError("Scan execution requires confirmation")

    commit = str(commit_sha or "").strip().casefold()
    if execute and re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", commit) is None:
        raise ValueError("Scan execution requires a full commit SHA")

    contract = validate_contract(resolved.contract)
    selected = ResolvedScan(
        contract_id=resolved.contract_id,
        provider=resolved.provider,
        provider_instance=resolved.provider_instance,
        repository_id=resolved.repository_id,
        contract=contract,
    )
    source = source_root.expanduser().resolve()
    if not source.is_dir():
        raise ValueError(f"Source directory does not exist: {source}")

    bridge = executable_path(bridge_executable)
    validate_executable(bridge, bridge_sha256)
    commands = planned_commands(bridge, selected)

    if not execute:
        return {
            "mode": "dry-run",
            "contract_id": selected.contract_id,
            "engine": contract["engine"],
            "products": list(contract["products"]),
            "commands": commands,
            "writes": 0,
            "remote_writes": 0,
            "writes_measurement": "scanner-stages-started",
            "stages_started": 0,
            "results": [],
            "scanner_executed": False,
        }

    environment = scan_environment(
        selected,
        commit,
        dict(os.environ),
    )
    started = time.monotonic()
    deadline = started + contract["timeout_seconds"]
    results: list[dict[str, Any]] = []
    stages_started = 0

    def finish(status: str, outcome: str) -> dict[str, Any]:
        return {
            "mode": "execute",
            "contract_id": selected.contract_id,
            "engine": contract["engine"],
            "products": list(contract["products"]),
            "commands": commands,
            # Compatibility field: this is not a count of Black Duck API writes.
            "writes": stages_started,
            "remote_writes": None if stages_started else 0,
            "writes_measurement": "scanner-stages-started",
            "stages_started": stages_started,
            "scanner_executed": stages_started > 0,
            "results": results,
            "status": status,
            "outcome": outcome,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }

    for product, command in zip(contract["products"], commands, strict=True):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            results.append({
                "product": product,
                "stage": PRODUCT_STAGES[product],
                "return_code": None,
                "status": "not-started",
                "error": "Contract runtime budget exhausted",
            })
            return finish("failed", "timeout")

        try:
            completed = subprocess.run(
                command,
                cwd=source,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=None,
                stderr=None,
                timeout=remaining,
                check=False,
            )
            stages_started += 1
        except subprocess.TimeoutExpired:
            stages_started += 1
            results.append({
                "product": product,
                "stage": PRODUCT_STAGES[product],
                "return_code": None,
                "status": "timed-out",
                "error": "Scanner exceeded the remaining contract runtime budget",
            })
            return finish("failed", "timeout")
        except OSError as error:
            results.append({
                "product": product,
                "stage": PRODUCT_STAGES[product],
                "return_code": None,
                "status": "start-failed",
                "error": redact_text(str(error)),
            })
            return finish("failed", "start-failed")

        results.append({
            "product": product,
            "stage": PRODUCT_STAGES[product],
            "return_code": completed.returncode,
            "status": "succeeded" if completed.returncode == 0 else "failed",
        })
        if completed.returncode != 0:
            return finish("failed", "scanner-failed")

        if time.monotonic() > deadline:
            return finish("failed", "timeout")

    return finish("succeeded", "completed")

