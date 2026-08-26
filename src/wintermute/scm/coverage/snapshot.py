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

from wintermute.scm.controls import (
    control_inventory_payload,
)
from wintermute.scm.coverage.mapping import (
    mapping_result_payload,
)
from wintermute.scm.coverage.models import (
    CoverageClassification,
    blackduck_project_payload,
)
from wintermute.scm.coverage.pipeline import (
    CoverageExecution,
)
from wintermute.scm.coverage.reporting import (
    coverage_report_payload,
)
from wintermute.scm.evidence import (
    evidence_inventory_payload,
)
from wintermute.scm.inventory import (
    inventory_payload,
)


COVERAGE_SNAPSHOT_SCHEMA_VERSION = 1
SNAPSHOT_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
)
ARTIFACT_NAMES = (
    "metadata.json",
    "repositories.json",
    "provider-evidence.json",
    "onboarding-controls.json",
    "blackduck-projects.json",
    "mappings.json",
    "coverage-report.json",
    "scan-gaps.json",
    "failures.json",
)


class CoverageSnapshotError(RuntimeError):
    pass


@dataclass(frozen=True)
class LoadedCoverageSnapshot:
    snapshot_id: str
    directory: Path
    metadata: dict[str, Any]
    coverage_report: dict[str, Any]
    scan_gaps: dict[str, Any]


def now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def create_coverage_snapshot_id() -> str:
    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")

    return (
        f"{timestamp}-{uuid.uuid4().hex[:8]}"
    )


def validate_snapshot_id(
    snapshot_id: str,
) -> str:
    selected = str(
        snapshot_id or ""
    ).strip()

    if (
        not SNAPSHOT_ID_PATTERN.fullmatch(
            selected
        )
        or selected in {".", ".."}
    ):
        raise CoverageSnapshotError(
            f"Invalid coverage snapshot ID: "
            f"{selected!r}"
        )

    return selected


def atomic_write_json(
    path: Path,
    payload: Any,
) -> None:
    temporary = path.with_name(
        f"{path.name}.tmp"
    )
    temporary.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            default=str,
        )
        + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def sha256_file(
    path: Path,
) -> str:
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


def read_json(
    path: Path,
) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        raise CoverageSnapshotError(
            f"Failed reading coverage artifact "
            f"{path}: {error}"
        ) from error

    if not isinstance(value, dict):
        raise CoverageSnapshotError(
            f"Coverage artifact is not an object: "
            f"{path}"
        )

    return value


def scan_gap_payload(
    execution: CoverageExecution,
) -> dict[str, Any]:
    gap_classifications = {
        CoverageClassification
        .MAPPED_NEVER_SCANNED,
        CoverageClassification
        .SCANNED_STALE,
    }
    gaps = [
        {
            "repository_external_id": (
                value.repository.external_id
            ),
            "name_with_owner": (
                value.repository.name_with_owner
            ),
            "classification": (
                value.classification.value
            ),
            "blackduck_project_id": (
                value.blackduck_project.project_id
                if value.blackduck_project
                is not None
                else ""
            ),
            "last_successful_scan_at": (
                value.last_successful_scan_at
            ),
            "freshness_sla_days": (
                value.freshness_sla_days
            ),
            "approval_state": "unreviewed",
            "reasons": list(value.reasons),
        }
        for value
        in execution.report.repositories
        if (
            value.eligible
            and value.classification
            in gap_classifications
        )
    ]

    return {
        "schema_version": (
            COVERAGE_SNAPSHOT_SCHEMA_VERSION
        ),
        "gap_count": len(gaps),
        "gaps": gaps,
    }


def failure_payload(
    execution: CoverageExecution,
) -> dict[str, Any]:
    source = execution.source_snapshot

    return {
        "schema_version": (
            COVERAGE_SNAPSHOT_SCHEMA_VERSION
        ),
        "scm_inventory_failures": [
            {
                "provider": value.provider,
                "provider_instance": (
                    value.provider_instance
                ),
                "tenant_id": value.tenant_id,
                "repository_id": (
                    value.repository_id
                ),
                "name_with_owner": (
                    value.name_with_owner
                ),
                "stage": value.stage,
                "error": value.error,
            }
            for value
            in source.inventory.failures
        ],
        "scm_evidence_failures": [
            {
                "provider": value.provider,
                "provider_instance": (
                    value.provider_instance
                ),
                "tenant_id": value.tenant_id,
                "repository_external_id": (
                    value.repository_external_id
                ),
                "name_with_owner": (
                    value.name_with_owner
                ),
                "stage": value.stage,
                "error": value.error,
            }
            for value
            in source.evidence.failures
        ],
        "scm_control_failures": [
            {
                "provider": value.provider,
                "provider_instance": (
                    value.provider_instance
                ),
                "tenant_id": value.tenant_id,
                "stage": value.stage,
                "error": value.error,
            }
            for value
            in source.controls.failures
        ],
        "blackduck_failures": [
            {
                "project": value.project,
                "project_href": (
                    value.project_href
                ),
                "stage": value.stage,
                "error": value.error,
            }
            for value
            in execution.blackduck.failures
        ],
    }


def write_coverage_snapshot(
    root: str | Path,
    execution: CoverageExecution,
    *,
    snapshot_id: str | None = None,
) -> Path:
    selected_id = validate_snapshot_id(
        snapshot_id
        or create_coverage_snapshot_id()
    )
    root_path = Path(root)
    staging = (
        root_path
        / ".staging"
        / selected_id
    )
    final = root_path / selected_id

    if final.exists():
        raise CoverageSnapshotError(
            f"Coverage snapshot already exists: "
            f"{final}"
        )

    if staging.exists():
        shutil.rmtree(staging)

    staging.mkdir(
        parents=True,
        exist_ok=False,
    )

    try:
        report = coverage_report_payload(
            execution.report
        )
        mappings = mapping_result_payload(
            execution.mappings
        )
        blackduck = {
            "schema_version": (
                COVERAGE_SNAPSHOT_SCHEMA_VERSION
            ),
            "project_count": len(
                execution.blackduck.projects
            ),
            "failure_count": len(
                execution.blackduck.failures
            ),
            "projects": [
                blackduck_project_payload(
                    value
                )
                for value
                in execution.blackduck.projects
            ],
        }
        gaps = scan_gap_payload(
            execution
        )
        failures = failure_payload(
            execution
        )
        failure_count = (
            execution.report
            .provider_failure_count
            + execution.report
            .blackduck_failure_count
        )
        metadata = {
            "schema_version": (
                COVERAGE_SNAPSHOT_SCHEMA_VERSION
            ),
            "snapshot_id": selected_id,
            "created_at": now_iso(),
            "source_inventory_snapshot_id": (
                execution.source_snapshot
                .snapshot_id
            ),
            "source_inventory_snapshot": str(
                execution.source_snapshot
                .directory
            ),
            "repository_count": (
                execution.report
                .repository_count
            ),
            "eligible_repository_count": (
                execution.report
                .eligible_repository_count
            ),
            "blackduck_project_count": (
                len(
                    execution.blackduck.projects
                )
            ),
            "mapping_count": len(
                execution.mappings.mappings
            ),
            "authoritative_mapping_count": (
                execution.mappings
                .authoritative_count
            ),
            "scan_gap_count": (
                gaps["gap_count"]
            ),
            "failure_count": (
                failure_count
            ),
            "status": (
                "partial"
                if failure_count
                else "succeeded"
            ),
        }
        payloads = {
            "metadata.json": metadata,
            "repositories.json": (
                inventory_payload(
                    execution
                    .source_snapshot
                    .inventory
                )
            ),
            "provider-evidence.json": (
                evidence_inventory_payload(
                    execution
                    .source_snapshot
                    .evidence
                )
            ),
            "onboarding-controls.json": (
                control_inventory_payload(
                    execution
                    .source_snapshot
                    .controls
                )
            ),
            "blackduck-projects.json": (
                blackduck
            ),
            "mappings.json": mappings,
            "coverage-report.json": (
                report
            ),
            "scan-gaps.json": gaps,
            "failures.json": failures,
        }

        for name, payload in payloads.items():
            atomic_write_json(
                staging / name,
                payload,
            )

        checksums = {
            name: sha256_file(
                staging / name
            )
            for name in ARTIFACT_NAMES
        }
        atomic_write_json(
            staging / "checksums.json",
            {
                "schema_version": (
                    COVERAGE_SNAPSHOT_SCHEMA_VERSION
                ),
                "sha256": checksums,
            },
        )

        root_path.mkdir(
            parents=True,
            exist_ok=True,
        )
        os.replace(staging, final)
        atomic_write_json(
            final / "READY",
            {
                "schema_version": (
                    COVERAGE_SNAPSHOT_SCHEMA_VERSION
                ),
                "snapshot_id": selected_id,
                "ready_at": now_iso(),
            },
        )

        return final

    except BaseException:
        if staging.exists():
            shutil.rmtree(
                staging,
                ignore_errors=True,
            )

        raise


def load_coverage_snapshot(
    directory: str | Path,
) -> LoadedCoverageSnapshot:
    root = Path(directory)

    if not root.is_dir():
        raise CoverageSnapshotError(
            f"Coverage snapshot does not exist: "
            f"{root}"
        )

    ready = read_json(root / "READY")
    metadata = read_json(
        root / "metadata.json"
    )
    snapshot_id = validate_snapshot_id(
        metadata.get("snapshot_id", "")
    )

    if ready.get("snapshot_id") != snapshot_id:
        raise CoverageSnapshotError(
            "Coverage READY marker does not "
            "match metadata"
        )

    checksums = read_json(
        root / "checksums.json"
    ).get("sha256")

    if not isinstance(checksums, dict):
        raise CoverageSnapshotError(
            "Coverage checksums are invalid"
        )

    for name in ARTIFACT_NAMES:
        expected = str(
            checksums.get(name) or ""
        )

        if not expected:
            raise CoverageSnapshotError(
                f"Missing checksum for {name}"
            )

        if sha256_file(root / name) != expected:
            raise CoverageSnapshotError(
                f"Checksum mismatch for {name}"
            )

    report = read_json(
        root / "coverage-report.json"
    )
    gaps = read_json(
        root / "scan-gaps.json"
    )

    if (
        metadata.get("repository_count")
        != report.get("repository_count")
    ):
        raise CoverageSnapshotError(
            "Coverage repository count mismatch"
        )

    if (
        metadata.get("scan_gap_count")
        != gaps.get("gap_count")
    ):
        raise CoverageSnapshotError(
            "Coverage scan-gap count mismatch"
        )

    return LoadedCoverageSnapshot(
        snapshot_id=snapshot_id,
        directory=root,
        metadata=metadata,
        coverage_report=report,
        scan_gaps=gaps,
    )


def mark_coverage_complete(
    directory: str | Path,
) -> Path:
    snapshot = load_coverage_snapshot(
        directory
    )
    path = snapshot.directory / "COMPLETE"
    atomic_write_json(
        path,
        {
            "schema_version": (
                COVERAGE_SNAPSHOT_SCHEMA_VERSION
            ),
            "snapshot_id": (
                snapshot.snapshot_id
            ),
            "completed_at": now_iso(),
        },
    )

    return path



def prune_coverage_snapshots(
    root: str | Path,
    *,
    retain_count: int,
    protected_ids: set[str] | None = None,
    require_complete: bool = True,
) -> tuple[str, ...]:
    if retain_count < 1:
        raise CoverageSnapshotError(
            "retain_count must be greater than zero"
        )

    root_path = Path(root)

    if not root_path.is_dir():
        return ()

    protected = {
        validate_snapshot_id(value)
        for value in (
            protected_ids or set()
        )
    }
    snapshots: list[
        tuple[str, str, Path]
    ] = []

    for directory in root_path.iterdir():
        if (
            not directory.is_dir()
            or directory.name == ".staging"
            or not (
                directory / "READY"
            ).is_file()
            or not (
                directory / "metadata.json"
            ).is_file()
        ):
            continue

        if (
            require_complete
            and not (
                directory / "COMPLETE"
            ).is_file()
        ):
            continue

        try:
            metadata = read_json(
                directory / "metadata.json"
            )
            snapshot_id = (
                validate_snapshot_id(
                    str(
                        metadata.get(
                            "snapshot_id"
                        )
                        or directory.name
                    )
                )
            )
        except CoverageSnapshotError:
            continue

        snapshots.append(
            (
                str(
                    metadata.get(
                        "created_at"
                    )
                    or ""
                ),
                snapshot_id,
                directory,
            )
        )

    snapshots.sort(
        key=lambda value: (
            value[0],
            value[1],
        ),
        reverse=True,
    )
    retained = {
        snapshot_id
        for _, snapshot_id, _
        in snapshots[:retain_count]
    }
    retained.update(protected)
    removed: list[str] = []

    for _, snapshot_id, directory in snapshots:
        if snapshot_id in retained:
            continue

        shutil.rmtree(directory)
        removed.append(snapshot_id)

    return tuple(sorted(removed))
