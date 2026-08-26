from __future__ import annotations

import threading
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any

from wintermute.blackduck.request_control import (
    BlackDuckCircuitOpenError,
    blackduck_request_context,
)
from wintermute.blackduck.resources import (
    get_link,
    get_self_href,
)
from wintermute.concurrency import (
    MAX_IO_WORKERS,
    bounded_worker_count,
    ordered_parallel_map,
)
from wintermute.scm.coverage.models import (
    BlackDuckInventoryObservation,
    BlackDuckObservationFailure,
    BlackDuckProjectObservation,
    BlackDuckVersionObservation,
)


SUCCESS_STATUSES = {
    "COMPLETE",
    "COMPLETED",
    "SUCCESS",
    "SUCCEEDED",
}
FAILURE_STATUSES = {
    "ERROR",
    "FAILED",
    "FAILURE",
}
TERMINAL_STATUSES = (
    SUCCESS_STATUSES
    | FAILURE_STATUSES
)
CODE_LOCATION_LINKS = (
    "code-locations",
    "codeLocations",
    "codelocations",
)
SCAN_SUMMARY_LINKS = (
    "scan-summaries",
    "scanSummaries",
    "scan-summary",
)
BOM_STATUS_LINKS = (
    "bom-status",
    "bomStatus",
)


@dataclass(frozen=True)
class ScanRecord:
    status: str
    completed_at: str
    identity: str
    scanner_type: str


@dataclass(frozen=True)
class VersionEvidenceResult:
    project_id: str
    version_id: str
    version: BlackDuckVersionObservation
    failures: tuple[
        BlackDuckObservationFailure,
        ...
    ]


def direct_value(
    value: dict[str, Any],
    *names: str,
) -> Any:
    wanted = {
        name.casefold()
        for name in names
    }

    for key, item in value.items():
        if (
            str(key).casefold()
            in wanted
            and item not in (None, "")
        ):
            return item

    return None


def parse_timestamp(
    value: Any,
) -> tuple[datetime, str] | None:
    selected = str(
        value or ""
    ).strip()

    if not selected:
        return None

    normalized = (
        selected[:-1] + "+00:00"
        if selected.endswith("Z")
        else selected
    )

    try:
        parsed = datetime.fromisoformat(
            normalized
        )
    except ValueError:
        return None

    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
    ):
        return None

    return (
        parsed.astimezone(timezone.utc),
        selected,
    )


def scan_records(
    value: Any,
) -> list[ScanRecord]:
    records: list[ScanRecord] = []

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            raw_status = direct_value(
                item,
                "status",
                "scanStatus",
                "scan_status",
                "state",
            )
            status = str(
                raw_status or ""
            ).strip().upper()

            if status:
                completed_at = str(
                    direct_value(
                        item,
                        "completedAt",
                        "completionTime",
                        "endTime",
                        "finishedAt",
                        "scanCompletedAt",
                        "updatedAt",
                        "updated",
                    )
                    or ""
                ).strip()
                identity = str(
                    get_self_href(item)
                    or direct_value(
                        item,
                        "id",
                        "scanId",
                        "scan_id",
                    )
                    or ""
                ).strip()
                scanner_type = str(
                    direct_value(
                        item,
                        "scannerType",
                        "scanType",
                        "scanMode",
                        "toolName",
                    )
                    or ""
                ).strip()

                records.append(
                    ScanRecord(
                        status=status,
                        completed_at=(
                            completed_at
                        ),
                        identity=identity,
                        scanner_type=(
                            scanner_type
                        ),
                    )
                )

            for nested in item.values():
                walk(nested)

        elif isinstance(item, list):
            for nested in item:
                walk(nested)

    walk(value)

    unique: dict[
        tuple[str, str, str, str],
        ScanRecord,
    ] = {}

    for record in records:
        unique.setdefault(
            (
                record.status,
                record.completed_at,
                record.identity,
                record.scanner_type,
            ),
            record,
        )

    return list(unique.values())


def terminal_records_complete(
    records: list[ScanRecord],
) -> bool:
    return bool(records) and all(
        record.status
        in TERMINAL_STATUSES
        for record in records
    )


def bom_status_value(
    value: Any,
) -> bool | None:
    if value in (None, ""):
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, dict):
        selected = direct_value(
            value,
            "status",
            "bomStatus",
            "state",
        )

        if selected in (None, ""):
            return (
                True
                if value
                else None
            )

        value = selected

    status = str(
        value or ""
    ).strip().upper()

    if not status:
        return None

    if status in {
        "NONE",
        "NOT_AVAILABLE",
        "NOT_BUILT",
        "NOT_GENERATED",
    }:
        return False

    return True


def successful_evidence(
    records: list[ScanRecord],
) -> tuple[str, str, str]:
    successful = [
        record
        for record in records
        if record.status
        in SUCCESS_STATUSES
        and (
            record.completed_at
            or record.identity
        )
    ]

    if not successful:
        return "", "", ""

    timestamped = [
        (
            parsed,
            text,
            record,
        )
        for record in successful
        if (
            parsed_value := parse_timestamp(
                record.completed_at
            )
        )
        is not None
        for parsed, text
        in (parsed_value,)
    ]

    if timestamped:
        _, text, selected = max(
            timestamped,
            key=lambda value: value[0],
        )

        return (
            text,
            selected.identity,
            selected.scanner_type,
        )

    selected = min(
        successful,
        key=lambda record: (
            record.identity,
            record.scanner_type,
        ),
    )

    return (
        "",
        selected.identity,
        selected.scanner_type,
    )


def collect_version_evidence(
    client: Any,
    project: BlackDuckProjectObservation,
    version: BlackDuckVersionObservation,
) -> VersionEvidenceResult:
    failures: list[
        BlackDuckObservationFailure
    ] = []

    def failure(
        stage: str,
        error: Exception | str,
    ) -> None:
        failures.append(
            BlackDuckObservationFailure(
                project=(
                    f"{project.name} / "
                    f"{version.name}"
                ),
                project_href=project.href,
                stage=stage,
                error=str(error),
            )
        )

    try:
        version_resource = client.get(
            version.href
        )
    except BlackDuckCircuitOpenError:
        raise
    except Exception as error:
        failure(
            "load-project-version-scan-evidence",
            error,
        )

        return VersionEvidenceResult(
            project_id=project.project_id,
            version_id=version.version_id,
            version=replace(
                version,
                scan_evidence_complete=False,
            ),
            failures=tuple(failures),
        )

    bom_exists = bom_status_value(
        direct_value(
            version_resource,
            "bomStatus",
            "bom_status",
        )
    )
    bom_url = get_link(
        version_resource,
        BOM_STATUS_LINKS,
    )

    if bom_url:
        try:
            bom_payload = client.get(
                bom_url
            )
            linked_bom = bom_status_value(
                bom_payload
            )

            if linked_bom is not None:
                bom_exists = linked_bom
        except BlackDuckCircuitOpenError:
            raise
        except Exception as error:
            failure(
                "load-bom-status",
                error,
            )

    code_locations_url = get_link(
        version_resource,
        CODE_LOCATION_LINKS,
    )
    code_location_count: int | None = None
    evidence_complete = False
    records: list[ScanRecord] = []

    if code_locations_url:
        try:
            code_locations = (
                client.paged_get(
                    code_locations_url
                )
            )
            code_location_count = len(
                code_locations
            )
            location_completeness: list[
                bool
            ] = []

            for location in code_locations:
                location_records = (
                    scan_records(location)
                )
                summaries_url = get_link(
                    location,
                    SCAN_SUMMARY_LINKS,
                )

                if summaries_url:
                    try:
                        summaries = (
                            client.paged_get(
                                summaries_url
                            )
                        )
                        summary_records: list[
                            ScanRecord
                        ] = []

                        for summary in summaries:
                            summary_records.extend(
                                scan_records(
                                    summary
                                )
                            )

                        location_records.extend(
                            summary_records
                        )
                        location_complete = True
                    except BlackDuckCircuitOpenError:
                        raise
                    except Exception as error:
                        failure(
                            "load-scan-summaries",
                            error,
                        )
                        location_complete = False
                else:
                    location_complete = (
                        terminal_records_complete(
                            location_records
                        )
                    )

                records.extend(
                    location_records
                )
                location_completeness.append(
                    location_complete
                )

            evidence_complete = (
                not code_locations
                or all(location_completeness)
            )

        except BlackDuckCircuitOpenError:
            raise
        except Exception as error:
            failure(
                "load-code-locations",
                error,
            )
    else:
        raw_count = direct_value(
            version_resource,
            "codeLocationCount",
            "code_location_count",
        )

        if (
            type(raw_count) is int
            and raw_count >= 0
        ):
            code_location_count = raw_count
            evidence_complete = (
                raw_count == 0
            )

    (
        completed_at,
        receipt_id,
        scanner_type,
    ) = successful_evidence(records)

    return VersionEvidenceResult(
        project_id=project.project_id,
        version_id=version.version_id,
        version=replace(
            version,
            bom_exists=bom_exists,
            code_location_count=(
                code_location_count
            ),
            last_successful_scan_at=(
                completed_at
            ),
            scan_source=(
                "blackduck-api"
                if completed_at
                or receipt_id
                else ""
            ),
            scanner_type=scanner_type,
            receipt_id=receipt_id,
            scan_evidence_complete=(
                evidence_complete
            ),
        ),
        failures=tuple(failures),
    )


def collect_blackduck_scan_evidence(
    client: Any,
    inventory: BlackDuckInventoryObservation,
    *,
    workers: int = 4,
) -> BlackDuckInventoryObservation:
    targets = [
        (
            project,
            version,
        )
        for project in inventory.projects
        for version in project.versions
    ]

    if not targets:
        return inventory

    worker_count = min(
        bounded_worker_count(
            workers,
            maximum=MAX_IO_WORKERS,
        ),
        len(targets),
    )
    worker_local = threading.local()

    def worker_client() -> Any:
        if worker_count == 1:
            return client

        selected = getattr(
            worker_local,
            "blackduck_client",
            None,
        )

        if selected is None:
            clone = getattr(
                client,
                "clone_for_worker",
                None,
            )
            selected = (
                clone()
                if callable(clone)
                else client
            )
            worker_local.blackduck_client = (
                selected
            )

        return selected

    def collect(
        target: tuple[
            BlackDuckProjectObservation,
            BlackDuckVersionObservation,
        ],
    ) -> VersionEvidenceResult:
        project, version = target

        with blackduck_request_context(
            project=project.name,
            project_id=project.project_id,
            project_version=version.name,
            project_version_id=version.version_id,
            project_version_href=version.href,
            stage="scm-direct-scan-evidence",
        ):
            return collect_version_evidence(
                worker_client(),
                project,
                version,
            )

    results = ordered_parallel_map(
        targets,
        collect,
        workers=worker_count,
        maximum=MAX_IO_WORKERS,
    )
    results_by_identity = {
        (
            result.project_id,
            result.version_id,
        ): result
        for result in results
    }
    projects: list[
        BlackDuckProjectObservation
    ] = []
    failures = list(
        inventory.failures
    )

    for project in inventory.projects:
        versions: list[
            BlackDuckVersionObservation
        ] = []

        for version in project.versions:
            result = results_by_identity[
                (
                    project.project_id,
                    version.version_id,
                )
            ]
            versions.append(
                result.version
            )
            failures.extend(
                result.failures
            )

        projects.append(
            replace(
                project,
                versions=tuple(versions),
            )
        )

    return BlackDuckInventoryObservation(
        projects=tuple(projects),
        failures=tuple(failures),
    )
