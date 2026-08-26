from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any

from wintermute.scm.coverage.models import (
    BlackDuckInventoryObservation,
    BlackDuckProjectObservation,
    BlackDuckVersionObservation,
)


SCAN_EVIDENCE_SCHEMA_VERSION = 1


def parse_timestamp(
    value: str,
    field: str,
) -> str:
    selected = str(value or "").strip()

    if not selected:
        return ""

    normalized = (
        selected[:-1] + "+00:00"
        if selected.endswith("Z")
        else selected
    )

    try:
        parsed = datetime.fromisoformat(
            normalized
        )
    except ValueError as error:
        raise ValueError(
            f"{field} must be an ISO-8601 timestamp"
        ) from error

    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
    ):
        raise ValueError(
            f"{field} must include a timezone"
        )

    return selected


def optional_boolean(
    value: Any,
    field: str,
) -> bool | None:
    if value is None:
        return None

    if type(value) is not bool:
        raise ValueError(
            f"{field} must be boolean or null"
        )

    return value


def optional_count(
    value: Any,
    field: str,
) -> int | None:
    if value is None:
        return None

    if (
        type(value) is not int
        or value < 0
    ):
        raise ValueError(
            f"{field} must be a nonnegative "
            "integer or null"
        )

    return value


def load_scan_evidence(
    path: str | Path,
) -> dict[str, Any]:
    source = Path(path)

    try:
        payload = json.loads(
            source.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        raise ValueError(
            f"Failed reading scan evidence "
            f"{source}: {error}"
        ) from error

    if not isinstance(payload, dict):
        raise ValueError(
            "Scan evidence must be an object"
        )

    if (
        payload.get("schema_version")
        != SCAN_EVIDENCE_SCHEMA_VERSION
    ):
        raise ValueError(
            "Unsupported scan evidence schema version"
        )

    if type(payload.get("complete")) is not bool:
        raise ValueError(
            "Scan evidence complete must be boolean"
        )

    observations = payload.get(
        "observations"
    )

    if (
        not isinstance(observations, list)
        or not all(
            isinstance(value, dict)
            for value in observations
        )
    ):
        raise ValueError(
            "Scan evidence observations must be "
            "a list of objects"
        )

    return payload


def validated_observations(
    payload: dict[str, Any],
) -> dict[
    tuple[str, str],
    dict[str, Any],
]:
    result: dict[
        tuple[str, str],
        dict[str, Any],
    ] = {}

    for index, raw in enumerate(
        payload["observations"]
    ):
        project_id = str(
            raw.get("project_id") or ""
        ).strip()
        version_id = str(
            raw.get("version_id") or ""
        ).strip()

        if not project_id or not version_id:
            raise ValueError(
                f"Scan evidence observation {index} "
                "requires project_id and version_id"
            )

        key = (
            project_id,
            version_id,
        )

        if key in result:
            raise ValueError(
                "Scan evidence contains duplicate "
                f"project/version identity: {key!r}"
            )

        evidence_complete = raw.get(
            "evidence_complete",
            payload["complete"],
        )

        if type(evidence_complete) is not bool:
            raise ValueError(
                "evidence_complete must be boolean"
            )

        result[key] = {
            "bom_exists": optional_boolean(
                raw.get("bom_exists"),
                "bom_exists",
            ),
            "code_location_count": optional_count(
                raw.get(
                    "code_location_count"
                ),
                "code_location_count",
            ),
            "last_successful_scan_at": (
                parse_timestamp(
                    raw.get(
                        "last_successful_scan_at",
                        "",
                    ),
                    "last_successful_scan_at",
                )
            ),
            "scan_source": str(
                raw.get("scan_source") or ""
            ).strip(),
            "scanner_type": str(
                raw.get("scanner_type") or ""
            ).strip(),
            "receipt_id": str(
                raw.get("receipt_id") or ""
            ).strip(),
            "scan_evidence_complete": (
                evidence_complete
            ),
        }

    return result


def apply_scan_evidence(
    inventory: BlackDuckInventoryObservation,
    payload: dict[str, Any],
) -> BlackDuckInventoryObservation:
    observations = validated_observations(
        payload
    )
    known = {
        (
            project.project_id,
            version.version_id,
        )
        for project in inventory.projects
        for version in project.versions
    }
    supplied = set(observations)
    unknown = supplied - known

    if unknown:
        raise ValueError(
            "Scan evidence references unknown "
            "Black Duck project/version identities: "
            + ", ".join(
                f"{project_id}/{version_id}"
                for project_id, version_id
                in sorted(unknown)
            )
        )

    if payload["complete"]:
        missing = known - supplied

        if missing:
            raise ValueError(
                "Complete scan evidence omitted "
                "Black Duck project/version identities: "
                + ", ".join(
                    f"{project_id}/{version_id}"
                    for project_id, version_id
                    in sorted(missing)
                )
            )

    projects: list[
        BlackDuckProjectObservation
    ] = []

    for project in inventory.projects:
        versions: list[
            BlackDuckVersionObservation
        ] = []

        for version in project.versions:
            values = observations.get(
                (
                    project.project_id,
                    version.version_id,
                )
            )

            if values is None:
                versions.append(version)
            else:
                versions.append(
                    replace(
                        version,
                        **values,
                    )
                )

        projects.append(
            replace(
                project,
                versions=tuple(versions),
            )
        )

    return BlackDuckInventoryObservation(
        projects=tuple(projects),
        failures=inventory.failures,
    )
