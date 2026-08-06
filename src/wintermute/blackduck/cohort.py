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

from wintermute.blackduck.models import (
    LineageContext,
    NormalizedFinding,
    ProjectVersionRef,
)
from wintermute.blackduck.pull import PullExecution
from wintermute.blackduck.serialization import (
    collection_failure_payload,
    normalized_finding_payload,
    scope_failure_payload,
)


COHORT_SCHEMA_VERSION = 1
COHORT_ID_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
)
ARTIFACT_NAMES = (
    "metadata.json",
    "manifest.json",
    "normalized-findings.json",
    "collection-failures.json",
)


class CohortError(RuntimeError):
    pass


@dataclass(frozen=True)
class LoadedCohort:
    cohort_id: str
    directory: Path
    metadata: dict[str, Any]
    manifest: dict[str, Any]
    findings: tuple[NormalizedFinding, ...]
    scope_failures: tuple[dict[str, Any], ...]
    collection_failures: tuple[
        dict[str, Any],
        ...
    ]


def now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def create_cohort_id() -> str:
    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")

    return (
        f"{timestamp}-{uuid.uuid4().hex[:8]}"
    )


def validate_cohort_id(cohort_id: str) -> str:
    cohort_id = str(cohort_id or "").strip()

    if not COHORT_ID_RE.fullmatch(cohort_id):
        raise CohortError(
            f"Invalid cohort ID: {cohort_id!r}"
        )

    if cohort_id in {".", ".."}:
        raise CohortError(
            f"Invalid cohort ID: {cohort_id!r}"
        )

    return cohort_id


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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as input_file:
        for chunk in iter(
            lambda: input_file.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def project_version_from_payload(
    payload: dict[str, Any],
) -> ProjectVersionRef:
    return ProjectVersionRef(
        instance_url=str(
            payload.get("instance_url") or ""
        ),
        project=str(
            payload.get("project") or ""
        ),
        version=str(
            payload.get("version") or ""
        ),
        project_href=str(
            payload.get("project_href") or ""
        ),
        version_href=str(
            payload.get("version_href") or ""
        ),
        phase=str(
            payload.get("phase") or ""
        ),
        updated=str(
            payload.get("updated") or ""
        ),
    )


def lineage_from_payload(
    payload: dict[str, Any],
) -> LineageContext:
    return LineageContext(
        parent=project_version_from_payload(
            dict(payload.get("parent") or {})
        ),
        child=project_version_from_payload(
            dict(payload.get("child") or {})
        ),
        detection_method=str(
            payload.get("detection_method") or ""
        ),
        bom_component_name=str(
            payload.get("bom_component_name")
            or ""
        ),
        bom_component_version=str(
            payload.get("bom_component_version")
            or ""
        ),
    )


def finding_from_payload(
    payload: dict[str, Any],
) -> NormalizedFinding:
    return NormalizedFinding(
        project_version=(
            project_version_from_payload(
                dict(
                    payload.get(
                        "project_version"
                    )
                    or {}
                )
            )
        ),
        component=str(
            payload.get("component") or ""
        ),
        component_version=str(
            payload.get("component_version")
            or ""
        ),
        component_href=str(
            payload.get("component_href") or ""
        ),
        vulnerability=str(
            payload.get("vulnerability")
            or "UNKNOWN"
        ),
        vulnerability_href=str(
            payload.get("vulnerability_href")
            or ""
        ),
        severity=str(
            payload.get("severity") or ""
        ),
        score_field=str(
            payload.get("score_field")
            or "overallScore"
        ),
        score=payload.get("score"),
        cvss_vector=str(
            payload.get("cvss_vector") or ""
        ),
        exploit_available=bool(
            payload.get("exploit_available")
        ),
        exploitable=str(
            payload.get("exploitable") or ""
        ),
        reachable=bool(
            payload.get("reachable")
        ),
        reachability=str(
            payload.get("reachability") or ""
        ),
        reachability_source=str(
            payload.get("reachability_source")
            or ""
        ),
        policy_name=str(
            payload.get("policy_name") or ""
        ),
        policy_rule_href=str(
            payload.get("policy_rule_href")
            or ""
        ),
        entity=str(
            payload.get("entity") or ""
        ),
        lineage_contexts=tuple(
            lineage_from_payload(
                dict(context)
            )
            for context in (
                payload.get("lineage_contexts")
                or []
            )
            if isinstance(context, dict)
        ),
        attributes=dict(
            payload.get("attributes") or {}
        ),
    )


def criteria_payload(
    execution: PullExecution,
) -> dict[str, Any]:
    criteria = execution.request.criteria

    return {
        "score_field": criteria.score_field,
        "score_operator": (
            criteria.score_operator.value
        ),
        "threshold": criteria.threshold,
        "require_exploit_available": (
            criteria.require_exploit_available
        ),
        "require_reachable": (
            criteria.require_reachable
        ),
        "reachability_mode": (
            criteria.reachability_mode
        ),
        "policy_name": criteria.policy_name,
        "policy_rule_id": (
            criteria.policy_rule_id
        ),
        "skip_policy_rules": (
            criteria.skip_policy_rules
        ),
        "include_policy_rule_details": (
            criteria.include_policy_rule_details
        ),
        "entity_custom_field": (
            criteria.entity_custom_field
        ),
        "require_entity": (
            criteria.require_entity
        ),
    }


def write_cohort(
    root: str | Path,
    execution: PullExecution,
    *,
    cohort_id: str | None = None,
) -> Path:
    cohort_id = validate_cohort_id(
        cohort_id or create_cohort_id()
    )
    root_path = Path(root)
    staging_root = root_path / ".staging"
    staging_directory = (
        staging_root / cohort_id
    )
    final_directory = root_path / cohort_id

    if final_directory.exists():
        raise CohortError(
            f"Cohort already exists: "
            f"{final_directory}"
        )

    if staging_directory.exists():
        shutil.rmtree(staging_directory)

    staging_directory.mkdir(
        parents=True,
        exist_ok=False,
    )

    try:
        findings = [
            normalized_finding_payload(finding)
            for finding
            in execution.collection.findings
        ]
        scope_failures = [
            scope_failure_payload(failure)
            for failure
            in execution.scope_failures
        ]
        collection_failures = [
            collection_failure_payload(failure)
            for failure
            in execution.collection.failures
        ]
        metadata = {
            "schema_version": (
                COHORT_SCHEMA_VERSION
            ),
            "cohort_id": cohort_id,
            "created_at": now_iso(),
            "scope": (
                execution.request.scope.value
            ),
            "target_count": (
                execution.target_count
            ),
            "finding_count": (
                execution.finding_count
            ),
            "failure_count": (
                execution.failure_count
            ),
            "lineage_context_count": (
                execution.manifest
                .lineage_context_count
            ),
            "workers": (
                execution.request.workers
            ),
            "component_workers": (
                execution.request
                .component_workers
            ),
            "criteria": criteria_payload(
                execution
            ),
        }
        payloads = {
            "metadata.json": metadata,
            "manifest.json": (
                execution.manifest.as_dict()
            ),
            "normalized-findings.json": {
                "schema_version": (
                    COHORT_SCHEMA_VERSION
                ),
                "finding_count": len(findings),
                "findings": findings,
            },
            "collection-failures.json": {
                "schema_version": (
                    COHORT_SCHEMA_VERSION
                ),
                "scope_failures": (
                    scope_failures
                ),
                "collection_failures": (
                    collection_failures
                ),
            },
        }

        for name, payload in payloads.items():
            atomic_write_json(
                staging_directory / name,
                payload,
            )

        checksums = {
            name: sha256_file(
                staging_directory / name
            )
            for name in ARTIFACT_NAMES
        }
        atomic_write_json(
            staging_directory / "checksums.json",
            {
                "schema_version": (
                    COHORT_SCHEMA_VERSION
                ),
                "sha256": checksums,
            },
        )

        root_path.mkdir(
            parents=True,
            exist_ok=True,
        )
        os.replace(
            staging_directory,
            final_directory,
        )
        atomic_write_json(
            final_directory / "READY",
            {
                "schema_version": (
                    COHORT_SCHEMA_VERSION
                ),
                "cohort_id": cohort_id,
                "ready_at": now_iso(),
            },
        )

        return final_directory

    except BaseException:
        if staging_directory.exists():
            shutil.rmtree(
                staging_directory,
                ignore_errors=True,
            )

        raise


def read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8")
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        raise CohortError(
            f"Failed reading cohort artifact "
            f"{path}: {error}"
        ) from error

    if not isinstance(payload, dict):
        raise CohortError(
            f"Cohort artifact is not an object: "
            f"{path}"
        )

    return payload


def load_cohort(
    directory: str | Path,
    *,
    verify_checksums: bool = True,
) -> LoadedCohort:
    cohort_directory = Path(directory)

    if not cohort_directory.is_dir():
        raise CohortError(
            f"Cohort directory does not exist: "
            f"{cohort_directory}"
        )

    ready_path = cohort_directory / "READY"

    if not ready_path.is_file():
        raise CohortError(
            f"Cohort is not ready: "
            f"{cohort_directory}"
        )

    ready = read_json(ready_path)
    metadata = read_json(
        cohort_directory / "metadata.json"
    )
    cohort_id = validate_cohort_id(
        str(metadata.get("cohort_id") or "")
    )

    if ready.get("cohort_id") != cohort_id:
        raise CohortError(
            "READY marker cohort ID does not "
            "match metadata"
        )

    if (
        metadata.get("schema_version")
        != COHORT_SCHEMA_VERSION
    ):
        raise CohortError(
            "Unsupported cohort schema version"
        )

    checksums_payload = read_json(
        cohort_directory / "checksums.json"
    )
    checksums = checksums_payload.get(
        "sha256",
        {},
    )

    if not isinstance(checksums, dict):
        raise CohortError(
            "Cohort checksums are invalid"
        )

    if verify_checksums:
        for name in ARTIFACT_NAMES:
            expected = str(
                checksums.get(name) or ""
            )

            if not expected:
                raise CohortError(
                    f"Missing checksum for {name}"
                )

            actual = sha256_file(
                cohort_directory / name
            )

            if actual != expected:
                raise CohortError(
                    f"Checksum mismatch for {name}"
                )

    manifest = read_json(
        cohort_directory / "manifest.json"
    )
    findings_payload = read_json(
        cohort_directory
        / "normalized-findings.json"
    )
    failures_payload = read_json(
        cohort_directory
        / "collection-failures.json"
    )
    raw_findings = findings_payload.get(
        "findings",
        [],
    )

    if not isinstance(raw_findings, list):
        raise CohortError(
            "Cohort findings are invalid"
        )

    findings = tuple(
        finding_from_payload(
            dict(payload)
        )
        for payload in raw_findings
        if isinstance(payload, dict)
    )

    if len(findings) != int(
        findings_payload.get(
            "finding_count",
            len(findings),
        )
    ):
        raise CohortError(
            "Cohort finding count does not "
            "match payload"
        )

    return LoadedCohort(
        cohort_id=cohort_id,
        directory=cohort_directory,
        metadata=metadata,
        manifest=manifest,
        findings=findings,
        scope_failures=tuple(
            dict(value)
            for value in (
                failures_payload.get(
                    "scope_failures",
                    [],
                )
                or []
            )
            if isinstance(value, dict)
        ),
        collection_failures=tuple(
            dict(value)
            for value in (
                failures_payload.get(
                    "collection_failures",
                    [],
                )
                or []
            )
            if isinstance(value, dict)
        ),
    )


def prune_cohorts(
    root: str | Path,
    *,
    retain_count: int,
    protected_ids: set[str] | None = None,
) -> tuple[str, ...]:
    if retain_count < 1:
        raise CohortError(
            "retain_count must be greater than zero"
        )

    root_path = Path(root)

    if not root_path.is_dir():
        return ()

    protected = {
        validate_cohort_id(value)
        for value in (protected_ids or set())
    }
    cohorts: list[tuple[str, str, Path]] = []

    for directory in root_path.iterdir():
        if (
            not directory.is_dir()
            or directory.name == ".staging"
            or not (directory / "READY").is_file()
            or not (directory / "metadata.json").is_file()
        ):
            continue

        try:
            metadata = read_json(
                directory / "metadata.json"
            )
            cohort_id = validate_cohort_id(
                str(
                    metadata.get("cohort_id")
                    or directory.name
                )
            )
        except CohortError:
            continue

        cohorts.append(
            (
                str(metadata.get("created_at") or ""),
                cohort_id,
                directory,
            )
        )

    cohorts.sort(
        key=lambda item: (
            item[0],
            item[1],
        ),
        reverse=True,
    )
    retained = {
        cohort_id
        for _, cohort_id, _
        in cohorts[:retain_count]
    }
    retained.update(protected)
    removed: list[str] = []

    for _, cohort_id, directory in cohorts:
        if cohort_id in retained:
            continue

        shutil.rmtree(directory)
        removed.append(cohort_id)

    return tuple(sorted(removed))
