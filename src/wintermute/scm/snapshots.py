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
    ControlInventory,
    control_inventory_from_payload,
    control_inventory_payload,
)
from wintermute.scm.evidence import (
    EvidenceInventory,
    EvidenceScope,
    evidence_inventory_from_payload,
    evidence_inventory_payload,
)
from wintermute.scm.inventory import (
    failure_payload,
    inventory_from_payload,
    inventory_payload,
)
from wintermute.scm.models import (
    RepositoryInventory,
    ScmTenant,
)
from wintermute.scm.observations import (
    ScmObservationResult,
)


SNAPSHOT_SCHEMA_VERSION = 1
SNAPSHOT_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
)
ARTIFACT_NAMES = (
    "metadata.json",
    "repositories.json",
    "failures.json",
    "provider-evidence.json",
    "onboarding-controls.json",
)


class SnapshotError(RuntimeError):
    pass


@dataclass(frozen=True)
class LoadedInventorySnapshot:
    snapshot_id: str
    directory: Path
    metadata: dict[str, Any]
    tenant: ScmTenant
    inventory: RepositoryInventory
    evidence: EvidenceInventory
    controls: ControlInventory


def now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def create_snapshot_id() -> str:
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
        raise SnapshotError(
            f"Invalid snapshot ID: {selected!r}"
        )

    return selected


def tenant_payload(
    tenant: ScmTenant,
) -> dict[str, str]:
    return {
        "provider": tenant.provider,
        "provider_instance": (
            tenant.provider_instance
        ),
        "tenant_id": tenant.tenant_id,
        "namespace": tenant.namespace,
        "identity_key": tenant.identity_key,
        "external_id": tenant.external_id,
    }


def tenant_from_payload(
    payload: dict[str, Any],
) -> ScmTenant:
    if not isinstance(payload, dict):
        raise SnapshotError(
            "Snapshot tenant must be an object"
        )

    tenant = ScmTenant(
        provider=payload.get("provider", ""),
        provider_instance=payload.get(
            "provider_instance",
            "",
        ),
        tenant_id=payload.get("tenant_id", ""),
        namespace=payload.get("namespace", ""),
    )

    for field, actual in (
        (
            "identity_key",
            tenant.identity_key,
        ),
        (
            "external_id",
            tenant.external_id,
        ),
    ):
        expected = payload.get(field)

        if (
            expected is not None
            and expected != actual
        ):
            raise SnapshotError(
                f"Snapshot tenant {field} does not match"
            )

    return tenant


def empty_observations() -> ScmObservationResult:
    return ScmObservationResult(
        evidence=EvidenceInventory(
            observations=()
        ),
        controls=ControlInventory(
            observations=()
        ),
    )


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
        payload = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        raise SnapshotError(
            f"Failed reading snapshot artifact "
            f"{path}: {error}"
        ) from error

    if not isinstance(payload, dict):
        raise SnapshotError(
            f"Snapshot artifact is not an object: {path}"
        )

    return payload


def inventory_repositories(
    inventory: RepositoryInventory,
) -> dict[str, str]:
    values = [
        *inventory.repositories,
        *(
            exclusion.repository
            for exclusion
            in inventory.exclusions
        ),
    ]

    return {
        repository.external_id: (
            repository.name_with_owner
        )
        for repository in values
    }


def validate_snapshot_contents(
    tenant: ScmTenant,
    inventory: RepositoryInventory,
    observations: ScmObservationResult,
) -> None:
    repositories = [
        *inventory.repositories,
        *(
            exclusion.repository
            for exclusion
            in inventory.exclusions
        ),
    ]

    for repository in repositories:
        if (
            repository.provider
            != tenant.provider
            or repository.provider_instance
            != tenant.provider_instance
            or repository.tenant_id
            != tenant.tenant_id
        ):
            raise SnapshotError(
                "Repository identity does not match "
                "the snapshot tenant"
            )

    for failure in inventory.failures:
        if (
            failure.provider
            != tenant.provider
            or failure.provider_instance
            != tenant.provider_instance
            or (
                failure.tenant_id
                and failure.tenant_id
                != tenant.tenant_id
            )
        ):
            raise SnapshotError(
                "Inventory failure identity does not "
                "match the snapshot tenant"
            )

    known_repositories = inventory_repositories(
        inventory
    )

    for observation in (
        observations.evidence.observations
    ):
        if (
            observation.provider
            != tenant.provider
            or observation.provider_instance
            != tenant.provider_instance
            or observation.tenant_id
            != tenant.tenant_id
        ):
            raise SnapshotError(
                "Evidence identity does not match "
                "the snapshot tenant"
            )

        if observation.repository_external_id:
            expected_name = known_repositories.get(
                observation.repository_external_id
            )

            if expected_name is None:
                raise SnapshotError(
                    "Evidence references an unknown repository"
                )

            if (
                observation.scope
                == EvidenceScope.REPOSITORY
                and expected_name.casefold()
                != observation.name_with_owner.casefold()
            ):
                raise SnapshotError(
                    "Evidence repository name does not "
                    "match its identity"
                )

    for failure in (
        observations.evidence.failures
    ):
        if (
            failure.provider
            != tenant.provider
            or failure.provider_instance
            != tenant.provider_instance
            or failure.tenant_id
            != tenant.tenant_id
        ):
            raise SnapshotError(
                "Evidence failure identity does not "
                "match the snapshot tenant"
            )

    for observation in (
        observations.controls.observations
    ):
        if (
            observation.provider
            != tenant.provider
            or observation.provider_instance
            != tenant.provider_instance
            or observation.tenant_id
            != tenant.tenant_id
        ):
            raise SnapshotError(
                "Control identity does not match "
                "the snapshot tenant"
            )

        expected_name = known_repositories.get(
            observation.repository_external_id
        )

        if expected_name is None:
            raise SnapshotError(
                "Control references an unknown repository"
            )

        if (
            expected_name.casefold()
            != observation.name_with_owner.casefold()
        ):
            raise SnapshotError(
                "Control repository name does not "
                "match its identity"
            )

    for failure in (
        observations.controls.failures
    ):
        if (
            failure.provider
            != tenant.provider
            or failure.provider_instance
            != tenant.provider_instance
            or failure.tenant_id
            != tenant.tenant_id
        ):
            raise SnapshotError(
                "Control failure identity does not "
                "match the snapshot tenant"
            )


def write_inventory_snapshot(
    root: str | Path,
    tenant: ScmTenant,
    inventory: RepositoryInventory,
    *,
    observations: (
        ScmObservationResult | None
    ) = None,
    snapshot_id: str | None = None,
) -> Path:
    if not inventory.reconciled:
        raise SnapshotError(
            "Unreconciled inventory cannot be published"
        )

    selected_observations = (
        observations
        or empty_observations()
    )
    validate_snapshot_contents(
        tenant,
        inventory,
        selected_observations,
    )
    selected_id = validate_snapshot_id(
        snapshot_id or create_snapshot_id()
    )
    root_path = Path(root)
    staging_directory = (
        root_path
        / ".staging"
        / selected_id
    )
    final_directory = (
        root_path / selected_id
    )

    if final_directory.exists():
        raise SnapshotError(
            f"Snapshot already exists: {final_directory}"
        )

    if staging_directory.exists():
        shutil.rmtree(
            staging_directory
        )

    staging_directory.mkdir(
        parents=True,
        exist_ok=False,
    )

    try:
        complete_inventory = inventory_payload(
            inventory
        )
        total_failure_count = (
            inventory.failure_count
            + selected_observations.failure_count
        )
        metadata = {
            "schema_version": (
                SNAPSHOT_SCHEMA_VERSION
            ),
            "snapshot_id": selected_id,
            "created_at": now_iso(),
            "status": (
                "partial"
                if total_failure_count
                else "succeeded"
            ),
            "tenant": tenant_payload(tenant),
            "discovered_repository_count": (
                inventory.discovered_count
            ),
            "repository_count": (
                inventory.repository_count
            ),
            "exclusion_count": (
                inventory.exclusion_count
            ),
            "inventory_failure_count": (
                inventory.failure_count
            ),
            "evidence_observation_count": (
                selected_observations
                .evidence
                .observation_count
            ),
            "evidence_failure_count": (
                selected_observations
                .evidence
                .failure_count
            ),
            "control_observation_count": (
                selected_observations
                .controls
                .observation_count
            ),
            "control_failure_count": (
                selected_observations
                .controls
                .failure_count
            ),
            "observation_failure_count": (
                selected_observations
                .failure_count
            ),
            "failure_count": (
                total_failure_count
            ),
            "reconciled": inventory.reconciled,
        }
        repositories = {
            "schema_version": (
                SNAPSHOT_SCHEMA_VERSION
            ),
            "discovered_repository_count": (
                inventory.discovered_count
            ),
            "repository_count": (
                inventory.repository_count
            ),
            "exclusion_count": (
                inventory.exclusion_count
            ),
            "reconciled": inventory.reconciled,
            "repositories": (
                complete_inventory["repositories"]
            ),
            "exclusions": (
                complete_inventory["exclusions"]
            ),
        }
        failures = {
            "schema_version": (
                SNAPSHOT_SCHEMA_VERSION
            ),
            "failure_count": (
                inventory.failure_count
            ),
            "failures": [
                failure_payload(failure)
                for failure
                in inventory.failures
            ],
        }
        payloads = {
            "metadata.json": metadata,
            "repositories.json": repositories,
            "failures.json": failures,
            "provider-evidence.json": (
                evidence_inventory_payload(
                    selected_observations.evidence
                )
            ),
            "onboarding-controls.json": (
                control_inventory_payload(
                    selected_observations.controls
                )
            ),
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
            staging_directory
            / "checksums.json",
            {
                "schema_version": (
                    SNAPSHOT_SCHEMA_VERSION
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
                    SNAPSHOT_SCHEMA_VERSION
                ),
                "snapshot_id": selected_id,
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


def load_inventory_snapshot(
    directory: str | Path,
    *,
    verify_checksums: bool = True,
) -> LoadedInventorySnapshot:
    snapshot_directory = Path(directory)

    if not snapshot_directory.is_dir():
        raise SnapshotError(
            f"Snapshot directory does not exist: "
            f"{snapshot_directory}"
        )

    if not (
        snapshot_directory / "READY"
    ).is_file():
        raise SnapshotError(
            f"Snapshot is not ready: "
            f"{snapshot_directory}"
        )

    ready = read_json(
        snapshot_directory / "READY"
    )
    metadata = read_json(
        snapshot_directory / "metadata.json"
    )

    if (
        metadata.get("schema_version")
        != SNAPSHOT_SCHEMA_VERSION
    ):
        raise SnapshotError(
            "Unsupported snapshot schema version"
        )

    snapshot_id = validate_snapshot_id(
        metadata.get("snapshot_id", "")
    )

    if ready.get("snapshot_id") != snapshot_id:
        raise SnapshotError(
            "READY snapshot ID does not match metadata"
        )

    checksums_payload = read_json(
        snapshot_directory
        / "checksums.json"
    )
    checksums = checksums_payload.get(
        "sha256"
    )

    if not isinstance(checksums, dict):
        raise SnapshotError(
            "Snapshot checksums are invalid"
        )

    if verify_checksums:
        for name in ARTIFACT_NAMES:
            expected = str(
                checksums.get(name) or ""
            )

            if not expected:
                raise SnapshotError(
                    f"Missing checksum for {name}"
                )

            actual = sha256_file(
                snapshot_directory / name
            )

            if actual != expected:
                raise SnapshotError(
                    f"Checksum mismatch for {name}"
                )

    repositories = read_json(
        snapshot_directory
        / "repositories.json"
    )
    failures = read_json(
        snapshot_directory / "failures.json"
    )
    evidence_payload = read_json(
        snapshot_directory
        / "provider-evidence.json"
    )
    controls_payload = read_json(
        snapshot_directory
        / "onboarding-controls.json"
    )
    combined_inventory = {
        **repositories,
        "failure_count": failures.get(
            "failure_count"
        ),
        "failures": failures.get(
            "failures"
        ),
    }

    try:
        inventory = inventory_from_payload(
            combined_inventory
        )
        evidence = (
            evidence_inventory_from_payload(
                evidence_payload
            )
        )
        controls = (
            control_inventory_from_payload(
                controls_payload
            )
        )
    except ValueError as error:
        raise SnapshotError(
            f"Invalid SCM snapshot payload: {error}"
        ) from error

    tenant = tenant_from_payload(
        metadata.get("tenant", {})
    )
    observations = ScmObservationResult(
        evidence=evidence,
        controls=controls,
    )
    validate_snapshot_contents(
        tenant,
        inventory,
        observations,
    )
    total_failure_count = (
        inventory.failure_count
        + observations.failure_count
    )
    expected_metadata = {
        "discovered_repository_count": (
            inventory.discovered_count
        ),
        "repository_count": (
            inventory.repository_count
        ),
        "exclusion_count": (
            inventory.exclusion_count
        ),
        "inventory_failure_count": (
            inventory.failure_count
        ),
        "evidence_observation_count": (
            evidence.observation_count
        ),
        "evidence_failure_count": (
            evidence.failure_count
        ),
        "control_observation_count": (
            controls.observation_count
        ),
        "control_failure_count": (
            controls.failure_count
        ),
        "observation_failure_count": (
            observations.failure_count
        ),
        "failure_count": (
            total_failure_count
        ),
        "reconciled": inventory.reconciled,
        "status": (
            "partial"
            if total_failure_count
            else "succeeded"
        ),
    }

    for field, expected in (
        expected_metadata.items()
    ):
        if metadata.get(field) != expected:
            raise SnapshotError(
                f"Snapshot metadata field {field!r} "
                "does not match its artifacts"
            )

    return LoadedInventorySnapshot(
        snapshot_id=snapshot_id,
        directory=snapshot_directory,
        metadata=metadata,
        tenant=tenant,
        inventory=inventory,
        evidence=evidence,
        controls=controls,
    )
