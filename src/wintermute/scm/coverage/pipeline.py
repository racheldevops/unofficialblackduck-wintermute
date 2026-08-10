from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from wintermute.blackduck.inventory import (
    InventoryFilter,
    build_project_version_inventory,
)
from wintermute.scm.coverage.blackduck import (
    observe_blackduck_inventory,
)
from wintermute.scm.coverage.blackduck_scan import (
    collect_blackduck_scan_evidence,
)
from wintermute.scm.coverage.mapping import (
    map_repositories_to_blackduck,
)
from wintermute.scm.coverage.models import (
    BlackDuckInventoryObservation,
    CoverageReport,
    ExplicitMapping,
    MappingMetadataFields,
    MappingResult,
)
from wintermute.scm.coverage.reconciliation import (
    reconcile_coverage,
)
from wintermute.scm.coverage.scan_evidence import (
    apply_scan_evidence,
    load_scan_evidence,
)
from wintermute.scm.snapshots import (
    LoadedInventorySnapshot,
    load_inventory_snapshot,
)


EXPLICIT_MAPPING_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class CoverageExecution:
    source_snapshot: LoadedInventorySnapshot
    blackduck: BlackDuckInventoryObservation
    mappings: MappingResult
    report: CoverageReport


def load_explicit_mappings(
    path: str | Path | None,
) -> tuple[ExplicitMapping, ...]:
    if not path:
        return ()

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
            f"Failed reading explicit mappings "
            f"{source}: {error}"
        ) from error

    if not isinstance(payload, dict):
        raise ValueError(
            "Explicit mapping file must be an object"
        )

    if (
        payload.get("schema_version")
        != EXPLICIT_MAPPING_SCHEMA_VERSION
    ):
        raise ValueError(
            "Unsupported explicit mapping schema version"
        )

    values = payload.get("mappings")

    if (
        not isinstance(values, list)
        or not all(
            isinstance(value, dict)
            for value in values
        )
    ):
        raise ValueError(
            "Explicit mappings must be a list of objects"
        )

    mappings = tuple(
        ExplicitMapping(
            repository_external_id=value.get(
                "repository_external_id",
                "",
            ),
            blackduck_project_id=value.get(
                "blackduck_project_id",
                "",
            ),
        )
        for value in values
    )
    identities = [
        mapping.repository_external_id
        for mapping in mappings
    ]

    if len(identities) != len(
        set(identities)
    ):
        raise ValueError(
            "Explicit mappings contain duplicate "
            "repository identities"
        )

    return mappings


def execute_coverage(
    client: Any,
    scm_snapshot: str | Path,
    *,
    inventory_filter: (
        InventoryFilter | None
    ) = None,
    workers: int = 4,
    metadata_fields: (
        MappingMetadataFields | None
    ) = None,
    explicit_mappings: tuple[
        ExplicitMapping,
        ...
    ] = (),
    scan_evidence_path: (
        str | Path | None
    ) = None,
    collect_direct_scan_evidence: bool = True,
    scan_evidence_workers: int | None = None,
    freshness_sla_days: int = 30,
    now: datetime | None = None,
) -> CoverageExecution:
    source = load_inventory_snapshot(
        scm_snapshot
    )
    raw_blackduck = (
        build_project_version_inventory(
            client,
            filters=(
                inventory_filter
                or InventoryFilter()
            ),
            workers=workers,
        )
    )
    blackduck = (
        observe_blackduck_inventory(
            raw_blackduck,
            metadata_fields=metadata_fields,
        )
    )

    if scan_evidence_path:
        blackduck = apply_scan_evidence(
            blackduck,
            load_scan_evidence(
                scan_evidence_path
            ),
        )
    elif collect_direct_scan_evidence:
        blackduck = (
            collect_blackduck_scan_evidence(
                client,
                blackduck,
                workers=(
                    scan_evidence_workers
                    if scan_evidence_workers
                    is not None
                    else workers
                ),
            )
        )

    mappings = (
        map_repositories_to_blackduck(
            source.inventory,
            blackduck,
            explicit_mappings=(
                explicit_mappings
            ),
        )
    )
    report = reconcile_coverage(
        source.inventory,
        source.controls,
        blackduck,
        mappings,
        freshness_sla_days=(
            freshness_sla_days
        ),
        now=now,
    )

    return CoverageExecution(
        source_snapshot=source,
        blackduck=blackduck,
        mappings=mappings,
        report=report,
    )
