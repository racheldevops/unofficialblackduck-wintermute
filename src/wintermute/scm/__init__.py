"""Provider-neutral source-code management services."""

from wintermute.scm.controls import (
    ControlFailure,
    ControlInventory,
    ControlKind,
    ControlObservation,
    ControlState,
    control_inventory_payload,
    observation_payload,
)
from wintermute.scm.evidence import (
    EVIDENCE_SCHEMA_VERSION,
    EvidenceFailure,
    EvidenceInventory,
    EvidenceKind,
    EvidenceObservation,
    EvidenceScope,
    evidence_inventory_payload,
    evidence_payload,
)
from wintermute.scm.observations import (
    ScmObservationResult,
)
from wintermute.scm.inventory import (
    INVENTORY_SCHEMA_VERSION,
    failure_payload,
    inventory_from_payload,
    inventory_payload,
    merge_inventories,
    repository_payload,
)
from wintermute.scm.models import (
    InventoryFailure,
    Repository,
    RepositoryExclusion,
    RepositoryInventory,
    ScmTenant,
)
from wintermute.scm.protocols import (
    ScmControlProvider,
    ScmInventoryProvider,
    ScmObservationProvider,
)
from wintermute.scm.snapshots import (
    SNAPSHOT_SCHEMA_VERSION,
    LoadedInventorySnapshot,
    SnapshotError,
    create_snapshot_id,
    load_inventory_snapshot,
    write_inventory_snapshot,
)


__all__ = [
    "INVENTORY_SCHEMA_VERSION",
    "SNAPSHOT_SCHEMA_VERSION",
    "ControlFailure",
    "ControlInventory",
    "ControlKind",
    "ControlObservation",
    "ControlState",
    "InventoryFailure",
    "LoadedInventorySnapshot",
    "Repository",
    "RepositoryExclusion",
    "RepositoryInventory",
    "ScmControlProvider",
    "ScmInventoryProvider",
    "ScmTenant",
    "SnapshotError",
    "control_inventory_payload",
    "create_snapshot_id",
    "failure_payload",
    "inventory_from_payload",
    "inventory_payload",
    "load_inventory_snapshot",
    "merge_inventories",
    "observation_payload",
    "repository_payload",
    "write_inventory_snapshot",
]
