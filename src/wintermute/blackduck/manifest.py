from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from wintermute.blackduck.models import (
    CollectionTarget,
    LineageContext,
    ProjectVersionRef,
)
from wintermute.blackduck.scopes import (
    CollectionScope,
    normalize_scope,
    resolve_targets,
)


MANIFEST_SCHEMA_VERSION = 1


def now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def project_version_payload(
    value: ProjectVersionRef,
) -> dict[str, Any]:
    return {
        "instance_url": value.instance_url,
        "project": value.project,
        "version": value.version,
        "project_href": value.project_href,
        "version_href": value.version_href,
        "phase": value.phase,
        "updated": value.updated,
        "identity_key": value.identity_key,
        "external_id": value.external_id,
    }


def lineage_payload(
    value: LineageContext,
) -> dict[str, Any]:
    return {
        "external_id": value.external_id,
        "relationship_key": value.relationship_key,
        "detection_method": value.detection_method,
        "bom_component_name": value.bom_component_name,
        "bom_component_version": value.bom_component_version,
        "parent": project_version_payload(value.parent),
        "child": project_version_payload(value.child),
    }


def target_payload(
    target: CollectionTarget,
) -> dict[str, Any]:
    return {
        "external_id": target.project_version.external_id,
        "project_version": project_version_payload(
            target.project_version
        ),
        "lineage_contexts": [
            lineage_payload(context)
            for context in target.lineage_contexts
        ],
    }


@dataclass(frozen=True)
class CollectionManifest:
    scope: CollectionScope
    targets: tuple[CollectionTarget, ...]
    generated_at: str
    schema_version: int = MANIFEST_SCHEMA_VERSION

    @property
    def target_count(self) -> int:
        return len(self.targets)

    @property
    def lineage_context_count(self) -> int:
        return sum(
            len(target.lineage_contexts)
            for target in self.targets
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "scope": self.scope.value,
            "target_count": self.target_count,
            "lineage_context_count": (
                self.lineage_context_count
            ),
            "targets": [
                target_payload(target)
                for target in self.targets
            ],
        }

    def to_json(self) -> str:
        return json.dumps(
            self.as_dict(),
            indent=2,
            sort_keys=True,
        )


def build_collection_manifest(
    scope: str | CollectionScope,
    rows: Iterable[Mapping[str, Any]],
    *,
    instance_url: str = "",
    generated_at: str | None = None,
) -> CollectionManifest:
    normalized_scope = normalize_scope(scope)
    targets = resolve_targets(
        normalized_scope,
        rows,
        instance_url=instance_url,
    )

    return CollectionManifest(
        scope=normalized_scope,
        targets=tuple(targets),
        generated_at=generated_at or now_iso(),
    )


def target_shard(
    target: CollectionTarget,
    shard_count: int,
) -> int:
    if shard_count < 1:
        raise ValueError(
            "shard_count must be greater than zero"
        )

    digest = hashlib.sha256(
        target.project_version.external_id.encode("utf-8")
    ).digest()

    return int.from_bytes(
        digest[:8],
        byteorder="big",
    ) % shard_count


def partition_targets(
    targets: Iterable[CollectionTarget],
    shard_count: int,
) -> list[list[CollectionTarget]]:
    if shard_count < 1:
        raise ValueError(
            "shard_count must be greater than zero"
        )

    partitions: list[list[CollectionTarget]] = [
        []
        for _ in range(shard_count)
    ]

    for target in sorted(
        targets,
        key=lambda item: (
            item.project_version.identity_key
        ),
    ):
        partitions[target_shard(target, shard_count)].append(
            target
        )

    return partitions
