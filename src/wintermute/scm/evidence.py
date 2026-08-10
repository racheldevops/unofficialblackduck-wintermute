from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Any

from wintermute.scm.models import (
    normalize_provider,
    normalize_provider_instance,
    required_text,
    sha256_hex,
    stable_key,
)


EVIDENCE_SCHEMA_VERSION = 1


class EvidenceKind(str, Enum):
    REPOSITORY_LANGUAGE_INVENTORY = (
        "repository-language-inventory"
    )
    REPOSITORY_LANGUAGE = (
        "repository-language"
    )
    REPOSITORY_WORKFLOW_INVENTORY = (
        "repository-workflow-inventory"
    )
    REPOSITORY_WORKFLOW = (
        "repository-workflow"
    )
    CUSTOM_PROPERTY_DEFINITION = (
        "custom-property-definition"
    )
    REPOSITORY_CUSTOM_PROPERTY = (
        "repository-custom-property"
    )
    BRANCH_RULESET = "branch-ruleset"
    REQUIRED_WORKFLOW_REFERENCE = (
        "required-workflow-reference"
    )


class EvidenceScope(str, Enum):
    TENANT = "tenant"
    REPOSITORY = "repository"


def canonical_value(
    value: Any,
) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )


@dataclass(frozen=True)
class EvidenceObservation:
    provider: str
    provider_instance: str
    tenant_id: str
    kind: EvidenceKind
    scope: EvidenceScope
    key: str
    source: str
    provider_resource_id: str = ""
    repository_external_id: str = ""
    name_with_owner: str = ""
    attributes: tuple[
        tuple[str, str],
        ...
    ] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "provider",
            normalize_provider(self.provider),
        )
        object.__setattr__(
            self,
            "provider_instance",
            normalize_provider_instance(
                self.provider_instance
            ),
        )
        object.__setattr__(
            self,
            "tenant_id",
            required_text(
                self.tenant_id,
                "tenant_id",
            ),
        )

        if not isinstance(
            self.kind,
            EvidenceKind,
        ):
            object.__setattr__(
                self,
                "kind",
                EvidenceKind(str(self.kind)),
            )

        if not isinstance(
            self.scope,
            EvidenceScope,
        ):
            object.__setattr__(
                self,
                "scope",
                EvidenceScope(str(self.scope)),
            )

        object.__setattr__(
            self,
            "key",
            required_text(
                self.key,
                "key",
            ),
        )
        object.__setattr__(
            self,
            "source",
            required_text(
                self.source,
                "source",
            ),
        )
        object.__setattr__(
            self,
            "provider_resource_id",
            str(
                self.provider_resource_id
                or ""
            ).strip(),
        )
        object.__setattr__(
            self,
            "repository_external_id",
            str(
                self.repository_external_id
                or ""
            ).strip(),
        )
        object.__setattr__(
            self,
            "name_with_owner",
            str(
                self.name_with_owner
                or ""
            ).strip(),
        )

        if (
            self.scope
            == EvidenceScope.REPOSITORY
            and not self.name_with_owner
        ):
            raise ValueError(
                "Repository evidence requires name_with_owner"
            )

        normalized_attributes = tuple(
            sorted(
                (
                    required_text(
                        name,
                        "attribute name",
                    ),
                    str(value),
                )
                for name, value
                in self.attributes
            )
        )

        if len(normalized_attributes) != len(
            {
                name
                for name, _
                in normalized_attributes
            }
        ):
            raise ValueError(
                "Evidence attributes contain duplicate names"
            )

        object.__setattr__(
            self,
            "attributes",
            normalized_attributes,
        )

    @property
    def identity_key(self) -> str:
        return stable_key(
            (
                self.provider,
                self.provider_instance,
                self.tenant_id,
                self.kind.value,
                self.scope.value,
                self.repository_external_id,
                self.name_with_owner.casefold(),
                self.provider_resource_id,
                self.key,
            )
        )

    @property
    def external_id(self) -> str:
        return sha256_hex(
            f"scm-evidence|{self.identity_key}"
        )


@dataclass(frozen=True)
class EvidenceFailure:
    provider: str
    provider_instance: str
    tenant_id: str
    stage: str
    error: str
    repository_external_id: str = ""
    name_with_owner: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "provider",
            normalize_provider(self.provider),
        )
        object.__setattr__(
            self,
            "provider_instance",
            normalize_provider_instance(
                self.provider_instance
            ),
        )
        object.__setattr__(
            self,
            "tenant_id",
            required_text(
                self.tenant_id,
                "tenant_id",
            ),
        )
        object.__setattr__(
            self,
            "stage",
            required_text(
                self.stage,
                "stage",
            ),
        )
        object.__setattr__(
            self,
            "error",
            required_text(
                self.error,
                "error",
            ),
        )
        object.__setattr__(
            self,
            "repository_external_id",
            str(
                self.repository_external_id
                or ""
            ).strip(),
        )
        object.__setattr__(
            self,
            "name_with_owner",
            str(
                self.name_with_owner
                or ""
            ).strip(),
        )

        if (
            self.repository_external_id
            and not self.name_with_owner
        ):
            raise ValueError(
                "Repository evidence failure requires "
                "name_with_owner"
            )


@dataclass(frozen=True)
class EvidenceInventory:
    observations: tuple[
        EvidenceObservation,
        ...
    ]
    failures: tuple[
        EvidenceFailure,
        ...
    ] = ()

    def __post_init__(self) -> None:
        identities = [
            observation.external_id
            for observation
            in self.observations
        ]

        if len(identities) != len(
            set(identities)
        ):
            raise ValueError(
                "Evidence inventory contains "
                "duplicate observations"
            )

    @property
    def observation_count(self) -> int:
        return len(self.observations)

    @property
    def failure_count(self) -> int:
        return len(self.failures)


def evidence_payload(
    observation: EvidenceObservation,
) -> dict[str, Any]:
    return {
        "external_id": observation.external_id,
        "identity_key": observation.identity_key,
        "provider": observation.provider,
        "provider_instance": (
            observation.provider_instance
        ),
        "tenant_id": observation.tenant_id,
        "kind": observation.kind.value,
        "scope": observation.scope.value,
        "key": observation.key,
        "source": observation.source,
        "provider_resource_id": (
            observation.provider_resource_id
        ),
        "repository_external_id": (
            observation.repository_external_id
        ),
        "name_with_owner": (
            observation.name_with_owner
        ),
        "attributes": {
            name: value
            for name, value
            in observation.attributes
        },
    }


def evidence_failure_payload(
    failure: EvidenceFailure,
) -> dict[str, str]:
    return {
        "provider": failure.provider,
        "provider_instance": (
            failure.provider_instance
        ),
        "tenant_id": failure.tenant_id,
        "stage": failure.stage,
        "error": failure.error,
        "repository_external_id": (
            failure.repository_external_id
        ),
        "name_with_owner": (
            failure.name_with_owner
        ),
    }


def evidence_inventory_payload(
    inventory: EvidenceInventory,
) -> dict[str, Any]:
    return {
        "schema_version": (
            EVIDENCE_SCHEMA_VERSION
        ),
        "observation_count": (
            inventory.observation_count
        ),
        "failure_count": (
            inventory.failure_count
        ),
        "observations": [
            evidence_payload(observation)
            for observation
            in sorted(
                inventory.observations,
                key=lambda item: (
                    item.provider,
                    item.provider_instance,
                    item.kind.value,
                    item.scope.value,
                    item.name_with_owner.casefold(),
                    item.key,
                ),
            )
        ],
        "failures": [
            evidence_failure_payload(failure)
            for failure
            in inventory.failures
        ],
    }


def _evidence_objects(
    payload: dict[str, Any],
    field: str,
) -> list[dict[str, Any]]:
    values = payload.get(field)

    if (
        not isinstance(values, list)
        or not all(
            isinstance(value, dict)
            for value in values
        )
    ):
        raise ValueError(
            f"Evidence field {field!r} must be "
            "a list of objects"
        )

    return [
        dict(value)
        for value in values
    ]


def evidence_from_payload(
    payload: dict[str, Any],
) -> EvidenceObservation:
    attributes = payload.get(
        "attributes",
        {},
    )

    if not isinstance(attributes, dict):
        raise ValueError(
            "Evidence attributes must be an object"
        )

    observation = EvidenceObservation(
        provider=payload.get("provider", ""),
        provider_instance=payload.get(
            "provider_instance",
            "",
        ),
        tenant_id=payload.get(
            "tenant_id",
            "",
        ),
        kind=payload.get("kind", ""),
        scope=payload.get("scope", ""),
        key=payload.get("key", ""),
        source=payload.get("source", ""),
        provider_resource_id=payload.get(
            "provider_resource_id",
            "",
        ),
        repository_external_id=payload.get(
            "repository_external_id",
            "",
        ),
        name_with_owner=payload.get(
            "name_with_owner",
            "",
        ),
        attributes=tuple(
            (
                str(name),
                str(value),
            )
            for name, value
            in attributes.items()
        ),
    )

    for field, actual in (
        (
            "identity_key",
            observation.identity_key,
        ),
        (
            "external_id",
            observation.external_id,
        ),
    ):
        expected = payload.get(field)

        if (
            expected is not None
            and expected != actual
        ):
            raise ValueError(
                f"Evidence {field} does not match "
                "the observation"
            )

    return observation


def evidence_failure_from_payload(
    payload: dict[str, Any],
) -> EvidenceFailure:
    return EvidenceFailure(
        provider=payload.get("provider", ""),
        provider_instance=payload.get(
            "provider_instance",
            "",
        ),
        tenant_id=payload.get(
            "tenant_id",
            "",
        ),
        stage=payload.get("stage", ""),
        error=payload.get("error", ""),
        repository_external_id=payload.get(
            "repository_external_id",
            "",
        ),
        name_with_owner=payload.get(
            "name_with_owner",
            "",
        ),
    )


def evidence_inventory_from_payload(
    payload: dict[str, Any],
) -> EvidenceInventory:
    if not isinstance(payload, dict):
        raise ValueError(
            "Evidence inventory must be an object"
        )

    if (
        payload.get("schema_version")
        != EVIDENCE_SCHEMA_VERSION
    ):
        raise ValueError(
            "Unsupported evidence inventory schema version"
        )

    inventory = EvidenceInventory(
        observations=tuple(
            evidence_from_payload(value)
            for value in _evidence_objects(
                payload,
                "observations",
            )
        ),
        failures=tuple(
            evidence_failure_from_payload(value)
            for value in _evidence_objects(
                payload,
                "failures",
            )
        ),
    )

    for field, expected in (
        (
            "observation_count",
            inventory.observation_count,
        ),
        (
            "failure_count",
            inventory.failure_count,
        ),
    ):
        if payload.get(field) != expected:
            raise ValueError(
                f"Evidence field {field!r} does not "
                "match its records"
            )

    return inventory


def merge_evidence_inventories(
    inventories: tuple[
        EvidenceInventory,
        ...
    ],
) -> EvidenceInventory:
    observations: list[
        EvidenceObservation
    ] = []
    failures: list[
        EvidenceFailure
    ] = []
    seen_observations: set[str] = set()
    seen_failures: set[
        tuple[str, ...]
    ] = set()

    for inventory in inventories:
        for observation in inventory.observations:
            if (
                observation.external_id
                in seen_observations
            ):
                raise ValueError(
                    "Duplicate evidence observation "
                    "while merging inventories"
                )

            seen_observations.add(
                observation.external_id
            )
            observations.append(observation)

        for failure in inventory.failures:
            key = (
                failure.provider,
                failure.provider_instance,
                failure.tenant_id,
                failure.repository_external_id,
                failure.name_with_owner,
                failure.stage,
                failure.error,
            )

            if key in seen_failures:
                continue

            seen_failures.add(key)
            failures.append(failure)

    return EvidenceInventory(
        observations=tuple(observations),
        failures=tuple(failures),
    )
