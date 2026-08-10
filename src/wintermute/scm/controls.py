from __future__ import annotations

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


class ControlKind(str, Enum):
    ONBOARDING_POLICY = "onboarding-policy"
    REQUIRED_SCAN_WORKFLOW = "required-scan-workflow"
    PROTECTED_DEFAULT_BRANCH = "protected-default-branch"


class ControlState(str, Enum):
    AVAILABLE = "available"
    COMPLIANT = "compliant"
    NONCOMPLIANT = "noncompliant"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"
    FAILED = "failed"


@dataclass(frozen=True)
class ControlObservation:
    provider: str
    provider_instance: str
    tenant_id: str
    repository_external_id: str
    name_with_owner: str
    control: ControlKind
    state: ControlState
    source: str
    expected: str = ""
    observed: str = ""
    message: str = ""
    provider_resource_id: str = ""
    attributes: tuple[tuple[str, str], ...] = ()

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
            "repository_external_id",
            required_text(
                self.repository_external_id,
                "repository_external_id",
            ),
        )
        object.__setattr__(
            self,
            "name_with_owner",
            required_text(
                self.name_with_owner,
                "name_with_owner",
            ),
        )

        if not isinstance(
            self.control,
            ControlKind,
        ):
            object.__setattr__(
                self,
                "control",
                ControlKind(str(self.control)),
            )

        if not isinstance(
            self.state,
            ControlState,
        ):
            object.__setattr__(
                self,
                "state",
                ControlState(str(self.state)),
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
            "expected",
            str(self.expected or "").strip(),
        )
        object.__setattr__(
            self,
            "observed",
            str(self.observed or "").strip(),
        )
        object.__setattr__(
            self,
            "message",
            str(self.message or "").strip(),
        )
        object.__setattr__(
            self,
            "provider_resource_id",
            str(
                self.provider_resource_id
                or ""
            ).strip(),
        )

        normalized_attributes = tuple(
            sorted(
                (
                    str(key).strip(),
                    str(value).strip(),
                )
                for key, value
                in self.attributes
                if str(key).strip()
            )
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
                self.repository_external_id,
                self.control.value,
            )
        )

    @property
    def external_id(self) -> str:
        return sha256_hex(
            f"scm-control|{self.identity_key}"
        )


@dataclass(frozen=True)
class ControlFailure:
    provider: str
    provider_instance: str
    tenant_id: str
    stage: str
    error: str

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


@dataclass(frozen=True)
class ControlInventory:
    observations: tuple[
        ControlObservation,
        ...
    ]
    failures: tuple[
        ControlFailure,
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
                "Control inventory contains duplicate observations"
            )

    @property
    def observation_count(self) -> int:
        return len(self.observations)

    @property
    def failure_count(self) -> int:
        return len(self.failures)


def observation_payload(
    observation: ControlObservation,
) -> dict[str, Any]:
    return {
        "external_id": observation.external_id,
        "identity_key": observation.identity_key,
        "provider": observation.provider,
        "provider_instance": (
            observation.provider_instance
        ),
        "tenant_id": observation.tenant_id,
        "repository_external_id": (
            observation.repository_external_id
        ),
        "name_with_owner": (
            observation.name_with_owner
        ),
        "control": observation.control.value,
        "state": observation.state.value,
        "source": observation.source,
        "expected": observation.expected,
        "observed": observation.observed,
        "message": observation.message,
        "provider_resource_id": (
            observation.provider_resource_id
        ),
        "attributes": {
            key: value
            for key, value
            in observation.attributes
        },
    }


def control_failure_payload(
    failure: ControlFailure,
) -> dict[str, str]:
    return {
        "provider": failure.provider,
        "provider_instance": (
            failure.provider_instance
        ),
        "tenant_id": failure.tenant_id,
        "stage": failure.stage,
        "error": failure.error,
    }


def control_inventory_payload(
    inventory: ControlInventory,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "observation_count": (
            inventory.observation_count
        ),
        "failure_count": (
            inventory.failure_count
        ),
        "observations": [
            observation_payload(observation)
            for observation
            in sorted(
                inventory.observations,
                key=lambda item: (
                    item.provider,
                    item.provider_instance,
                    item.name_with_owner.casefold(),
                    item.control.value,
                ),
            )
        ],
        "failures": [
            control_failure_payload(failure)
            for failure
            in inventory.failures
        ],
    }


def _control_objects(
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
            f"Control field {field!r} must be "
            "a list of objects"
        )

    return [
        dict(value)
        for value in values
    ]


def observation_from_payload(
    payload: dict[str, Any],
) -> ControlObservation:
    attributes = payload.get(
        "attributes",
        {},
    )

    if not isinstance(attributes, dict):
        raise ValueError(
            "Control attributes must be an object"
        )

    observation = ControlObservation(
        provider=payload.get("provider", ""),
        provider_instance=payload.get(
            "provider_instance",
            "",
        ),
        tenant_id=payload.get(
            "tenant_id",
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
        control=payload.get("control", ""),
        state=payload.get("state", ""),
        source=payload.get("source", ""),
        expected=payload.get("expected", ""),
        observed=payload.get("observed", ""),
        message=payload.get("message", ""),
        provider_resource_id=payload.get(
            "provider_resource_id",
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
                f"Control {field} does not match "
                "the observation"
            )

    return observation


def control_failure_from_payload(
    payload: dict[str, Any],
) -> ControlFailure:
    return ControlFailure(
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
    )


def control_inventory_from_payload(
    payload: dict[str, Any],
) -> ControlInventory:
    if not isinstance(payload, dict):
        raise ValueError(
            "Control inventory must be an object"
        )

    if payload.get("schema_version") != 1:
        raise ValueError(
            "Unsupported control inventory schema version"
        )

    inventory = ControlInventory(
        observations=tuple(
            observation_from_payload(value)
            for value in _control_objects(
                payload,
                "observations",
            )
        ),
        failures=tuple(
            control_failure_from_payload(value)
            for value in _control_objects(
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
                f"Control field {field!r} does not "
                "match its records"
            )

    return inventory
