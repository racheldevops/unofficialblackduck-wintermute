from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wintermute.blackduck.actions.models import (
    ActionLimits,
    belongs_to_instance,
    json_copy,
    normalize_base_url,
    stable_digest,
)
from wintermute.scm.providers.gitlab.repository import (
    validate_repository_location,
    validate_revision,
)


CIP_CONFIGURATION_SCHEMA_VERSION = 1

PROJECT_VERSION_HREF_ENV = (
    "WINTERMUTE_CIP_PROJECT_VERSION_HREF"
)
COMPONENT_VERSION_HREF_ENV = (
    "WINTERMUTE_CIP_COMPONENT_VERSION_HREF"
)
TAG_ENV = "WINTERMUTE_CIP_TAG"
BRANCH_ENV = "WINTERMUTE_CIP_BRANCH"
TARGETS_JSON_ENV = "WINTERMUTE_CIP_TARGETS_JSON"


def environment_value(
    environment: Mapping[str, str],
    name: str,
) -> str:
    return str(
        environment.get(name, "") or ""
    ).strip()


def environment_integer(
    environment: Mapping[str, str],
    name: str,
    default: int,
) -> int:
    raw = environment_value(
        environment,
        name,
    )

    if not raw:
        return default

    try:
        return int(raw)
    except ValueError as error:
        raise ValueError(
            f"{name} must be an integer"
        ) from error


def environment_boolean(
    environment: Mapping[str, str],
    name: str,
    default: bool,
) -> bool:
    raw = environment_value(
        environment,
        name,
    ).casefold()

    if not raw:
        return default

    if raw in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return True

    if raw in {
        "0",
        "false",
        "no",
        "off",
    }:
        return False

    raise ValueError(
        f"{name} must be boolean"
    )


def blackduck_href(
    base_url: str,
    value: str,
) -> str:
    selected = str(value or "").strip()

    if selected.startswith("/api/"):
        return (
            f"{base_url.rstrip('/')}"
            f"{selected}"
        )

    if selected.startswith(
        ("http://", "https://")
    ):
        if not belongs_to_instance(
            base_url,
            selected,
        ):
            raise ValueError(
                "CIP target belongs to another "
                "Black Duck instance"
            )

        return selected.rstrip("/")

    raise ValueError(
        "CIP target must be an absolute Black Duck "
        "URL or an /api/ path"
    )


def configured_target_payloads(
    payload: dict[str, Any],
    environment: Mapping[str, str],
) -> tuple[list[dict[str, Any]], bool]:
    raw_json = environment_value(
        environment,
        TARGETS_JSON_ENV,
    )

    if raw_json:
        try:
            values = json.loads(raw_json)
        except json.JSONDecodeError as error:
            raise ValueError(
                f"{TARGETS_JSON_ENV} must contain "
                "valid JSON"
            ) from error

        if (
            not isinstance(values, list)
            or not all(
                isinstance(value, dict)
                for value in values
            )
        ):
            raise ValueError(
                f"{TARGETS_JSON_ENV} must be a JSON "
                "array of objects"
            )

        return [
            dict(value)
            for value in values
        ], True

    names = (
        PROJECT_VERSION_HREF_ENV,
        COMPONENT_VERSION_HREF_ENV,
        TAG_ENV,
        BRANCH_ENV,
    )
    supplied = {
        name: environment_value(
            environment,
            name,
        )
        for name in names
    }

    if any(supplied.values()):
        missing = [
            name
            for name, value in supplied.items()
            if not value
        ]

        if missing:
            raise ValueError(
                "Missing required CIP environment "
                "variable(s): "
                + ", ".join(missing)
            )

        return [
            {
                "project_version_href": (
                    supplied[
                        PROJECT_VERSION_HREF_ENV
                    ]
                ),
                "component_version_href": (
                    supplied[
                        COMPONENT_VERSION_HREF_ENV
                    ]
                ),
                "cip_tag": supplied[TAG_ENV],
                "cip_branch": supplied[
                    BRANCH_ENV
                ],
            }
        ], True

    values = payload.get("targets", [])

    if not isinstance(values, list):
        raise ValueError(
            "targets must be an array"
        )

    if not all(
        isinstance(value, dict)
        for value in values
    ):
        raise ValueError(
            "targets must contain objects"
        )

    return [
        dict(value)
        for value in values
    ], False


@dataclass(frozen=True)
class RepositoryConfiguration:
    location: str
    revision: str

    def validate(self) -> None:
        validate_repository_location(
            self.location
        )
        validate_revision(self.revision)

    def as_dict(self) -> dict[str, str]:
        return {
            "location": self.location,
            "revision": self.revision,
        }

    @classmethod
    def from_dict(
        cls,
        payload: dict[str, Any],
    ) -> RepositoryConfiguration:
        result = cls(
            location=str(
                payload.get("location") or ""
            ),
            revision=str(
                payload.get("revision") or ""
            ),
        )
        result.validate()
        return result


@dataclass(frozen=True)
class CipTarget:
    project_version_href: str
    component_version_href: str
    cip_tag: str
    cip_branch: str

    def validate(
        self,
        blackduck_base_url: str,
    ) -> None:
        for href in (
            self.project_version_href,
            self.component_version_href,
        ):
            if not belongs_to_instance(
                blackduck_base_url,
                href,
            ):
                raise ValueError(
                    "CIP target belongs to another "
                    "Black Duck instance"
                )

        validate_revision(self.cip_tag)
        validate_revision(self.cip_branch)

    def as_dict(self) -> dict[str, str]:
        return {
            "project_version_href": (
                self.project_version_href
            ),
            "component_version_href": (
                self.component_version_href
            ),
            "cip_tag": self.cip_tag,
            "cip_branch": self.cip_branch,
        }

    @classmethod
    def from_dict(
        cls,
        payload: dict[str, Any],
        *,
        blackduck_base_url: str = "",
    ) -> CipTarget:
        project_version_href = str(
            payload.get(
                "project_version_href"
            )
            or ""
        )
        component_version_href = str(
            payload.get(
                "component_version_href"
            )
            or ""
        )

        if blackduck_base_url:
            project_version_href = (
                blackduck_href(
                    blackduck_base_url,
                    project_version_href,
                )
            )
            component_version_href = (
                blackduck_href(
                    blackduck_base_url,
                    component_version_href,
                )
            )

        return cls(
            project_version_href=(
                project_version_href
            ),
            component_version_href=(
                component_version_href
            ),
            cip_tag=str(
                payload.get("cip_tag") or ""
            ),
            cip_branch=str(
                payload.get("cip_branch") or ""
            ),
        )


@dataclass(frozen=True)
class CipConfiguration:
    schema_version: int
    blackduck_base_url: str
    kernel_repository: RepositoryConfiguration
    security_repository: RepositoryConfiguration
    targets: tuple[CipTarget, ...]
    desired_status: str
    preserve_existing_decisions: bool
    read_workers: int
    evidence_workers: int
    plan_lifetime_hours: int
    limits: ActionLimits
    metadata: dict[str, Any]

    @property
    def digest(self) -> str:
        return stable_digest(self.as_dict())

    def validate(self) -> None:
        if (
            self.schema_version
            != CIP_CONFIGURATION_SCHEMA_VERSION
        ):
            raise ValueError(
                "Unsupported CIP configuration schema"
            )

        if (
            normalize_base_url(
                self.blackduck_base_url
            )
            != self.blackduck_base_url
        ):
            raise ValueError(
                "Black Duck URL is not normalized"
            )

        self.kernel_repository.validate()
        self.security_repository.validate()

        if not self.targets:
            raise ValueError(
                "At least one CIP target is required"
            )

        identities: set[
            tuple[str, str]
        ] = set()

        for target in self.targets:
            target.validate(
                self.blackduck_base_url
            )
            identity = (
                target.project_version_href,
                target.component_version_href,
            )

            if identity in identities:
                raise ValueError(
                    "Duplicate CIP target"
                )

            identities.add(identity)

        if not self.desired_status.strip():
            raise ValueError(
                "Desired remediation status is required"
            )

        if not 1 <= self.read_workers <= 8:
            raise ValueError(
                "read_workers must be between 1 and 8"
            )

        if not 1 <= self.evidence_workers <= 8:
            raise ValueError(
                "evidence_workers must be between 1 and 8"
            )

        if self.plan_lifetime_hours < 1:
            raise ValueError(
                "plan_lifetime_hours must be positive"
            )

        self.limits.validate()
        json_copy(self.metadata)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "blackduck_base_url": (
                self.blackduck_base_url
            ),
            "kernel_repository": (
                self.kernel_repository.as_dict()
            ),
            "security_repository": (
                self.security_repository.as_dict()
            ),
            "targets": [
                target.as_dict()
                for target in self.targets
            ],
            "remediation": {
                "desired_status": (
                    self.desired_status
                ),
                "preserve_existing_decisions": (
                    self.preserve_existing_decisions
                ),
            },
            "execution": {
                "read_workers": self.read_workers,
                "evidence_workers": (
                    self.evidence_workers
                ),
                "plan_lifetime_hours": (
                    self.plan_lifetime_hours
                ),
                "limits": self.limits.as_dict(),
            },
            "metadata": json_copy(self.metadata),
        }

    @classmethod
    def from_dict(
        cls,
        payload: dict[str, Any],
    ) -> CipConfiguration:
        remediation = payload.get(
            "remediation",
            {},
        )
        execution = payload.get(
            "execution",
            {},
        )
        raw_targets = payload.get(
            "targets",
            [],
        )
        metadata = payload.get(
            "metadata",
            {},
        )

        if not isinstance(remediation, dict):
            raise ValueError(
                "remediation must be an object"
            )

        if not isinstance(execution, dict):
            raise ValueError(
                "execution must be an object"
            )

        if not isinstance(raw_targets, list):
            raise ValueError(
                "targets must be an array"
            )

        if not isinstance(metadata, dict):
            raise ValueError(
                "metadata must be an object"
            )

        blackduck_base_url = (
            normalize_base_url(
                str(
                    payload.get(
                        "blackduck_base_url"
                    )
                    or ""
                )
            )
        )
        result = cls(
            schema_version=int(
                payload.get("schema_version") or 0
            ),
            blackduck_base_url=(
                blackduck_base_url
            ),
            kernel_repository=(
                RepositoryConfiguration.from_dict(
                    dict(
                        payload.get(
                            "kernel_repository"
                        )
                        or {}
                    )
                )
            ),
            security_repository=(
                RepositoryConfiguration.from_dict(
                    dict(
                        payload.get(
                            "security_repository"
                        )
                        or {}
                    )
                )
            ),
            targets=tuple(
                CipTarget.from_dict(
                    dict(target),
                    blackduck_base_url=(
                        blackduck_base_url
                    ),
                )
                for target in raw_targets
            ),
            desired_status=str(
                remediation.get(
                    "desired_status"
                )
                or "PATCHED"
            ).upper(),
            preserve_existing_decisions=bool(
                remediation.get(
                    "preserve_existing_decisions",
                    True,
                )
            ),
            read_workers=int(
                execution.get(
                    "read_workers",
                    2,
                )
            ),
            evidence_workers=int(
                execution.get(
                    "evidence_workers",
                    4,
                )
            ),
            plan_lifetime_hours=int(
                execution.get(
                    "plan_lifetime_hours",
                    24,
                )
            ),
            limits=ActionLimits.from_dict(
                dict(
                    execution.get("limits")
                    or {}
                )
            ),
            metadata=json_copy(metadata),
        )
        result.validate()
        return result


def read_configuration_payload(
    path: str | Path | None,
) -> dict[str, Any]:
    if not path:
        return {}

    config_path = Path(path).expanduser()

    try:
        payload = json.loads(
            config_path.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        raise ValueError(
            f"Could not read CIP configuration: "
            f"{error}"
        ) from error

    if not isinstance(payload, dict):
        raise ValueError(
            "CIP configuration must be an object"
        )

    return payload


def load_cip_configuration(
    path: str | Path | None = None,
    *,
    environment: (
        Mapping[str, str] | None
    ) = None,
) -> CipConfiguration:
    selected_environment = (
        os.environ
        if environment is None
        else environment
    )
    payload = read_configuration_payload(
        path
    )
    raw_targets, targets_from_environment = (
        configured_target_payloads(
            payload,
            selected_environment,
        )
    )

    if (
        targets_from_environment
        or not payload.get(
            "blackduck_base_url"
        )
    ):
        blackduck_url = environment_value(
            selected_environment,
            "BLACKDUCK_URL",
        )

        if not blackduck_url:
            raise ValueError(
                "BLACKDUCK_URL must be set"
            )
    else:
        blackduck_url = str(
            payload.get(
                "blackduck_base_url"
            )
            or ""
        )

    if not raw_targets:
        raise ValueError(
            "Set WINTERMUTE_CIP_TARGETS_JSON or "
            "WINTERMUTE_CIP_PROJECT_VERSION_HREF, "
            "WINTERMUTE_CIP_COMPONENT_VERSION_HREF, "
            "WINTERMUTE_CIP_TAG, and "
            "WINTERMUTE_CIP_BRANCH"
        )

    kernel_payload = dict(
        payload.get(
            "kernel_repository"
        )
        or {}
    )
    security_payload = dict(
        payload.get(
            "security_repository"
        )
        or {}
    )
    remediation_payload = dict(
        payload.get("remediation")
        or {}
    )
    execution_payload = dict(
        payload.get("execution")
        or {}
    )
    limits_payload = dict(
        execution_payload.get("limits")
        or {}
    )

    kernel_payload["location"] = (
        environment_value(
            selected_environment,
            "WINTERMUTE_CIP_KERNEL_REPOSITORY",
        )
        or kernel_payload.get("location")
        or ""
    )
    kernel_payload["revision"] = (
        environment_value(
            selected_environment,
            "WINTERMUTE_CIP_KERNEL_REVISION",
        )
        or kernel_payload.get("revision")
        or ""
    )
    security_payload["location"] = (
        environment_value(
            selected_environment,
            "WINTERMUTE_CIP_SECURITY_REPOSITORY",
        )
        or security_payload.get("location")
        or ""
    )
    security_payload["revision"] = (
        environment_value(
            selected_environment,
            "WINTERMUTE_CIP_SECURITY_REVISION",
        )
        or security_payload.get("revision")
        or ""
    )
    remediation_payload[
        "desired_status"
    ] = (
        environment_value(
            selected_environment,
            "WINTERMUTE_CIP_DESIRED_STATUS",
        )
        or remediation_payload.get(
            "desired_status"
        )
        or "PATCHED"
    )
    remediation_payload[
        "preserve_existing_decisions"
    ] = environment_boolean(
        selected_environment,
        (
            "WINTERMUTE_CIP_"
            "PRESERVE_EXISTING_DECISIONS"
        ),
        bool(
            remediation_payload.get(
                "preserve_existing_decisions",
                True,
            )
        ),
    )
    execution_payload["read_workers"] = (
        environment_integer(
            selected_environment,
            "WINTERMUTE_CIP_READ_WORKERS",
            int(
                execution_payload.get(
                    "read_workers",
                    2,
                )
            ),
        )
    )
    execution_payload[
        "evidence_workers"
    ] = environment_integer(
        selected_environment,
        "WINTERMUTE_CIP_EVIDENCE_WORKERS",
        int(
            execution_payload.get(
                "evidence_workers",
                4,
            )
        ),
    )
    execution_payload[
        "plan_lifetime_hours"
    ] = environment_integer(
        selected_environment,
        (
            "WINTERMUTE_CIP_"
            "PLAN_LIFETIME_HOURS"
        ),
        int(
            execution_payload.get(
                "plan_lifetime_hours",
                24,
            )
        ),
    )

    for environment_name, field, default in (
        (
            "WINTERMUTE_CIP_MAX_ACTIONS",
            "maximum_actions",
            10,
        ),
        (
            "WINTERMUTE_CIP_MAX_BLACKDUCK_READS",
            "maximum_blackduck_reads",
            500,
        ),
        (
            "WINTERMUTE_CIP_MAX_BLACKDUCK_WRITES",
            "maximum_blackduck_writes",
            10,
        ),
    ):
        limits_payload[field] = (
            environment_integer(
                selected_environment,
                environment_name,
                int(
                    limits_payload.get(
                        field,
                        default,
                    )
                ),
            )
        )

    execution_payload["limits"] = (
        limits_payload
    )
    merged = {
        "schema_version": int(
            payload.get(
                "schema_version",
                CIP_CONFIGURATION_SCHEMA_VERSION,
            )
        ),
        "blackduck_base_url": (
            normalize_base_url(
                blackduck_url
            )
        ),
        "kernel_repository": (
            kernel_payload
        ),
        "security_repository": (
            security_payload
        ),
        "targets": raw_targets,
        "remediation": (
            remediation_payload
        ),
        "execution": execution_payload,
        "metadata": dict(
            payload.get("metadata") or {}
        ),
    }

    return CipConfiguration.from_dict(merged)
