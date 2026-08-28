from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any
from urllib.parse import urlsplit


ACTION_PLAN_SCHEMA_VERSION = 1
_SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_KIND_RE = re.compile(
    r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$"
)
_NAME_RE = re.compile(r"[^a-z0-9-]+")


def json_copy(value: Any) -> Any:
    try:
        return json.loads(
            json.dumps(
                value,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    except (TypeError, ValueError) as error:
        raise ValueError(
            "Value must be JSON serializable"
        ) from error


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def stable_digest(value: Any) -> str:
    return (
        "sha256:"
        + sha256(canonical_json(value)).hexdigest()
    )


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(
        microsecond=0
    )


def utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError(
            f"Invalid timestamp: {value!r}"
        ) from error

    if parsed.tzinfo is None:
        raise ValueError(
            "Timestamp must include a timezone"
        )

    return parsed.astimezone(timezone.utc)


def normalize_base_url(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())

    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "Black Duck base URL must be an absolute "
            "HTTP(S) URL"
        )

    return (
        f"{parsed.scheme.lower()}://"
        f"{parsed.netloc.lower()}"
        f"{parsed.path.rstrip('/')}"
    )


def belongs_to_instance(
    base_url: str,
    resource_url: str,
) -> bool:
    base = urlsplit(normalize_base_url(base_url))
    resource = urlsplit(
        str(resource_url or "").strip()
    )

    return (
        resource.scheme.lower() == base.scheme.lower()
        and resource.netloc.lower() == base.netloc.lower()
        and not resource.username
        and not resource.password
        and not resource.fragment
    )


def normalize_name(value: str) -> str:
    normalized = _NAME_RE.sub(
        "-",
        str(value or "").strip().lower(),
    ).strip("-")

    if not normalized:
        raise ValueError("Name cannot be empty")

    return normalized


@dataclass(frozen=True)
class ActionTarget:
    resource_type: str
    resource_href: str
    project_version_href: str
    identifiers: dict[str, str]

    def validate(self, base_url: str) -> None:
        if not self.resource_type.strip():
            raise ValueError(
                "Target resource type is required"
            )

        if not self.resource_href.strip():
            raise ValueError(
                "Target resource URL is required"
            )

        if not self.project_version_href.strip():
            raise ValueError(
                "Project-version URL is required"
            )

        for value in (
            self.resource_href,
            self.project_version_href,
        ):
            if not belongs_to_instance(
                base_url,
                value,
            ):
                raise ValueError(
                    "Target URL belongs to another "
                    "Black Duck instance"
                )

        for key, value in self.identifiers.items():
            if not str(key).strip():
                raise ValueError(
                    "Identifier key cannot be empty"
                )

            if not str(value).strip():
                raise ValueError(
                    "Identifier value cannot be empty"
                )

    def as_dict(self) -> dict[str, Any]:
        return {
            "resource_type": self.resource_type,
            "resource_href": self.resource_href,
            "project_version_href": (
                self.project_version_href
            ),
            "identifiers": dict(
                sorted(self.identifiers.items())
            ),
        }

    @classmethod
    def from_dict(
        cls,
        payload: dict[str, Any],
    ) -> ActionTarget:
        identifiers = payload.get("identifiers", {})

        if not isinstance(identifiers, dict):
            raise ValueError(
                "Target identifiers must be an object"
            )

        return cls(
            resource_type=str(
                payload.get("resource_type") or ""
            ),
            resource_href=str(
                payload.get("resource_href") or ""
            ),
            project_version_href=str(
                payload.get("project_version_href") or ""
            ),
            identifiers={
                str(key): str(value)
                for key, value in identifiers.items()
            },
        )


@dataclass(frozen=True)
class ActionEvidence:
    provider: str
    subject: str
    revision: str
    digest: str
    details: dict[str, Any]

    def validate(self) -> None:
        if not self.provider.strip():
            raise ValueError(
                "Evidence provider is required"
            )

        if not self.subject.strip():
            raise ValueError(
                "Evidence subject is required"
            )

        if not self.revision.strip():
            raise ValueError(
                "Evidence revision is required"
            )

        if not _SHA256_RE.fullmatch(self.digest):
            raise ValueError(
                "Evidence digest is invalid"
            )

        json_copy(self.details)

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "subject": self.subject,
            "revision": self.revision,
            "digest": self.digest,
            "details": json_copy(self.details),
        }

    @classmethod
    def from_dict(
        cls,
        payload: dict[str, Any],
    ) -> ActionEvidence:
        details = payload.get("details", {})

        if not isinstance(details, dict):
            raise ValueError(
                "Evidence details must be an object"
            )

        result = cls(
            provider=str(
                payload.get("provider") or ""
            ),
            subject=str(
                payload.get("subject") or ""
            ),
            revision=str(
                payload.get("revision") or ""
            ),
            digest=str(
                payload.get("digest") or ""
            ),
            details=json_copy(details),
        )
        result.validate()
        return result


@dataclass(frozen=True)
class ActionOwnership:
    producer: str
    marker: str

    def validate(self) -> None:
        if normalize_name(self.producer) != self.producer:
            raise ValueError(
                "Producer name must be normalized"
            )

        if not self.marker.strip():
            raise ValueError(
                "Ownership marker is required"
            )

        if len(self.marker) > 128:
            raise ValueError(
                "Ownership marker is too long"
            )

    def as_dict(self) -> dict[str, str]:
        return {
            "producer": self.producer,
            "marker": self.marker,
        }

    @classmethod
    def from_dict(
        cls,
        payload: dict[str, Any],
    ) -> ActionOwnership:
        result = cls(
            producer=str(
                payload.get("producer") or ""
            ),
            marker=str(
                payload.get("marker") or ""
            ),
        )
        result.validate()
        return result


@dataclass(frozen=True)
class ActionLimits:
    maximum_actions: int = 10
    maximum_blackduck_reads: int = 500
    maximum_blackduck_writes: int = 10

    def validate(self) -> None:
        values = (
            self.maximum_actions,
            self.maximum_blackduck_reads,
            self.maximum_blackduck_writes,
        )

        if any(value < 0 for value in values):
            raise ValueError(
                "Action limits cannot be negative"
            )

        if (
            self.maximum_blackduck_writes
            > self.maximum_actions
        ):
            raise ValueError(
                "Write limit cannot exceed action limit"
            )

    def as_dict(self) -> dict[str, int]:
        return {
            "maximum_actions": self.maximum_actions,
            "maximum_blackduck_reads": (
                self.maximum_blackduck_reads
            ),
            "maximum_blackduck_writes": (
                self.maximum_blackduck_writes
            ),
        }

    @classmethod
    def from_dict(
        cls,
        payload: dict[str, Any],
    ) -> ActionLimits:
        result = cls(
            maximum_actions=int(
                payload.get("maximum_actions", 10)
            ),
            maximum_blackduck_reads=int(
                payload.get(
                    "maximum_blackduck_reads",
                    500,
                )
            ),
            maximum_blackduck_writes=int(
                payload.get(
                    "maximum_blackduck_writes",
                    10,
                )
            ),
        )
        result.validate()
        return result


@dataclass(frozen=True)
class BlackDuckAction:
    action_id: str
    kind: str
    target: ActionTarget
    observed: dict[str, Any]
    observed_fingerprint: str
    desired: dict[str, Any]
    ownership: ActionOwnership
    evidence: ActionEvidence
    reason: str

    @classmethod
    def build(
        cls,
        *,
        kind: str,
        target: ActionTarget,
        observed: dict[str, Any],
        desired: dict[str, Any],
        ownership: ActionOwnership,
        evidence: ActionEvidence,
        reason: str,
    ) -> BlackDuckAction:
        observed_copy = json_copy(observed)
        desired_copy = json_copy(desired)
        observed_fingerprint = stable_digest(
            observed_copy
        )
        payload = {
            "kind": kind,
            "target": target.as_dict(),
            "observed": observed_copy,
            "observed_fingerprint": (
                observed_fingerprint
            ),
            "desired": desired_copy,
            "ownership": ownership.as_dict(),
            "evidence": evidence.as_dict(),
            "reason": reason,
        }
        result = cls(
            action_id=stable_digest(payload),
            kind=kind,
            target=target,
            observed=observed_copy,
            observed_fingerprint=(
                observed_fingerprint
            ),
            desired=desired_copy,
            ownership=ownership,
            evidence=evidence,
            reason=reason,
        )
        result.validate()
        return result

    def content(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "target": self.target.as_dict(),
            "observed": json_copy(self.observed),
            "observed_fingerprint": (
                self.observed_fingerprint
            ),
            "desired": json_copy(self.desired),
            "ownership": self.ownership.as_dict(),
            "evidence": self.evidence.as_dict(),
            "reason": self.reason,
        }

    def validate(
        self,
        base_url: str | None = None,
    ) -> None:
        if not _KIND_RE.fullmatch(self.kind):
            raise ValueError(
                f"Invalid action kind: {self.kind!r}"
            )

        if not _SHA256_RE.fullmatch(self.action_id):
            raise ValueError("Invalid action ID")

        if not _SHA256_RE.fullmatch(
            self.observed_fingerprint
        ):
            raise ValueError(
                "Invalid observed-state fingerprint"
            )

        if (
            stable_digest(self.observed)
            != self.observed_fingerprint
        ):
            raise ValueError(
                "Observed-state fingerprint changed"
            )

        if not self.desired:
            raise ValueError(
                "Desired state cannot be empty"
            )

        if not self.reason.strip():
            raise ValueError(
                "Action reason is required"
            )

        self.ownership.validate()
        self.evidence.validate()
        json_copy(self.observed)
        json_copy(self.desired)

        if base_url is not None:
            self.target.validate(base_url)

        if stable_digest(self.content()) != self.action_id:
            raise ValueError(
                "Action ID does not match content"
            )

    def as_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            **self.content(),
        }

    @classmethod
    def from_dict(
        cls,
        payload: dict[str, Any],
    ) -> BlackDuckAction:
        observed = payload.get("observed", {})
        desired = payload.get("desired", {})

        if not isinstance(observed, dict):
            raise ValueError(
                "Observed state must be an object"
            )

        if not isinstance(desired, dict):
            raise ValueError(
                "Desired state must be an object"
            )

        result = cls(
            action_id=str(
                payload.get("action_id") or ""
            ),
            kind=str(payload.get("kind") or ""),
            target=ActionTarget.from_dict(
                dict(payload.get("target") or {})
            ),
            observed=json_copy(observed),
            observed_fingerprint=str(
                payload.get(
                    "observed_fingerprint"
                )
                or ""
            ),
            desired=json_copy(desired),
            ownership=ActionOwnership.from_dict(
                dict(payload.get("ownership") or {})
            ),
            evidence=ActionEvidence.from_dict(
                dict(payload.get("evidence") or {})
            ),
            reason=str(
                payload.get("reason") or ""
            ),
        )
        result.validate()
        return result


@dataclass(frozen=True)
class ActionPlan:
    schema_version: int
    plan_id: str
    producer: str
    producer_version: str
    blackduck_base_url: str
    created_at: str
    expires_at: str
    limits: ActionLimits
    actions: tuple[BlackDuckAction, ...]
    metadata: dict[str, Any]

    @classmethod
    def create(
        cls,
        *,
        producer: str,
        producer_version: str,
        blackduck_base_url: str,
        actions: tuple[BlackDuckAction, ...],
        limits: ActionLimits | None = None,
        metadata: dict[str, Any] | None = None,
        created_at: datetime | None = None,
        expires_in_hours: int = 24,
    ) -> ActionPlan:
        if expires_in_hours < 1:
            raise ValueError(
                "Plan lifetime must be at least one hour"
            )

        created = created_at or utc_now()

        if created.tzinfo is None:
            created = created.replace(
                tzinfo=timezone.utc
            )

        created = created.astimezone(timezone.utc)
        producer_name = normalize_name(producer)
        selected_limits = limits or ActionLimits()
        normalized_url = normalize_base_url(
            blackduck_base_url
        )
        metadata_copy = json_copy(metadata or {})
        expires = created + timedelta(
            hours=expires_in_hours
        )
        body = {
            "schema_version": (
                ACTION_PLAN_SCHEMA_VERSION
            ),
            "producer": producer_name,
            "producer_version": producer_version,
            "blackduck_base_url": normalized_url,
            "created_at": utc_text(created),
            "expires_at": utc_text(expires),
            "limits": selected_limits.as_dict(),
            "actions": [
                action.as_dict()
                for action in actions
            ],
            "metadata": metadata_copy,
        }
        plan_id = (
            f"{created.strftime('%Y%m%dT%H%M%SZ')}-"
            f"{producer_name}-"
            f"{stable_digest(body)[7:19]}"
        )
        result = cls(
            schema_version=(
                ACTION_PLAN_SCHEMA_VERSION
            ),
            plan_id=plan_id,
            producer=producer_name,
            producer_version=producer_version,
            blackduck_base_url=normalized_url,
            created_at=utc_text(created),
            expires_at=utc_text(expires),
            limits=selected_limits,
            actions=tuple(actions),
            metadata=metadata_copy,
        )
        result.validate()
        return result

    def content(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "producer": self.producer,
            "producer_version": self.producer_version,
            "blackduck_base_url": (
                self.blackduck_base_url
            ),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "limits": self.limits.as_dict(),
            "actions": [
                action.as_dict()
                for action in self.actions
            ],
            "metadata": json_copy(self.metadata),
        }

    def expected_plan_id(self) -> str:
        created = parse_utc(self.created_at)

        return (
            f"{created.strftime('%Y%m%dT%H%M%SZ')}-"
            f"{self.producer}-"
            f"{stable_digest(self.content())[7:19]}"
        )

    @property
    def digest(self) -> str:
        return stable_digest(self.as_dict())

    def validate(self) -> None:
        if (
            self.schema_version
            != ACTION_PLAN_SCHEMA_VERSION
        ):
            raise ValueError(
                "Unsupported action-plan schema"
            )

        if normalize_name(self.producer) != self.producer:
            raise ValueError(
                "Producer name must be normalized"
            )

        if not self.producer_version.strip():
            raise ValueError(
                "Producer version is required"
            )

        if (
            normalize_base_url(
                self.blackduck_base_url
            )
            != self.blackduck_base_url
        ):
            raise ValueError(
                "Black Duck base URL is not normalized"
            )

        created = parse_utc(self.created_at)
        expires = parse_utc(self.expires_at)

        if expires <= created:
            raise ValueError(
                "Plan expiration is invalid"
            )

        self.limits.validate()
        json_copy(self.metadata)

        if len(self.actions) > (
            self.limits.maximum_actions
        ):
            raise ValueError(
                "Action count exceeds plan limit"
            )

        action_ids: set[str] = set()

        for action in self.actions:
            action.validate(
                self.blackduck_base_url
            )

            if action.action_id in action_ids:
                raise ValueError(
                    "Plan contains duplicate actions"
                )

            action_ids.add(action.action_id)

        if self.plan_id != self.expected_plan_id():
            raise ValueError(
                "Plan ID does not match content"
            )

    def assert_not_expired(
        self,
        current_time: datetime | None = None,
    ) -> None:
        current = current_time or utc_now()

        if current.tzinfo is None:
            current = current.replace(
                tzinfo=timezone.utc
            )

        if (
            current.astimezone(timezone.utc)
            >= parse_utc(self.expires_at)
        ):
            raise ValueError(
                f"Action plan expired at "
                f"{self.expires_at}"
            )

    def as_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            **self.content(),
        }

    @classmethod
    def from_dict(
        cls,
        payload: dict[str, Any],
    ) -> ActionPlan:
        raw_actions = payload.get("actions", [])
        metadata = payload.get("metadata", {})

        if not isinstance(raw_actions, list):
            raise ValueError(
                "Plan actions must be an array"
            )

        if not isinstance(metadata, dict):
            raise ValueError(
                "Plan metadata must be an object"
            )

        result = cls(
            schema_version=int(
                payload.get("schema_version") or 0
            ),
            plan_id=str(
                payload.get("plan_id") or ""
            ),
            producer=str(
                payload.get("producer") or ""
            ),
            producer_version=str(
                payload.get("producer_version") or ""
            ),
            blackduck_base_url=str(
                payload.get(
                    "blackduck_base_url"
                )
                or ""
            ),
            created_at=str(
                payload.get("created_at") or ""
            ),
            expires_at=str(
                payload.get("expires_at") or ""
            ),
            limits=ActionLimits.from_dict(
                dict(payload.get("limits") or {})
            ),
            actions=tuple(
                BlackDuckAction.from_dict(
                    dict(action)
                )
                for action in raw_actions
            ),
            metadata=json_copy(metadata),
        )
        result.validate()
        return result
