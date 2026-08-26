from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from wintermute.blackduck.resources import (
    canonical_href,
)
from wintermute.scm.models import (
    required_text,
    sha256_hex,
    stable_key,
)


class MappingMethod(str, Enum):
    NONE = "none"
    PROVIDER_REPOSITORY_ID = (
        "provider-repository-id"
    )
    CANONICAL_REPOSITORY_URL = (
        "canonical-repository-url"
    )
    EXPLICIT = "explicit"
    EXACT_NAMESPACE_NAME = (
        "exact-namespace-name"
    )
    NORMALIZED_PROJECT_NAME = (
        "normalized-project-name"
    )


class MappingConfidence(str, Enum):
    AUTHORITATIVE = "authoritative"
    HIGH = "high"
    INFERRED = "inferred"
    AMBIGUOUS = "ambiguous"
    REJECTED = "rejected"


@dataclass(frozen=True)
class MappingMetadataFields:
    provider: str = "scm_provider"
    provider_instance: str = (
        "scm_provider_instance"
    )
    repository_id: str = (
        "scm_repository_id"
    )
    canonical_url: str = (
        "scm_repository_url"
    )

    def __post_init__(self) -> None:
        values = (
            self.provider,
            self.provider_instance,
            self.repository_id,
            self.canonical_url,
        )

        if any(
            not str(value or "").strip()
            for value in values
        ):
            raise ValueError(
                "Black Duck mapping metadata field "
                "names must not be empty"
            )

        if len(
            {
                str(value).casefold()
                for value in values
            }
        ) != len(values):
            raise ValueError(
                "Black Duck mapping metadata field "
                "names must be unique"
            )


@dataclass(frozen=True)
class BlackDuckVersionObservation:
    project_id: str
    version_id: str
    name: str
    href: str
    phase: str = ""
    created: str = ""
    updated: str = ""
    bom_exists: bool | None = None
    code_location_count: int | None = None
    last_successful_scan_at: str = ""
    scan_source: str = ""
    scanner_type: str = ""
    receipt_id: str = ""
    scan_evidence_complete: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "project_id",
            required_text(
                self.project_id,
                "project_id",
            ),
        )
        object.__setattr__(
            self,
            "version_id",
            required_text(
                self.version_id,
                "version_id",
            ),
        )
        object.__setattr__(
            self,
            "name",
            required_text(
                self.name,
                "version name",
            ),
        )
        object.__setattr__(
            self,
            "href",
            canonical_href(
                required_text(
                    self.href,
                    "version href",
                )
            ),
        )

        if (
            self.bom_exists is not None
            and type(self.bom_exists) is not bool
        ):
            raise ValueError(
                "bom_exists must be boolean or unknown"
            )

        if (
            self.code_location_count is not None
            and (
                type(self.code_location_count)
                is not int
                or self.code_location_count < 0
            )
        ):
            raise ValueError(
                "code_location_count must be "
                "a nonnegative integer or unknown"
            )

        if type(self.scan_evidence_complete) is not bool:
            raise ValueError(
                "scan_evidence_complete must be boolean"
            )

        for field in (
            "phase",
            "created",
            "updated",
            "last_successful_scan_at",
            "scan_source",
            "scanner_type",
            "receipt_id",
        ):
            object.__setattr__(
                self,
                field,
                str(
                    getattr(self, field)
                    or ""
                ).strip(),
            )

    @property
    def registration_exists(self) -> bool:
        return True

    @property
    def successful_scan_known(self) -> bool:
        return bool(
            self.last_successful_scan_at
            or self.receipt_id
        )

    @property
    def scan_evidence_known(self) -> bool:
        return (
            self.scan_evidence_complete
            or self.successful_scan_known
        )


@dataclass(frozen=True)
class BlackDuckProjectObservation:
    instance_url: str
    project_id: str
    name: str
    href: str
    versions: tuple[
        BlackDuckVersionObservation,
        ...
    ] = ()
    metadata: tuple[
        tuple[str, str],
        ...
    ] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "instance_url",
            canonical_href(
                required_text(
                    self.instance_url,
                    "instance_url",
                )
            ),
        )
        object.__setattr__(
            self,
            "project_id",
            required_text(
                self.project_id,
                "project_id",
            ),
        )
        object.__setattr__(
            self,
            "name",
            required_text(
                self.name,
                "project name",
            ),
        )
        object.__setattr__(
            self,
            "href",
            canonical_href(
                required_text(
                    self.href,
                    "project href",
                )
            ),
        )

        versions = tuple(
            sorted(
                self.versions,
                key=lambda value: (
                    value.name.casefold(),
                    value.version_id,
                ),
            )
        )

        if any(
            version.project_id
            != self.project_id
            for version in versions
        ):
            raise ValueError(
                "Black Duck version belongs to "
                "a different project"
            )

        if len(
            {
                version.version_id
                for version in versions
            }
        ) != len(versions):
            raise ValueError(
                "Black Duck project contains "
                "duplicate version IDs"
            )

        object.__setattr__(
            self,
            "versions",
            versions,
        )

        metadata = tuple(
            sorted(
                (
                    required_text(
                        key,
                        "metadata key",
                    ),
                    str(value or "").strip(),
                )
                for key, value
                in self.metadata
                if str(value or "").strip()
            )
        )

        if len(metadata) != len(
            {
                key
                for key, _
                in metadata
            }
        ):
            raise ValueError(
                "Black Duck project metadata "
                "contains duplicate keys"
            )

        object.__setattr__(
            self,
            "metadata",
            metadata,
        )

    def metadata_value(
        self,
        name: str,
    ) -> str:
        wanted = str(
            name or ""
        ).casefold()

        for key, value in self.metadata:
            if key.casefold() == wanted:
                return value

        return ""


@dataclass(frozen=True)
class BlackDuckObservationFailure:
    project: str
    stage: str
    error: str
    project_href: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "project",
            str(self.project or "").strip(),
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
            "project_href",
            canonical_href(
                self.project_href
            ),
        )


@dataclass(frozen=True)
class BlackDuckInventoryObservation:
    projects: tuple[
        BlackDuckProjectObservation,
        ...
    ]
    failures: tuple[
        BlackDuckObservationFailure,
        ...
    ] = ()

    def __post_init__(self) -> None:
        project_ids = [
            project.project_id
            for project in self.projects
        ]

        if len(project_ids) != len(
            set(project_ids)
        ):
            raise ValueError(
                "Black Duck inventory contains "
                "duplicate project IDs"
            )


@dataclass(frozen=True)
class ExplicitMapping:
    repository_external_id: str
    blackduck_project_id: str

    def __post_init__(self) -> None:
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
            "blackduck_project_id",
            required_text(
                self.blackduck_project_id,
                "blackduck_project_id",
            ),
        )


@dataclass(frozen=True)
class MappingProjectRef:
    project_id: str
    name: str
    href: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "project_id",
            required_text(
                self.project_id,
                "project_id",
            ),
        )
        object.__setattr__(
            self,
            "name",
            required_text(
                self.name,
                "project name",
            ),
        )
        object.__setattr__(
            self,
            "href",
            canonical_href(
                required_text(
                    self.href,
                    "project href",
                )
            ),
        )


@dataclass(frozen=True)
class RepositoryProjectMapping:
    repository_external_id: str
    name_with_owner: str
    method: MappingMethod
    confidence: MappingConfidence
    authoritative: bool
    candidates: tuple[
        MappingProjectRef,
        ...
    ] = ()
    conflicts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
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
            self.method,
            MappingMethod,
        ):
            object.__setattr__(
                self,
                "method",
                MappingMethod(str(self.method)),
            )

        if not isinstance(
            self.confidence,
            MappingConfidence,
        ):
            object.__setattr__(
                self,
                "confidence",
                MappingConfidence(
                    str(self.confidence)
                ),
            )

        candidates = tuple(
            sorted(
                self.candidates,
                key=lambda value: (
                    value.name.casefold(),
                    value.project_id,
                ),
            )
        )

        if len(candidates) != len(
            {
                candidate.project_id
                for candidate in candidates
            }
        ):
            raise ValueError(
                "Mapping contains duplicate project candidates"
            )

        object.__setattr__(
            self,
            "candidates",
            candidates,
        )
        object.__setattr__(
            self,
            "conflicts",
            tuple(
                sorted(
                    {
                        str(value).strip()
                        for value
                        in self.conflicts
                        if str(value).strip()
                    }
                )
            ),
        )

        if self.authoritative:
            if (
                self.confidence
                != MappingConfidence.AUTHORITATIVE
                or len(candidates) != 1
            ):
                raise ValueError(
                    "Authoritative mapping requires "
                    "one authoritative candidate"
                )

    @property
    def accepted_project_id(self) -> str:
        if (
            self.authoritative
            and len(self.candidates) == 1
        ):
            return (
                self.candidates[0].project_id
            )

        return ""

    @property
    def identity_key(self) -> str:
        return stable_key(
            (
                self.repository_external_id,
                self.method.value,
                self.accepted_project_id,
            )
        )

    @property
    def external_id(self) -> str:
        return sha256_hex(
            f"repository-mapping|{self.identity_key}"
        )


@dataclass(frozen=True)
class MappingResult:
    mappings: tuple[
        RepositoryProjectMapping,
        ...
    ]
    orphaned_blackduck_projects: tuple[
        MappingProjectRef,
        ...
    ] = ()

    @property
    def authoritative_count(self) -> int:
        return sum(
            mapping.authoritative
            for mapping in self.mappings
        )

    @property
    def recommendation_count(self) -> int:
        return sum(
            (
                not mapping.authoritative
                and bool(mapping.candidates)
                and mapping.confidence
                in {
                    MappingConfidence.HIGH,
                    MappingConfidence.INFERRED,
                }
            )
            for mapping in self.mappings
        )

    @property
    def conflict_count(self) -> int:
        return sum(
            mapping.confidence
            in {
                MappingConfidence.AMBIGUOUS,
                MappingConfidence.REJECTED,
            }
            for mapping in self.mappings
        )

    @property
    def unmapped_count(self) -> int:
        return sum(
            not mapping.candidates
            and not mapping.conflicts
            for mapping in self.mappings
        )


def blackduck_version_payload(
    value: BlackDuckVersionObservation,
) -> dict[str, Any]:
    return {
        "project_id": value.project_id,
        "version_id": value.version_id,
        "name": value.name,
        "href": value.href,
        "phase": value.phase,
        "created": value.created,
        "updated": value.updated,
        "registration_exists": (
            value.registration_exists
        ),
        "bom_exists": value.bom_exists,
        "code_location_count": (
            value.code_location_count
        ),
        "last_successful_scan_at": (
            value.last_successful_scan_at
        ),
        "successful_scan_known": (
            value.successful_scan_known
        ),
        "scan_source": value.scan_source,
        "scanner_type": value.scanner_type,
        "receipt_id": value.receipt_id,
        "scan_evidence_complete": (
            value.scan_evidence_complete
        ),
    }


def blackduck_project_payload(
    value: BlackDuckProjectObservation,
) -> dict[str, Any]:
    return {
        "instance_url": value.instance_url,
        "project_id": value.project_id,
        "name": value.name,
        "href": value.href,
        "metadata": {
            key: item
            for key, item
            in value.metadata
        },
        "versions": [
            blackduck_version_payload(version)
            for version in value.versions
        ],
    }


from wintermute.scm.models import Repository


class CoverageClassification(str, Enum):
    EXCLUDED = "excluded"
    NOT_ONBOARDED = "not-onboarded"
    ONBOARDED_NOT_MAPPED = (
        "onboarded-not-mapped"
    )
    MAPPED_NEVER_SCANNED = (
        "mapped-never-scanned"
    )
    SCANNED_STALE = "scanned-stale"
    SCANNED_CURRENT = "scanned-current"
    MAPPING_CONFLICT = "mapping-conflict"
    ORPHANED_REPOSITORY = (
        "orphaned-repository"
    )
    ORPHANED_BLACKDUCK_PROJECT = (
        "orphaned-blackduck-project"
    )
    PROVIDER_ERROR = "provider-error"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class RepositoryCoverage:
    repository: Repository
    eligible: bool
    onboarded: bool | None
    mapping: RepositoryProjectMapping
    classification: CoverageClassification
    blackduck_project: (
        MappingProjectRef | None
    ) = None
    exclusion_reason: str = ""
    project_version_count: int = 0
    scan_evidence_complete: bool = False
    successful_scan: bool = False
    last_successful_scan_at: str = ""
    fresh_scan: bool = False
    freshness_sla_days: int = 30
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.eligible) is not bool:
            raise ValueError(
                "eligible must be boolean"
            )

        if (
            self.onboarded is not None
            and type(self.onboarded) is not bool
        ):
            raise ValueError(
                "onboarded must be boolean or unknown"
            )

        if (
            self.mapping.repository_external_id
            != self.repository.external_id
        ):
            raise ValueError(
                "Coverage mapping belongs to a "
                "different repository"
            )

        if not isinstance(
            self.classification,
            CoverageClassification,
        ):
            object.__setattr__(
                self,
                "classification",
                CoverageClassification(
                    str(self.classification)
                ),
            )

        if (
            type(self.project_version_count)
            is not int
            or self.project_version_count < 0
        ):
            raise ValueError(
                "project_version_count must be "
                "a nonnegative integer"
            )

        if type(self.scan_evidence_complete) is not bool:
            raise ValueError(
                "scan_evidence_complete must be boolean"
            )

        if type(self.successful_scan) is not bool:
            raise ValueError(
                "successful_scan must be boolean"
            )

        if type(self.fresh_scan) is not bool:
            raise ValueError(
                "fresh_scan must be boolean"
            )

        if (
            type(self.freshness_sla_days)
            is not int
            or self.freshness_sla_days < 1
        ):
            raise ValueError(
                "freshness_sla_days must be positive"
            )

        if (
            self.fresh_scan
            and not self.successful_scan
        ):
            raise ValueError(
                "A fresh scan must also be successful"
            )

        object.__setattr__(
            self,
            "exclusion_reason",
            str(
                self.exclusion_reason or ""
            ).strip(),
        )
        object.__setattr__(
            self,
            "last_successful_scan_at",
            str(
                self.last_successful_scan_at
                or ""
            ).strip(),
        )
        object.__setattr__(
            self,
            "reasons",
            tuple(
                sorted(
                    {
                        str(reason).strip()
                        for reason in self.reasons
                        if str(reason).strip()
                    }
                )
            ),
        )


@dataclass(frozen=True)
class CoverageReport:
    repositories: tuple[
        RepositoryCoverage,
        ...
    ]
    orphaned_blackduck_projects: tuple[
        MappingProjectRef,
        ...
    ] = ()
    provider_failure_count: int = 0
    blackduck_failure_count: int = 0

    def __post_init__(self) -> None:
        identities = [
            value.repository.external_id
            for value in self.repositories
        ]

        if len(identities) != len(
            set(identities)
        ):
            raise ValueError(
                "Coverage report contains duplicate "
                "repository identities"
            )

        for field in (
            "provider_failure_count",
            "blackduck_failure_count",
        ):
            value = getattr(self, field)

            if (
                type(value) is not int
                or value < 0
            ):
                raise ValueError(
                    f"{field} must be a "
                    "nonnegative integer"
                )

    @property
    def repository_count(self) -> int:
        return len(self.repositories)

    @property
    def eligible_repository_count(self) -> int:
        return sum(
            value.eligible
            for value in self.repositories
        )
