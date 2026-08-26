from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


VISIBILITIES = {
    "internal",
    "private",
    "public",
    "unknown",
}

ACTIVITY_STATUSES = {
    "active",
    "inactive",
    "unknown",
}


def stable_key(parts: tuple[str, ...]) -> str:
    return json.dumps(
        [str(part or "") for part in parts],
        ensure_ascii=False,
        separators=(",", ":"),
    )


def sha256_hex(value: str) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def required_text(
    value: object,
    field: str,
) -> str:
    selected = str(value or "").strip()

    if not selected:
        raise ValueError(
            f"{field} must not be empty"
        )

    return selected


def normalize_provider(
    value: object,
) -> str:
    provider = required_text(
        value,
        "provider",
    ).casefold()

    if (
        not re.fullmatch(
            r"[a-z][a-z0-9_-]*",
            provider,
        )
    ):
        raise ValueError(
            "provider contains unsupported characters"
        )

    return provider


def normalize_provider_instance(
    value: object,
) -> str:
    selected = required_text(
        value,
        "provider_instance",
    )

    if any(
        character.isspace()
        for character in selected
    ):
        raise ValueError(
            "provider_instance must not contain whitespace"
        )

    if "://" in selected:
        parsed = urlsplit(selected)

        if (
            parsed.scheme.casefold() != "https"
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "provider_instance URL must be an HTTPS origin"
            )

        return parsed.netloc.casefold()

    parsed = urlsplit(f"//{selected}")

    if (
        not parsed.netloc
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError(
            "provider_instance must be a hostname "
            "with an optional port"
        )

    return parsed.netloc.casefold()


def canonical_repository_url(
    value: object,
) -> str:
    selected = required_text(
        value,
        "canonical_url",
    )
    parsed = urlsplit(selected)

    if (
        parsed.scheme.casefold() != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.path.strip("/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "canonical_url must be an HTTPS repository URL "
            "without credentials, query, or fragment"
        )

    return urlunsplit(
        (
            "https",
            parsed.netloc.casefold(),
            parsed.path.rstrip("/"),
            "",
            "",
        )
    )


def normalize_namespace(
    value: object,
) -> str:
    namespace = required_text(
        value,
        "namespace",
    ).strip("/")

    if (
        not namespace
        or any(
            not part
            for part in namespace.split("/")
        )
    ):
        raise ValueError(
            "namespace is invalid"
        )

    return namespace


def normalize_language(
    value: object,
) -> str:
    language = re.sub(
        r"\s+",
        "-",
        required_text(
            value,
            "language",
        ).casefold(),
    )

    return language


@dataclass(frozen=True)
class ScmTenant:
    provider: str
    provider_instance: str
    tenant_id: str
    namespace: str

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
            "namespace",
            normalize_namespace(
                self.namespace
            ),
        )

    @property
    def identity_key(self) -> str:
        return stable_key(
            (
                self.provider,
                self.provider_instance,
                self.tenant_id,
            )
        )

    @property
    def external_id(self) -> str:
        return sha256_hex(
            f"scm-tenant|{self.identity_key}"
        )


@dataclass(frozen=True)
class Repository:
    provider: str
    provider_instance: str
    tenant_id: str
    repository_id: str
    namespace: str
    name: str
    canonical_url: str
    default_branch: str = ""
    head_sha: str = ""
    visibility: str = "unknown"
    archived: bool = False
    fork: bool = False
    template: bool = False
    pushed_at: str = ""
    activity_status: str = "unknown"
    languages: tuple[str, ...] = ("unknown",)
    language_bytes: tuple[
        tuple[str, int],
        ...
    ] = ()
    language_total_bytes: int | None = None
    language_data_complete: bool = False

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
            "repository_id",
            required_text(
                self.repository_id,
                "repository_id",
            ),
        )
        object.__setattr__(
            self,
            "namespace",
            normalize_namespace(
                self.namespace
            ),
        )

        name = required_text(
            self.name,
            "name",
        )

        if "/" in name:
            raise ValueError(
                "name must not contain '/'"
            )

        object.__setattr__(
            self,
            "name",
            name,
        )
        object.__setattr__(
            self,
            "canonical_url",
            canonical_repository_url(
                self.canonical_url
            ),
        )
        object.__setattr__(
            self,
            "default_branch",
            str(
                self.default_branch or ""
            ).strip(),
        )

        head_sha = str(
            self.head_sha or ""
        ).strip().casefold()

        if (
            head_sha
            and not re.fullmatch(
                r"[0-9a-f]{40}|[0-9a-f]{64}",
                head_sha,
            )
        ):
            raise ValueError(
                "head_sha must be a full hexadecimal Git object ID"
            )

        object.__setattr__(
            self,
            "head_sha",
            head_sha,
        )

        visibility = str(
            self.visibility or "unknown"
        ).strip().casefold()

        if visibility not in VISIBILITIES:
            raise ValueError(
                f"Unsupported visibility: {visibility!r}"
            )

        object.__setattr__(
            self,
            "visibility",
            visibility,
        )

        for field_name in (
            "archived",
            "fork",
            "template",
        ):
            if type(
                getattr(self, field_name)
            ) is not bool:
                raise ValueError(
                    f"{field_name} must be boolean"
                )

        object.__setattr__(
            self,
            "pushed_at",
            str(
                self.pushed_at or ""
            ).strip(),
        )

        activity_status = str(
            self.activity_status or "unknown"
        ).strip().casefold()

        if (
            activity_status
            not in ACTIVITY_STATUSES
        ):
            raise ValueError(
                "activity_status must be active, "
                "inactive, or unknown"
            )

        object.__setattr__(
            self,
            "activity_status",
            activity_status,
        )

        languages = tuple(
            sorted(
                {
                    normalize_language(language)
                    for language in self.languages
                    if str(language or "").strip()
                }
            )
        )

        if not languages:
            languages = ("unknown",)

        if (
            "unknown" in languages
            and languages != ("unknown",)
        ):
            raise ValueError(
                "unknown cannot be mixed with known languages"
            )

        object.__setattr__(
            self,
            "languages",
            languages,
        )

        if not isinstance(
            self.language_bytes,
            (tuple, list),
        ):
            raise ValueError(
                "language_bytes must be a sequence"
            )

        raw_language_bytes: list[
            tuple[str, int]
        ] = []
        seen_languages: set[str] = set()

        for item in self.language_bytes:
            if (
                not isinstance(item, (tuple, list))
                or len(item) != 2
            ):
                raise ValueError(
                    "language_bytes entries must contain "
                    "language and byte count"
                )

            language = normalize_language(
                item[0]
            )
            byte_count = item[1]

            if (
                type(byte_count) is not int
                or byte_count < 0
            ):
                raise ValueError(
                    "Language byte counts must be "
                    "nonnegative integers"
                )

            if language in seen_languages:
                raise ValueError(
                    "language_bytes contains duplicate "
                    f"language {language!r}"
                )

            seen_languages.add(language)
            raw_language_bytes.append(
                (language, byte_count)
            )

        normalized_language_bytes = tuple(
            sorted(raw_language_bytes)
        )
        object.__setattr__(
            self,
            "language_bytes",
            normalized_language_bytes,
        )

        if (
            self.language_total_bytes is not None
            and (
                type(self.language_total_bytes) is not int
                or self.language_total_bytes < 0
            )
        ):
            raise ValueError(
                "language_total_bytes must be a "
                "nonnegative integer or unknown"
            )

        if type(self.language_data_complete) is not bool:
            raise ValueError(
                "language_data_complete must be boolean"
            )

        if (
            self.language_data_complete
            and self.language_total_bytes is None
        ):
            raise ValueError(
                "Complete language evidence requires "
                "language_total_bytes"
            )

        if (
            self.language_data_complete
            and sum(
                byte_count
                for _, byte_count
                in normalized_language_bytes
            )
            != self.language_total_bytes
        ):
            raise ValueError(
                "Language byte counts do not match "
                "language_total_bytes"
            )

        if (
            self.language_data_complete
            and languages != ("unknown",)
            and not set(languages).issubset(
                seen_languages
            )
        ):
            raise ValueError(
                "Classified languages are absent from "
                "complete language evidence"
            )

    @property
    def name_with_owner(self) -> str:
        return (
            f"{self.namespace}/{self.name}"
        )

    @property
    def identity_key(self) -> str:
        return stable_key(
            (
                self.provider,
                self.provider_instance,
                self.repository_id,
            )
        )

    @property
    def external_id(self) -> str:
        return sha256_hex(
            f"scm-repository|{self.identity_key}"
        )


@dataclass(frozen=True)
class RepositoryExclusion:
    repository: Repository
    reason: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "reason",
            required_text(
                self.reason,
                "reason",
            ),
        )


@dataclass(frozen=True)
class InventoryFailure:
    provider: str
    provider_instance: str
    tenant_id: str
    stage: str
    error: str
    repository_id: str = ""
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
            str(
                self.tenant_id or ""
            ).strip(),
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
            "repository_id",
            str(
                self.repository_id or ""
            ).strip(),
        )
        object.__setattr__(
            self,
            "name_with_owner",
            str(
                self.name_with_owner or ""
            ).strip(),
        )


@dataclass(frozen=True)
class RepositoryInventory:
    repositories: tuple[Repository, ...]
    exclusions: tuple[RepositoryExclusion, ...]
    failures: tuple[InventoryFailure, ...]
    discovered_count: int

    def __post_init__(self) -> None:
        if (
            type(self.discovered_count) is not int
            or self.discovered_count < 0
        ):
            raise ValueError(
                "discovered_count must be a "
                "nonnegative integer"
            )

        identities = [
            repository.external_id
            for repository in self.repositories
        ] + [
            exclusion.repository.external_id
            for exclusion in self.exclusions
        ]

        if len(identities) != len(set(identities)):
            raise ValueError(
                "Repository inventory contains "
                "duplicate repository identities"
            )

    @property
    def repository_count(self) -> int:
        return len(self.repositories)

    @property
    def exclusion_count(self) -> int:
        return len(self.exclusions)

    @property
    def failure_count(self) -> int:
        return len(self.failures)

    @property
    def categorized_count(self) -> int:
        return (
            self.repository_count
            + self.exclusion_count
            + self.failure_count
        )

    @property
    def reconciled(self) -> bool:
        return (
            self.categorized_count
            == self.discovered_count
        )
