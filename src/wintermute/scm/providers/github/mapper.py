from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote, urlsplit

from wintermute.scm.models import (
    InventoryFailure,
    Repository,
    RepositoryExclusion,
    RepositoryInventory,
    normalize_language,
    normalize_provider_instance,
)


class GitHubMappingError(ValueError):
    pass


def required_string(
    value: Any,
    field: str,
) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
    ):
        raise GitHubMappingError(
            f"GitHub field {field!r} must be "
            "a nonempty string"
        )

    return value.strip()


def boolean_value(
    value: Any,
    field: str,
) -> bool:
    if type(value) is not bool:
        raise GitHubMappingError(
            f"GitHub field {field!r} must be boolean"
        )

    return value


def nonnegative_integer(
    value: Any,
    field: str,
) -> int:
    if (
        type(value) is not int
        or value < 0
    ):
        raise GitHubMappingError(
            f"GitHub field {field!r} must be "
            "a nonnegative integer"
        )

    return value


def parse_github_timestamp(
    value: Any,
    field: str,
) -> datetime | None:
    if value in (None, ""):
        return None

    text = required_string(
        value,
        field,
    )
    normalized = (
        text[:-1] + "+00:00"
        if text.endswith("Z")
        else text
    )

    try:
        parsed = datetime.fromisoformat(
            normalized
        )
    except ValueError as error:
        raise GitHubMappingError(
            f"GitHub field {field!r} has an "
            "invalid timestamp"
        ) from error

    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
    ):
        raise GitHubMappingError(
            f"GitHub field {field!r} must "
            "include a timezone"
        )

    return parsed.astimezone(timezone.utc)


def repository_parts(
    value: Any,
) -> tuple[str, str]:
    name_with_owner = required_string(
        value,
        "nameWithOwner",
    )

    if (
        name_with_owner.count("/") != 1
        or name_with_owner.startswith("/")
        or name_with_owner.endswith("/")
    ):
        raise GitHubMappingError(
            "GitHub nameWithOwner must use owner/name"
        )

    return tuple(
        name_with_owner.split("/", 1)
    )


def repository_url(
    value: Any,
    namespace: str,
    name: str,
) -> str:
    url = required_string(
        value,
        "url",
    )
    parsed = urlsplit(url)

    if (
        parsed.scheme.casefold() != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise GitHubMappingError(
            "GitHub repository URL is invalid"
        )

    actual_parts = [
        unquote(part)
        for part in parsed.path.strip("/").split("/")
        if part
    ]
    expected_parts = [
        *namespace.split("/"),
        name,
    ]

    if [
        part.casefold()
        for part in actual_parts[-len(expected_parts):]
    ] != [
        part.casefold()
        for part in expected_parts
    ]:
        raise GitHubMappingError(
            "GitHub repository URL does not match "
            "nameWithOwner"
        )

    return url


def language_evidence(
    node: dict[str, Any],
) -> tuple[
    tuple[str, ...],
    tuple[tuple[str, int], ...],
    int,
    bool,
]:
    connection = node.get("languages")

    if not isinstance(connection, dict):
        raise GitHubMappingError(
            "GitHub languages must be an object"
        )

    page_info = connection.get("pageInfo")

    if not isinstance(page_info, dict):
        raise GitHubMappingError(
            "GitHub languages.pageInfo must be an object"
        )

    has_next_page = boolean_value(
        page_info.get("hasNextPage"),
        "languages.pageInfo.hasNextPage",
    )

    if has_next_page:
        raise GitHubMappingError(
            "GitHub language metadata is truncated"
        )

    edges = connection.get("edges")

    if not isinstance(edges, list):
        raise GitHubMappingError(
            "GitHub languages.edges must be a list"
        )

    totals: dict[str, int] = {}
    edge_total = 0

    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            raise GitHubMappingError(
                f"GitHub language edge {index} "
                "must be an object"
            )

        language_node = edge.get("node")

        if not isinstance(
            language_node,
            dict,
        ):
            raise GitHubMappingError(
                f"GitHub language edge {index} "
                "has no node"
            )

        language = normalize_language(
            required_string(
                language_node.get("name"),
                f"languages.edges[{index}].node.name",
            )
        )
        size = nonnegative_integer(
            edge.get("size"),
            f"languages.edges[{index}].size",
        )
        edge_total += size
        totals[language] = (
            totals.get(language, 0)
            + size
        )

    total_size = nonnegative_integer(
        connection.get("totalSize"),
        "languages.totalSize",
    )

    if total_size != edge_total:
        raise GitHubMappingError(
            "GitHub languages.totalSize does not "
            "match language edges"
        )

    positive = {
        language: size
        for language, size in totals.items()
        if size > 0
    }

    if not positive:
        classified = ("unknown",)
    else:
        primary = min(
            positive,
            key=lambda language: (
                -positive[language],
                language,
            ),
        )
        classified = (primary,)

    return (
        classified,
        tuple(sorted(totals.items())),
        total_size,
        True,
    )


def detected_languages(
    node: dict[str, Any],
) -> tuple[str, ...]:
    return language_evidence(node)[0]

def default_branch_values(
    node: dict[str, Any],
) -> tuple[str, str]:
    branch = node.get("defaultBranchRef")

    if branch is None:
        return "", ""

    if not isinstance(branch, dict):
        raise GitHubMappingError(
            "GitHub defaultBranchRef must be "
            "an object or null"
        )

    name = required_string(
        branch.get("name"),
        "defaultBranchRef.name",
    )
    target = branch.get("target")
    head_sha = ""

    if target is not None:
        if not isinstance(target, dict):
            raise GitHubMappingError(
                "GitHub defaultBranchRef.target "
                "must be an object"
            )

        raw_sha = target.get("oid")

        if raw_sha not in (None, ""):
            head_sha = required_string(
                raw_sha,
                "defaultBranchRef.target.oid",
            ).casefold()

            if not re.fullmatch(
                r"[0-9a-f]{40}|[0-9a-f]{64}",
                head_sha,
            ):
                raise GitHubMappingError(
                    "GitHub default branch oid is invalid"
                )

    return name, head_sha


def activity_status(
    pushed_at: datetime | None,
    cutoff: datetime,
) -> str:
    if (
        cutoff.tzinfo is None
        or cutoff.utcoffset() is None
    ):
        raise ValueError(
            "Activity cutoff must include a timezone"
        )

    if pushed_at is None:
        return "inactive"

    return (
        "active"
        if pushed_at
        >= cutoff.astimezone(timezone.utc)
        else "inactive"
    )


def exclusion_reason(
    repository: Repository,
) -> str:
    if repository.archived and repository.template:
        return "archived_and_template"

    if repository.archived:
        return "archived"

    if repository.template:
        return "template"

    return ""


def map_repository(
    node: dict[str, Any],
    *,
    provider_instance: str,
    tenant_id: str,
    namespace: str,
    activity_cutoff: datetime,
) -> Repository:
    if not isinstance(node, dict):
        raise GitHubMappingError(
            "GitHub repository node must be an object"
        )

    repository_id = required_string(
        node.get("id"),
        "id",
    )
    owner, name = repository_parts(
        node.get("nameWithOwner")
    )

    if owner.casefold() != namespace.casefold():
        raise GitHubMappingError(
            "GitHub repository belongs to a "
            "different organization"
        )

    visibility = required_string(
        node.get("visibility"),
        "visibility",
    ).casefold()

    if visibility not in {
        "internal",
        "private",
        "public",
    }:
        raise GitHubMappingError(
            "GitHub visibility is invalid"
        )

    pushed = parse_github_timestamp(
        node.get("pushedAt"),
        "pushedAt",
    )
    default_branch, head_sha = (
        default_branch_values(node)
    )

    disk_usage = node.get("diskUsage")

    if disk_usage is not None:
        nonnegative_integer(
            disk_usage,
            "diskUsage",
        )

    (
        languages,
        language_bytes,
        language_total_bytes,
        language_data_complete,
    ) = language_evidence(node)

    return Repository(
        provider="github",
        provider_instance=provider_instance,
        tenant_id=tenant_id,
        repository_id=repository_id,
        namespace=owner,
        name=name,
        canonical_url=repository_url(
            node.get("url"),
            owner,
            name,
        ),
        default_branch=default_branch,
        head_sha=head_sha,
        visibility=visibility,
        archived=boolean_value(
            node.get("isArchived"),
            "isArchived",
        ),
        fork=boolean_value(
            node.get("isFork"),
            "isFork",
        ),
        template=boolean_value(
            node.get("isTemplate"),
            "isTemplate",
        ),
        pushed_at=(
            str(node.get("pushedAt") or "")
        ),
        activity_status=activity_status(
            pushed,
            activity_cutoff,
        ),
        languages=languages,
        language_bytes=language_bytes,
        language_total_bytes=(
            language_total_bytes
        ),
        language_data_complete=(
            language_data_complete
        ),
    )


def map_discovery_payload(
    payload: dict[str, Any],
    *,
    provider_instance: str,
    tenant_id: str,
    namespace: str,
    activity_cutoff: datetime,
) -> RepositoryInventory:
    if not isinstance(payload, dict):
        raise GitHubMappingError(
            "GitHub payload must be an object"
        )

    errors = payload.get("errors")

    if errors:
        raise GitHubMappingError(
            "GitHub payload contains GraphQL errors"
        )

    data = payload.get("data", payload)

    if not isinstance(data, dict):
        raise GitHubMappingError(
            "GitHub payload data must be an object"
        )

    organization = data.get("organization")

    if not isinstance(organization, dict):
        raise GitHubMappingError(
            "GitHub organization is unavailable"
        )

    connection = organization.get(
        "repositories"
    )

    if not isinstance(connection, dict):
        raise GitHubMappingError(
            "GitHub repositories must be an object"
        )

    total_count = nonnegative_integer(
        connection.get("totalCount"),
        "repositories.totalCount",
    )
    nodes = connection.get("nodes")

    if not isinstance(nodes, list):
        raise GitHubMappingError(
            "GitHub repositories.nodes must be a list"
        )

    page_info = connection.get("pageInfo")

    if not isinstance(page_info, dict):
        raise GitHubMappingError(
            "GitHub repositories.pageInfo "
            "must be an object"
        )

    if boolean_value(
        page_info.get("hasNextPage"),
        "repositories.pageInfo.hasNextPage",
    ):
        raise GitHubMappingError(
            "GitHub discovery payload is incomplete"
        )

    if len(nodes) != total_count:
        raise GitHubMappingError(
            "GitHub discovery count does not match "
            "repositories.totalCount"
        )

    selected_instance = (
        normalize_provider_instance(
            provider_instance
        )
    )
    repositories: list[Repository] = []
    exclusions: list[
        RepositoryExclusion
    ] = []
    failures: list[InventoryFailure] = []
    seen_ids: set[str] = set()
    seen_names: set[str] = set()

    for node in nodes:
        raw_id = (
            str(node.get("id") or "").strip()
            if isinstance(node, dict)
            else ""
        )
        raw_name = (
            str(
                node.get("nameWithOwner")
                or ""
            ).strip()
            if isinstance(node, dict)
            else ""
        )

        try:
            repository = map_repository(
                node,
                provider_instance=(
                    selected_instance
                ),
                tenant_id=tenant_id,
                namespace=namespace,
                activity_cutoff=(
                    activity_cutoff
                ),
            )
            normalized_name = (
                repository.name_with_owner
                .casefold()
            )

            if (
                repository.repository_id
                in seen_ids
            ):
                raise GitHubMappingError(
                    "GitHub returned a duplicate "
                    "repository ID"
                )

            if normalized_name in seen_names:
                raise GitHubMappingError(
                    "GitHub returned a duplicate "
                    "repository name"
                )

            seen_ids.add(
                repository.repository_id
            )
            seen_names.add(normalized_name)

            reason = exclusion_reason(
                repository
            )

            if reason:
                exclusions.append(
                    RepositoryExclusion(
                        repository=repository,
                        reason=reason,
                    )
                )
            else:
                repositories.append(repository)

        except (
            GitHubMappingError,
            ValueError,
        ) as error:
            failures.append(
                InventoryFailure(
                    provider="github",
                    provider_instance=(
                        selected_instance
                    ),
                    tenant_id=tenant_id,
                    repository_id=raw_id,
                    name_with_owner=raw_name,
                    stage="map-repository",
                    error=str(error),
                )
            )

    inventory = RepositoryInventory(
        repositories=tuple(
            sorted(
                repositories,
                key=lambda repository: (
                    repository
                    .name_with_owner
                    .casefold(),
                    repository.repository_id,
                ),
            )
        ),
        exclusions=tuple(
            sorted(
                exclusions,
                key=lambda exclusion: (
                    exclusion.repository
                    .name_with_owner
                    .casefold(),
                    exclusion.repository
                    .repository_id,
                ),
            )
        ),
        failures=tuple(failures),
        discovered_count=total_count,
    )

    if not inventory.reconciled:
        raise GitHubMappingError(
            "Mapped GitHub repository categories "
            "do not reconcile"
        )

    return inventory
