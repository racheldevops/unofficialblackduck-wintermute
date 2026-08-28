from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, unquote, urlsplit

from wintermute.blackduck.actions.models import (
    ActionTarget,
)
from wintermute.blackduck.collector import (
    component_version_href,
)
from wintermute.blackduck.jobs.cip.config import (
    CipTarget,
)
from wintermute.blackduck.resources import (
    canonical_href,
    get_link,
    get_self_href,
)


_CVE_RE = re.compile(
    r"\bCVE-[0-9]{4}-[0-9]{4,}\b",
    re.IGNORECASE,
)
_BDSA_RE = re.compile(
    r"\bBDSA-[0-9]{4}-[0-9]+\b",
    re.IGNORECASE,
)
_IDENTIFIER_FIELDS = {
    "name",
    "id",
    "externalid",
    "vulnerability",
    "vulnerabilityid",
    "vulnerabilityname",
    "vulnerabilityexternalid",
    "cve",
    "cveid",
    "bdsaid",
}


@dataclass(frozen=True)
class CipCandidate:
    target: CipTarget
    cve: str
    remediation_target: ActionTarget

    def as_dict(self) -> dict[str, Any]:
        return {
            "project_version_href": (
                self.target.project_version_href
            ),
            "component_version_href": (
                self.target.component_version_href
            ),
            "cip_tag": self.target.cip_tag,
            "cip_branch": self.target.cip_branch,
            "cve": self.cve,
            "remediation_target": (
                self.remediation_target.as_dict()
            ),
        }


@dataclass(frozen=True)
class TargetReadFailure:
    project_version_href: str
    component_version_href: str
    cip_tag: str
    stage: str
    error: str

    def as_dict(self) -> dict[str, str]:
        return {
            "project_version_href": (
                self.project_version_href
            ),
            "component_version_href": (
                self.component_version_href
            ),
            "cip_tag": self.cip_tag,
            "stage": self.stage,
            "error": self.error,
        }


@dataclass(frozen=True)
class TargetReadResult:
    target: CipTarget
    candidates: tuple[CipCandidate, ...]
    failures: tuple[TargetReadFailure, ...]
    start_offset: int = 0
    next_offset: int = 0
    total_count: int | None = None
    scanned_count: int = 0
    occurrence_count: int = 0
    unresolved_count: int = 0
    wrapped: bool = False

    def cursor_payload(self) -> dict[str, Any]:
        return {
            "next_offset": self.next_offset,
            "total_count": self.total_count,
            "wrapped": self.wrapped,
        }


def identifier_from_href(
    value: str,
) -> str:
    path = urlsplit(
        str(value or "")
    ).path
    marker = "/api/vulnerabilities/"

    if marker not in path:
        return ""

    suffix = path.split(
        marker,
        1,
    )[1]

    return unquote(
        suffix.split("/", 1)[0]
    ).strip().upper()


def identifiers(
    value: Any,
) -> tuple[str, ...]:
    values: set[str] = set()

    def add(value: Any) -> None:
        text = str(value or "").strip()

        values.update(
            match.upper()
            for match in _CVE_RE.findall(text)
        )
        values.update(
            match.upper()
            for match in _BDSA_RE.findall(text)
        )
        href_identifier = identifier_from_href(
            text
        )

        if href_identifier:
            values.add(href_identifier)

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            meta = item.get("_meta")

            if isinstance(meta, dict):
                add(meta.get("href"))

                for link in (
                    meta.get("links") or []
                ):
                    if isinstance(link, dict):
                        add(link.get("href"))

            for key, nested in item.items():
                if (
                    str(key).casefold()
                    in _IDENTIFIER_FIELDS
                    and isinstance(
                        nested,
                        (str, int),
                    )
                ):
                    add(nested)

                if isinstance(
                    nested,
                    (dict, list),
                ):
                    walk(nested)

        elif isinstance(item, list):
            for nested in item:
                walk(nested)

    walk(value)
    return tuple(sorted(values))


def cve_identifiers(
    value: Any,
) -> tuple[str, ...]:
    return tuple(
        identifier
        for identifier in identifiers(value)
        if _CVE_RE.fullmatch(identifier)
    )


def project_remediation_href(
    occurrence: dict[str, Any],
    project_version_href: str,
) -> tuple[str, str]:
    project = urlsplit(
        project_version_href
    )
    expected_prefix = (
        project.path.rstrip("/")
        + "/components/"
    )

    def valid(value: str) -> bool:
        parsed = urlsplit(
            str(value or "")
        )

        return (
            parsed.scheme.casefold()
            == project.scheme.casefold()
            and parsed.netloc.casefold()
            == project.netloc.casefold()
            and parsed.path.startswith(
                expected_prefix
            )
            and parsed.path.rstrip(
                "/"
            ).endswith("/remediation")
            and not parsed.query
            and not parsed.fragment
        )

    self_href = get_self_href(occurrence)

    if self_href and valid(self_href):
        return (
            canonical_href(self_href),
            "",
        )

    meta = occurrence.get("_meta")
    links = (
        meta.get("links") or []
        if isinstance(meta, dict)
        else []
    )

    for link in links:
        if not isinstance(link, dict):
            continue

        href = str(
            link.get("href") or ""
        )
        rel = str(
            link.get("rel") or ""
        ).casefold()

        if (
            rel
            in {
                "self",
                "remediation",
                "vulnerability-remediation",
            }
            and valid(href)
        ):
            return (
                canonical_href(href),
                str(
                    link.get("type")
                    or link.get("mediaType")
                    or ""
                ),
            )

    return "", ""


def target_failure(
    target: CipTarget,
    stage: str,
    error: str,
) -> TargetReadFailure:
    return TargetReadFailure(
        project_version_href=(
            target.project_version_href
        ),
        component_version_href=(
            target.component_version_href
        ),
        cip_tag=target.cip_tag,
        stage=stage,
        error=error,
    )


def collection_page(
    client: Any,
    url: str,
    *,
    offset: int,
    limit: int,
    query: str = "",
) -> tuple[
    list[dict[str, Any]],
    int | None,
]:
    params: dict[str, Any] = {
        "offset": offset,
        "limit": limit,
    }

    if query:
        params["q"] = query

    payload = client.get(
        url,
        params,
    )

    if not isinstance(payload, dict):
        raise RuntimeError(
            "Collection response is not an object"
        )

    if "items" not in payload:
        return (
            [payload] if payload else [],
            1 if payload else 0,
        )

    raw_items = payload.get("items")

    if not isinstance(raw_items, list):
        raise RuntimeError(
            "Collection items are not an array"
        )

    rows = [
        dict(value)
        for value in raw_items
        if isinstance(value, dict)
    ]
    raw_total = payload.get("totalCount")

    try:
        total = (
            int(raw_total)
            if raw_total is not None
            else None
        )
    except (
        TypeError,
        ValueError,
    ):
        total = None

    return rows, total


def vulnerable_components_url(
    project_version: dict[str, Any],
    project_version_href: str,
) -> str:
    linked = get_link(
        project_version,
        (
            "vulnerable-bom-components",
            "vulnerableBomComponents",
            "vulnerable-components",
        ),
    )

    if linked:
        return linked

    return (
        f"{canonical_href(project_version_href)}"
        "/vulnerable-bom-components"
    )


def alias_cache_key(
    base_url: str,
    identifier: str,
) -> str:
    return (
        f"{base_url.rstrip('/')}|"
        f"{identifier.upper()}"
    )


def cached_aliases(
    alias_cache: Any,
    key: str,
    *,
    max_age_seconds: float,
) -> tuple[str, ...]:
    if alias_cache is None:
        return ()

    value = alias_cache.get(
        key,
        max_age_seconds=max_age_seconds,
    )

    if not isinstance(value, list):
        return ()

    return tuple(
        sorted(
            {
                str(item).upper()
                for item in value
                if _CVE_RE.fullmatch(
                    str(item)
                )
            }
        )
    )


def store_aliases(
    alias_cache: Any,
    key: str,
    cves: tuple[str, ...],
) -> None:
    if alias_cache is None or not cves:
        return

    alias_cache.set(
        key,
        list(cves),
    )


def global_vulnerability_aliases(
    client: Any,
    identifier: str,
) -> tuple[str, ...]:
    resource = client.get(
        (
            f"{client.base_url.rstrip('/')}"
            "/api/vulnerabilities/"
            f"{quote(identifier, safe='')}"
        )
    )

    return cve_identifiers(resource)


def origin_vulnerability_aliases(
    client: Any,
    occurrence: dict[str, Any],
    identifier: str,
) -> tuple[str, ...]:
    url = get_link(
        occurrence,
        (
            "vulnerabilities",
            "vulnerability",
        ),
    )

    if not url:
        return ()

    rows, _ = collection_page(
        client,
        url,
        offset=0,
        limit=25,
        query=identifier,
    )
    cves: set[str] = set()

    for row in rows:
        row_identifiers = identifiers(row)

        if (
            identifier.upper()
            not in row_identifiers
        ):
            continue

        cves.update(
            cve_identifiers(row)
        )

    return tuple(sorted(cves))


def resolve_identifier_aliases(
    client: Any,
    occurrence: dict[str, Any],
    identifier: str,
    *,
    alias_cache: Any,
    alias_cache_max_age_seconds: float,
) -> tuple[str, ...]:
    normalized = identifier.upper()

    if _CVE_RE.fullmatch(normalized):
        return (normalized,)

    if not _BDSA_RE.fullmatch(normalized):
        return ()

    key = alias_cache_key(
        client.base_url,
        normalized,
    )
    cached = cached_aliases(
        alias_cache,
        key,
        max_age_seconds=(
            alias_cache_max_age_seconds
        ),
    )

    if cached:
        return cached

    direct_error: Exception | None = None

    try:
        cves = global_vulnerability_aliases(
            client,
            normalized,
        )
    except Exception as error:
        direct_error = error
        cves = ()

    if not cves:
        try:
            cves = (
                origin_vulnerability_aliases(
                    client,
                    occurrence,
                    normalized,
                )
            )
        except Exception as error:
            if direct_error is not None:
                raise RuntimeError(
                    f"Could not resolve {normalized}: "
                    f"{direct_error}; {error}"
                ) from error

            raise

    store_aliases(
        alias_cache,
        key,
        cves,
    )
    return cves


def resolve_occurrence_cves(
    client: Any,
    occurrence: dict[str, Any],
    *,
    alias_cache: Any = None,
    alias_cache_max_age_seconds: float = (
        7 * 24 * 3600
    ),
) -> tuple[str, ...]:
    direct = cve_identifiers(occurrence)

    if direct:
        return direct

    resolved: set[str] = set()

    for identifier in identifiers(
        occurrence
    ):
        resolved.update(
            resolve_identifier_aliases(
                client,
                occurrence,
                identifier,
                alias_cache=alias_cache,
                alias_cache_max_age_seconds=(
                    alias_cache_max_age_seconds
                ),
            )
        )

    return tuple(sorted(resolved))


def load_target_candidates(
    client: Any,
    target: CipTarget,
    *,
    start_offset: int = 0,
    page_size: int = 25,
    max_occurrences: int = 25,
    max_candidates: int = 10,
    alias_cache: Any = None,
    alias_cache_max_age_seconds: float = (
        7 * 24 * 3600
    ),
    progress_every: int = 10,
) -> TargetReadResult:
    if start_offset < 0:
        raise ValueError(
            "start_offset cannot be negative"
        )

    if page_size < 1:
        raise ValueError(
            "page_size must be positive"
        )

    if max_occurrences < 1:
        raise ValueError(
            "max_occurrences must be positive"
        )

    if max_candidates < 1:
        raise ValueError(
            "max_candidates must be positive"
        )

    if progress_every < 1:
        raise ValueError(
            "progress_every must be positive"
        )

    try:
        project_version = client.get(
            target.project_version_href
        )
    except Exception as error:
        return TargetReadResult(
            target=target,
            candidates=(),
            failures=(
                target_failure(
                    target,
                    "load-project-version",
                    str(error),
                ),
            ),
            start_offset=start_offset,
            next_offset=start_offset,
        )

    collection_url = (
        vulnerable_components_url(
            project_version,
            target.project_version_href,
        )
    )
    wanted_component = canonical_href(
        target.component_version_href
    )
    candidates: dict[
        tuple[str, str],
        CipCandidate,
    ] = {}
    offset = start_offset
    scanned_count = 0
    occurrence_count = 0
    unresolved_count = 0
    missing_remediation_count = 0
    alias_failure_count = 0
    last_alias_error = ""
    total_count: int | None = None
    wrapped = False
    stop = False

    while (
        scanned_count < max_occurrences
        and len(candidates) < max_candidates
        and not stop
    ):
        remaining = (
            max_occurrences - scanned_count
        )
        limit = min(
            page_size,
            remaining,
        )

        try:
            rows, total_count = (
                collection_page(
                    client,
                    collection_url,
                    offset=offset,
                    limit=limit,
                )
            )
        except Exception as error:
            return TargetReadResult(
                target=target,
                candidates=tuple(
                    candidates[key]
                    for key in sorted(candidates)
                ),
                failures=(
                    target_failure(
                        target,
                        "load-vulnerable-components",
                        str(error),
                    ),
                ),
                start_offset=start_offset,
                next_offset=offset,
                total_count=total_count,
                scanned_count=scanned_count,
                occurrence_count=(
                    occurrence_count
                ),
                unresolved_count=(
                    unresolved_count
                ),
            )

        if not rows:
            offset = 0
            wrapped = True
            break

        consumed = 0

        for occurrence in rows:
            consumed += 1
            scanned_count += 1

            if (
                scanned_count % progress_every
                == 0
            ):
                print(
                    "CIP target progress: "
                    f"offset={offset + consumed}, "
                    f"scanned={scanned_count}, "
                    f"candidates={len(candidates)}",
                    file=sys.stderr,
                )

            if canonical_href(
                component_version_href(
                    occurrence
                )
            ) != wanted_component:
                continue

            occurrence_count += 1
            remediation_href, media_type = (
                project_remediation_href(
                    occurrence,
                    target.project_version_href,
                )
            )

            if not remediation_href:
                missing_remediation_count += 1
                continue

            try:
                cves = resolve_occurrence_cves(
                    client,
                    occurrence,
                    alias_cache=alias_cache,
                    alias_cache_max_age_seconds=(
                        alias_cache_max_age_seconds
                    ),
                )
            except Exception as error:
                alias_failure_count += 1
                last_alias_error = str(error)
                continue

            if not cves:
                unresolved_count += 1
                continue

            bom_component_href = (
                canonical_href(
                    get_self_href(occurrence)
                )
            )

            for cve in cves:
                action_identifiers = {
                    "component_version_href": (
                        wanted_component
                    ),
                    "vulnerability": cve,
                }

                if bom_component_href:
                    action_identifiers[
                        "bom_component_href"
                    ] = bom_component_href

                if media_type:
                    action_identifiers[
                        "media_type"
                    ] = media_type

                action_target = ActionTarget(
                    resource_type=(
                        "vulnerability-remediation"
                    ),
                    resource_href=(
                        remediation_href
                    ),
                    project_version_href=(
                        canonical_href(
                            target
                            .project_version_href
                        )
                    ),
                    identifiers=(
                        action_identifiers
                    ),
                )
                key = (
                    cve,
                    remediation_href,
                )
                candidates.setdefault(
                    key,
                    CipCandidate(
                        target=target,
                        cve=cve,
                        remediation_target=(
                            action_target
                        ),
                    ),
                )

                if (
                    len(candidates)
                    >= max_candidates
                ):
                    stop = True
                    break

            if stop:
                break

        offset += consumed

        if (
            total_count is not None
            and offset >= total_count
        ):
            offset = 0
            wrapped = True
            break

        if len(rows) < limit:
            offset = 0
            wrapped = True
            break

    failures: list[
        TargetReadFailure
    ] = []

    if unresolved_count:
        failures.append(
            target_failure(
                target,
                "resolve-cve-aliases",
                f"{unresolved_count} occurrence(s) "
                "could not be resolved to a CVE",
            )
        )

    if alias_failure_count:
        failures.append(
            target_failure(
                target,
                "load-vulnerability-aliases",
                f"{alias_failure_count} alias lookup(s) "
                f"failed; last error: "
                f"{last_alias_error}",
            )
        )

    if missing_remediation_count:
        failures.append(
            target_failure(
                target,
                "find-remediation-resource",
                f"{missing_remediation_count} "
                "occurrence(s) had no project-scoped "
                "remediation resource",
            )
        )

    return TargetReadResult(
        target=target,
        candidates=tuple(
            candidates[key]
            for key in sorted(candidates)
        ),
        failures=tuple(failures),
        start_offset=start_offset,
        next_offset=offset,
        total_count=total_count,
        scanned_count=scanned_count,
        occurrence_count=occurrence_count,
        unresolved_count=unresolved_count,
        wrapped=wrapped,
    )
