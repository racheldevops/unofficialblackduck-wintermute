from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

from wintermute.paths import ensure_parent_dir


CACHE_SCHEMA_VERSION = 2


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )
    except ValueError:
        return None


def new_cache(
    base_url: str,
    resolve_bom_names: bool,
) -> dict[str, Any]:
    timestamp = now_iso()

    return {
        "schema_version": CACHE_SCHEMA_VERSION,
        "base_url": base_url.rstrip("/"),
        "settings": {
            "resolve_bom_names": (
                resolve_bom_names
            ),
        },
        "created_at": timestamp,
        "updated_at": timestamp,
        "entries": {},
    }


def load_cache(
    path: str,
    base_url: str,
    resolve_bom_names: bool,
) -> dict[str, Any]:
    fresh = new_cache(
        base_url,
        resolve_bom_names,
    )

    if not os.path.exists(path):
        print(
            f"No cache found at {path}; "
            "full scan required.",
            file=sys.stderr,
        )
        return fresh

    try:
        with open(
            path,
            encoding="utf-8",
        ) as input_file:
            cache = json.load(input_file)
    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        print(
            f"Warning: failed to read cache "
            f"{path}: {error}; full scan required.",
            file=sys.stderr,
        )
        return fresh

    if not isinstance(cache, dict):
        return fresh

    if (
        cache.get("schema_version")
        != CACHE_SCHEMA_VERSION
    ):
        print(
            f"Cache schema mismatch in {path}; "
            "full scan required.",
            file=sys.stderr,
        )
        return fresh

    if (
        str(cache.get("base_url") or "").rstrip("/")
        != base_url.rstrip("/")
    ):
        print(
            "Cache base URL differs from current "
            "Black Duck URL; full scan required.",
            file=sys.stderr,
        )
        return fresh

    cached_settings = cache.get(
        "settings",
        {},
    )

    if (
        bool(
            cached_settings.get(
                "resolve_bom_names"
            )
        )
        != resolve_bom_names
    ):
        print(
            "Cache was created with a different "
            "resolve-bom-names setting; "
            "full scan required.",
            file=sys.stderr,
        )
        return fresh

    if not isinstance(
        cache.get("entries"),
        dict,
    ):
        return fresh

    return cache


def save_cache(
    path: str,
    cache: dict[str, Any],
) -> None:
    ensure_parent_dir(path)
    cache["updated_at"] = now_iso()
    temporary_path = f"{path}.tmp"

    with open(
        temporary_path,
        "w",
        encoding="utf-8",
    ) as output_file:
        json.dump(
            cache,
            output_file,
            indent=2,
            sort_keys=True,
        )

    os.replace(temporary_path, path)


def cache_entry_for_version(
    cache: dict[str, Any],
    version_info: Any,
) -> dict[str, Any] | None:
    entry = cache.get(
        "entries",
        {},
    ).get(version_info.version_href)

    return entry if isinstance(
        entry,
        dict,
    ) else None


def cache_age_days(
    entry: dict[str, Any],
) -> float | None:
    scanned_at = parse_iso(
        str(entry.get("scanned_at") or "")
    )

    if scanned_at is None:
        return None

    return (
        datetime.now(timezone.utc) - scanned_at
    ).total_seconds() / 86400


def scan_reason_for_version(
    version_info: Any,
    entry: dict[str, Any] | None,
    refresh_all: bool,
    refresh_failed: bool,
    refresh_older_than_days: float,
    trust_cache_without_update_marker: bool,
) -> str | None:
    if refresh_all:
        return "refresh-all"

    if not entry:
        return "new-version"

    if (
        entry.get("signature")
        != version_info.signature()
    ):
        return "version-changed"

    if (
        entry.get("status") == "failed"
        and refresh_failed
    ):
        return "previous-scan-failed"

    if (
        not version_info.updated
        and not trust_cache_without_update_marker
    ):
        return "no-update-marker"

    if refresh_older_than_days >= 0:
        age = cache_age_days(entry)

        if age is None:
            return "cache-age-unknown"

        if age >= refresh_older_than_days:
            return (
                f"cache-older-than-"
                f"{refresh_older_than_days}-days"
            )

    return None


def relation_identity(
    relation: dict[str, Any],
) -> tuple[str, str]:
    return (
        str(
            relation.get(
                "parent_version_href",
                "",
            )
        ),
        str(
            relation.get(
                "child_version_href",
                "",
            )
        ),
    )


def dedupe_relations(
    relations: list[dict[str, str]],
) -> list[dict[str, str]]:
    unique: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for relation in relations:
        key = relation_identity(relation)

        if key in seen:
            continue

        seen.add(key)
        unique.append(relation)

    return unique


def relation_with_cache_metadata(
    relation: dict[str, str],
    entry: dict[str, Any],
) -> dict[str, str]:
    enriched = dict(relation)
    enriched.setdefault(
        "parent_updated",
        "",
    )
    enriched["cache_entry_status"] = str(
        entry.get("status") or ""
    )
    enriched["cache_reuse_reason"] = str(
        entry.get("reuse_reason") or ""
    )
    enriched["parent_scanned_at"] = str(
        entry.get("scanned_at") or ""
    )
    enriched["parent_scan_error"] = str(
        entry.get("error") or ""
    )

    return enriched


def collect_relations_from_cache(
    cache: dict[str, Any],
    inventory: list[Any],
) -> list[dict[str, str]]:
    relations: list[dict[str, str]] = []
    entries = cache.get("entries", {})

    for version_info in inventory:
        entry = entries.get(
            version_info.version_href
        )

        if not isinstance(entry, dict):
            continue

        for relation in entry.get(
            "relations",
            [],
        ):
            if isinstance(relation, dict):
                relations.append(
                    relation_with_cache_metadata(
                        relation,
                        entry,
                    )
                )

    return dedupe_relations(relations)


def plan_scan(
    cache: dict[str, Any],
    inventory: list[Any],
    refresh_all: bool,
    refresh_failed: bool,
    refresh_older_than_days: float,
    trust_cache_without_update_marker: bool,
) -> tuple[list[tuple[Any, str]], int]:
    to_scan: list[tuple[Any, str]] = []
    reused_count = 0

    for version_info in inventory:
        entry = cache_entry_for_version(
            cache,
            version_info,
        )
        reason = scan_reason_for_version(
            version_info,
            entry,
            refresh_all,
            refresh_failed,
            refresh_older_than_days,
            trust_cache_without_update_marker,
        )

        if reason:
            to_scan.append(
                (version_info, reason)
            )
        else:
            reused_count += 1

            if entry is not None:
                entry["reuse_reason"] = (
                    "unchanged-cache-hit"
                )

    return to_scan, reused_count


def update_cache_with_scan_results(
    cache: dict[str, Any],
    results: list[
        tuple[
            Any,
            str,
            list[dict[str, str]],
            str | None,
        ]
    ],
) -> None:
    entries = cache.setdefault(
        "entries",
        {},
    )

    for (
        version_info,
        reason,
        relations,
        error,
    ) in results:
        previous = entries.get(
            version_info.version_href,
            {},
        )
        previous_relations: list[
            dict[str, str]
        ] = []

        if isinstance(previous, dict):
            stored = previous.get(
                "relations",
                [],
            )

            if isinstance(stored, list):
                previous_relations = stored

        entries[version_info.version_href] = {
            "signature": version_info.signature(),
            "project_name": (
                version_info.project_name
            ),
            "version_name": (
                version_info.version_name
            ),
            "version_href": (
                version_info.version_href
            ),
            "project_href": (
                version_info.project_href
            ),
            "phase": version_info.phase,
            "updated": version_info.updated,
            "created": version_info.created,
            "status": (
                "failed" if error else "ok"
            ),
            "reuse_reason": reason,
            "scanned_at": now_iso(),
            "error": str(error or ""),
            "relations": (
                previous_relations
                if error
                else relations
            ),
        }


def prune_cache_to_current_inventory(
    cache: dict[str, Any],
    inventory: list[Any],
) -> int:
    entries = cache.setdefault(
        "entries",
        {},
    )
    current_hrefs = {
        version_info.version_href
        for version_info in inventory
    }
    stale_hrefs = [
        href
        for href in list(entries)
        if href not in current_hrefs
    ]

    for href in stale_hrefs:
        entries.pop(href, None)

    return len(stale_hrefs)
