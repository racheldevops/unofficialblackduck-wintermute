from __future__ import annotations

import hashlib
from typing import Any, Iterable
from urllib.parse import urlparse, urlunparse


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_href(value: Any) -> str:
    href = str(value or "").strip()

    if not href:
        return ""

    parsed = urlparse(href)

    if not parsed.scheme or not parsed.netloc:
        return href.rstrip("/")

    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path.rstrip("/"),
            "",
            "",
            "",
        )
    )


def get_self_href(resource: dict[str, Any]) -> str:
    return str((resource.get("_meta") or {}).get("href") or "")


def get_link(
    resource: dict[str, Any],
    rel_names: Iterable[str],
) -> str:
    wanted = {
        str(rel or "").strip().lower()
        for rel in rel_names
        if str(rel or "").strip()
    }
    links = (resource.get("_meta") or {}).get("links") or []

    for link in links:
        if not isinstance(link, dict):
            continue

        rel = str(link.get("rel") or "").lower()
        href = str(link.get("href") or "")

        if href and rel in wanted:
            return href

    for link in links:
        if not isinstance(link, dict):
            continue

        rel = str(link.get("rel") or "").lower()
        href = str(link.get("href") or "")

        if href and any(wanted_rel in rel for wanted_rel in wanted):
            return href

    return ""


def first_value_by_key(
    value: Any,
    keys: Iterable[str],
) -> Any:
    wanted = {
        str(key or "").lower()
        for key in keys
        if str(key or "")
    }

    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in wanted and item not in (None, ""):
                return item

        for item in value.values():
            found = first_value_by_key(item, wanted)

            if found not in (None, ""):
                return found

    elif isinstance(value, list):
        for item in value:
            found = first_value_by_key(item, wanted)

            if found not in (None, ""):
                return found

    return None


def iter_hrefs(value: Any) -> list[str]:
    hrefs: list[str] = []

    if isinstance(value, dict):
        for key, item in value.items():
            if key == "href" and isinstance(item, str):
                hrefs.append(item)
            else:
                hrefs.extend(iter_hrefs(item))

    elif isinstance(value, list):
        for item in value:
            hrefs.extend(iter_hrefs(item))

    return hrefs


def looks_like_resource_url(value: Any) -> bool:
    text = str(value or "").strip().lower()

    return (
        text.startswith("http://")
        or text.startswith("https://")
        or text.startswith("/api/")
    )


def to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value

    return str(value or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "y",
        "available",
        "exploit_available",
        "exploitable",
        "reachable",
        "confirmed",
        "high",
    }


def sorted_unique(values: Iterable[Any]) -> list[str]:
    return sorted(
        {
            str(value or "").strip()
            for value in values
            if str(value or "").strip()
        }
    )
