#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

from harness.paths import ensure_parent_dir, jira_output_path


PROJECT_VERSION_RE = re.compile(
    r"/api/projects/[0-9a-fA-F-]+/versions/[0-9a-fA-F-]+"
)

CACHE_SCHEMA_VERSION = 2

RELATION_FIELDNAMES = [
    "parent_project",
    "parent_version",
    "parent_phase",
    "parent_updated",
    "child_project",
    "child_version",
    "child_phase",
    "detection_method",
    "bom_component_name",
    "bom_component_version",
    "parent_version_href",
    "child_version_href",
    "cache_entry_status",
    "cache_reuse_reason",
    "parent_scanned_at",
    "parent_scan_error",
]


@dataclass(frozen=True)
class VersionInfo:
    project_name: str
    version_name: str
    project_href: str
    version_href: str
    phase: str = ""
    updated: str = ""
    created: str = ""

    def signature(self) -> str:
        payload = {
            "project_name": self.project_name,
            "version_name": self.version_name,
            "project_href": self.project_href,
            "version_href": self.version_href,
            "phase": self.phase,
            "updated": self.updated,
            "created": self.created,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class BlackDuckClient:
    def __init__(
            self,
            base_url: str,
            api_token: str,
            insecure: bool = False,
            ca_bundle: str | None = None,
            timeout: int = 60,
            retries: int = 2,
            retry_delay: float = 2.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.bearer_token: str | None = None
        self.timeout = timeout
        self.retries = retries
        self.retry_delay = retry_delay

        if insecure and ca_bundle:
            raise ValueError("Use either --insecure or --ca-bundle, not both.")

        if insecure:
            self.ssl_context = ssl._create_unverified_context()
        elif ca_bundle:
            self.ssl_context = ssl.create_default_context(cafile=ca_bundle)
        else:
            self.ssl_context = None

    def authenticate(self) -> None:
        url = f"{self.base_url}/api/tokens/authenticate"
        headers = {
            "Authorization": f"token {self.api_token}",
            "Accept": "application/json",
        }

        retryable_statuses = {429, 500, 502, 503, 504}

        for attempt in range(self.retries + 1):
            request = Request(url, data=b"", headers=headers, method="POST")

            try:
                with urlopen(
                        request,
                        context=self.ssl_context,
                        timeout=self.timeout,
                ) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                    self.bearer_token = payload["bearerToken"]
                    return

            except HTTPError as error:
                body = error.read().decode("utf-8", errors="replace")

                if error.code not in retryable_statuses or attempt >= self.retries:
                    raise RuntimeError(
                        f"Authentication failed: HTTP {error.code} {error.reason}\n{body}"
                    ) from error

                sleep_seconds = self.retry_delay * (attempt + 1)
                print(
                    f"Retrying authentication after HTTP {error.code}; "
                    f"attempt {attempt + 1}/{self.retries}, sleeping {sleep_seconds}s",
                    file=sys.stderr,
                )
                time.sleep(sleep_seconds)

            except (TimeoutError, URLError) as error:
                if attempt >= self.retries:
                    raise RuntimeError(
                        f"Authentication failed after {self.retries + 1} attempt(s): {error}"
                    ) from error

                sleep_seconds = self.retry_delay * (attempt + 1)
                print(
                    f"Retrying authentication after network error: {error}; "
                    f"attempt {attempt + 1}/{self.retries}, sleeping {sleep_seconds}s",
                    file=sys.stderr,
                )
                time.sleep(sleep_seconds)

        raise RuntimeError("Authentication failed unexpectedly")

    def get(self, url_or_path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.request("GET", url_or_path, params=params)

    def request(
            self,
            method: str,
            url_or_path: str,
            params: dict[str, Any] | None = None,
            body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = self._make_url(url_or_path, params)

        headers = {
            "Accept": "application/json",
        }

        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"

        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")

        retryable_statuses = {429, 500, 502, 503, 504}

        for attempt in range(self.retries + 1):
            request = Request(url, data=data, headers=headers, method=method)

            try:
                with urlopen(
                        request,
                        context=self.ssl_context,
                        timeout=self.timeout,
                ) as response:
                    text = response.read().decode("utf-8")
                    return json.loads(text) if text else {}

            except HTTPError as error:
                response_body = error.read().decode("utf-8", errors="replace")

                if error.code not in retryable_statuses or attempt >= self.retries:
                    raise RuntimeError(
                        f"{method} {url} failed: HTTP {error.code} {error.reason}\n"
                        f"{response_body[:4000]}"
                    ) from error

                sleep_seconds = self.retry_delay * (attempt + 1)
                print(
                    f"Retrying {method} {url} after HTTP {error.code}; "
                    f"attempt {attempt + 1}/{self.retries}, sleeping {sleep_seconds}s",
                    file=sys.stderr,
                )
                time.sleep(sleep_seconds)

            except (TimeoutError, URLError) as error:
                if attempt >= self.retries:
                    raise RuntimeError(
                        f"{method} {url} failed after {self.retries + 1} attempt(s): {error}"
                    ) from error

                sleep_seconds = self.retry_delay * (attempt + 1)
                print(
                    f"Retrying {method} {url} after network error: {error}; "
                    f"attempt {attempt + 1}/{self.retries}, sleeping {sleep_seconds}s",
                    file=sys.stderr,
                )
                time.sleep(sleep_seconds)

        raise RuntimeError(f"{method} {url} failed unexpectedly")

    def paged_get(
            self,
            url_or_path: str,
            params: dict[str, Any] | None = None,
            limit: int = 100,
    ) -> list[dict[str, Any]]:
        all_items: list[dict[str, Any]] = []
        offset = 0

        while True:
            page_params = dict(params or {})
            page_params["offset"] = offset
            page_params["limit"] = limit

            payload = self.get(url_or_path, params=page_params)

            if "items" not in payload:
                return [payload]

            items = payload.get("items", [])
            all_items.extend(items)

            total_count = payload.get("totalCount")

            if not items:
                break

            offset += len(items)

            if total_count is not None and offset >= total_count:
                break

            if len(items) < limit:
                break

        return all_items

    def _make_url(self, url_or_path: str, params: dict[str, Any] | None = None) -> str:
        if url_or_path.startswith("http://") or url_or_path.startswith("https://"):
            url = url_or_path
        else:
            url = f"{self.base_url}/{url_or_path.lstrip('/')}"

        if not params:
            return url

        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))

        for key, value in params.items():
            if value is not None:
                query[key] = str(value)

        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                urlencode(query),
                parsed.fragment,
            )
        )


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def canonical_href(href: str) -> str:
    parsed = urlparse(href)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))


def get_self_href(resource: dict[str, Any]) -> str | None:
    return resource.get("_meta", {}).get("href")


def get_link(resource: dict[str, Any], rel_names: tuple[str, ...]) -> str | None:
    wanted = {rel.lower() for rel in rel_names}

    for link in resource.get("_meta", {}).get("links", []):
        rel = str(link.get("rel", "")).lower()
        href = link.get("href")
        if rel in wanted and href:
            return href

    for link in resource.get("_meta", {}).get("links", []):
        rel = str(link.get("rel", "")).lower()
        href = link.get("href")
        if href and any(wanted_rel in rel for wanted_rel in wanted):
            return href

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


def extract_project_version_hrefs(raw_href: str, base_url: str) -> list[str]:
    hrefs: list[str] = []

    for match in PROJECT_VERSION_RE.finditer(raw_href):
        path = match.group(0)

        if raw_href.startswith("http://") or raw_href.startswith("https://"):
            parsed = urlparse(raw_href)
            hrefs.append(canonical_href(f"{parsed.scheme}://{parsed.netloc}{path}"))
        else:
            hrefs.append(canonical_href(f"{base_url}{path}"))

    return hrefs


def project_href_from_version_href(version_href: str) -> str | None:
    match = re.search(
        r"(.*/api/projects/[0-9a-fA-F-]+)/versions/[0-9a-fA-F-]+",
        version_href,
    )
    return canonical_href(match.group(1)) if match else None


def version_name(version: dict[str, Any]) -> str:
    return str(version.get("versionName") or version.get("name") or "")


def first_value_by_key(value: Any, keys: list[str]) -> Any:
    wanted = {key.lower() for key in keys}

    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in wanted and item not in (None, ""):
                return item

        for item in value.values():
            found = first_value_by_key(item, keys)
            if found not in (None, ""):
                return found

    elif isinstance(value, list):
        for item in value:
            found = first_value_by_key(item, keys)
            if found not in (None, ""):
                return found

    return None


def extract_updated_timestamp(version: dict[str, Any]) -> str:
    value = first_value_by_key(
        version,
        [
            "updatedAt",
            "updatedDate",
            "lastUpdated",
            "lastUpdatedDate",
            "modifiedAt",
            "modifiedDate",
            "updated",
        ],
    )
    return str(value or "")


def extract_created_timestamp(version: dict[str, Any]) -> str:
    value = first_value_by_key(
        version,
        [
            "createdAt",
            "createdDate",
            "created",
        ],
    )
    return str(value or "")


def get_project_versions(client: BlackDuckClient, project: dict[str, Any]) -> list[dict[str, Any]]:
    versions_url = get_link(project, ("versions",))

    if not versions_url:
        project_href = get_self_href(project)
        if not project_href:
            return []
        versions_url = f"{project_href}/versions"

    return client.paged_get(versions_url)


def build_version_inventory(
        client: BlackDuckClient,
        project_name_contains: str | None,
        max_projects: int | None,
        debug: bool,
) -> list[VersionInfo]:
    projects = client.paged_get("/api/projects")
    inventory: list[VersionInfo] = []

    scanned_projects = 0

    for project in projects:
        project_name = str(project.get("name") or "")

        if project_name_contains:
            if project_name_contains.lower() not in project_name.lower():
                continue

        project_href = get_self_href(project)

        if not project_href:
            continue

        project_href = canonical_href(project_href)
        scanned_projects += 1

        if debug:
            print(f"Indexing project: {project_name}", file=sys.stderr)

        try:
            versions = get_project_versions(client, project)
        except RuntimeError as error:
            print(
                f"Warning: failed to read versions for project {project_name}: {error}",
                file=sys.stderr,
            )
            continue

        for version in versions:
            version_href = get_self_href(version)

            if not version_href:
                continue

            inventory.append(
                VersionInfo(
                    project_name=project_name,
                    version_name=version_name(version),
                    project_href=project_href,
                    version_href=canonical_href(version_href),
                    phase=str(version.get("phase") or ""),
                    updated=extract_updated_timestamp(version),
                    created=extract_created_timestamp(version),
                )
            )

        if max_projects is not None and scanned_projects >= max_projects:
            break

    return inventory


def build_indexes(
        inventory: list[VersionInfo],
) -> tuple[dict[str, VersionInfo], dict[tuple[str, str], list[VersionInfo]]]:
    by_href: dict[str, VersionInfo] = {}
    by_name: dict[tuple[str, str], list[VersionInfo]] = {}

    for info in inventory:
        by_href[info.version_href] = info
        by_name.setdefault((info.project_name, info.version_name), []).append(info)

    return by_href, by_name


def resolve_version_href(
        client: BlackDuckClient,
        version_href: str,
        versions_by_href: dict[str, VersionInfo],
) -> VersionInfo | None:
    version_href = canonical_href(version_href)

    if version_href in versions_by_href:
        return versions_by_href[version_href]

    project_href = project_href_from_version_href(version_href)

    if not project_href:
        return None

    try:
        project = client.get(project_href)
        version = client.get(version_href)
    except RuntimeError:
        return None

    project_name = str(project.get("name") or "")
    child_version_name = version_name(version)

    if not project_name or not child_version_name:
        return None

    return VersionInfo(
        project_name=project_name,
        version_name=child_version_name,
        project_href=project_href,
        version_href=version_href,
        phase=str(version.get("phase") or ""),
        updated=extract_updated_timestamp(version),
        created=extract_created_timestamp(version),
    )


def get_bom_components(client: BlackDuckClient, version_info: VersionInfo) -> list[dict[str, Any]]:
    components_url = f"{version_info.version_href}/components"

    try:
        return client.paged_get(components_url)
    except RuntimeError as direct_error:
        try:
            version = client.get(version_info.version_href)
            linked_components_url = get_link(
                version,
                (
                    "components",
                    "bom-components",
                    "bomComponents",
                ),
            )

            if linked_components_url:
                return client.paged_get(linked_components_url)

        except RuntimeError:
            pass

        raise direct_error


def discover_subprojects_for_version(
        client: BlackDuckClient,
        parent: VersionInfo,
        versions_by_href: dict[str, VersionInfo],
        versions_by_name: dict[tuple[str, str], list[VersionInfo]],
        resolve_bom_names: bool,
        debug: bool,
) -> list[dict[str, str]]:
    relations: list[dict[str, str]] = []
    seen_child_hrefs: set[str] = set()

    bom_components = get_bom_components(client, parent)

    for bom_item in bom_components:
        bom_component_name = str(
            first_value_by_key(bom_item, ["componentName", "name"]) or ""
        )
        bom_component_version = str(
            first_value_by_key(
                bom_item,
                ["componentVersionName", "componentVersion", "versionName"],
            )
            or ""
        )

        detected_hrefs: list[str] = []

        for raw_href in iter_hrefs(bom_item):
            detected_hrefs.extend(
                extract_project_version_hrefs(raw_href, client.base_url)
            )

        for detected_href in detected_hrefs:
            detected_href = canonical_href(detected_href)

            if detected_href == parent.version_href:
                continue

            if detected_href in seen_child_hrefs:
                continue

            child = resolve_version_href(client, detected_href, versions_by_href)

            if not child:
                continue

            seen_child_hrefs.add(child.version_href)

            relations.append(
                {
                    "parent_project": parent.project_name,
                    "parent_version": parent.version_name,
                    "parent_phase": parent.phase,
                    "parent_updated": parent.updated,
                    "child_project": child.project_name,
                    "child_version": child.version_name,
                    "child_phase": child.phase,
                    "detection_method": "api-href",
                    "bom_component_name": bom_component_name,
                    "bom_component_version": bom_component_version,
                    "parent_version_href": parent.version_href,
                    "child_version_href": child.version_href,
                }
            )

        if resolve_bom_names and bom_component_name and bom_component_version:
            matches = versions_by_name.get((bom_component_name, bom_component_version), [])

            if len(matches) > 1 and debug:
                print(
                    f"Ambiguous BOM name match for {bom_component_name} / "
                    f"{bom_component_version}: {len(matches)} project versions",
                    file=sys.stderr,
                )

            for child in matches:
                if child.version_href == parent.version_href:
                    continue

                if child.version_href in seen_child_hrefs:
                    continue

                seen_child_hrefs.add(child.version_href)

                relations.append(
                    {
                        "parent_project": parent.project_name,
                        "parent_version": parent.version_name,
                        "parent_phase": parent.phase,
                        "parent_updated": parent.updated,
                        "child_project": child.project_name,
                        "child_version": child.version_name,
                        "child_phase": child.phase,
                        "detection_method": "bom-component-name-version",
                        "bom_component_name": bom_component_name,
                        "bom_component_version": bom_component_version,
                        "parent_version_href": parent.version_href,
                        "child_version_href": child.version_href,
                    }
                )

    return relations


def relation_identity(relation: dict[str, str]) -> tuple[str, str]:
    return (
        relation.get("parent_version_href", ""),
        relation.get("child_version_href", ""),
    )


def dedupe_relations(relations: list[dict[str, str]]) -> list[dict[str, str]]:
    unique: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for relation in relations:
        key = relation_identity(relation)

        if key in seen:
            continue

        seen.add(key)
        unique.append(relation)

    return unique


def new_cache(base_url: str, resolve_bom_names: bool) -> dict[str, Any]:
    timestamp = now_iso()
    return {
        "schema_version": CACHE_SCHEMA_VERSION,
        "base_url": base_url.rstrip("/"),
        "settings": {
            "resolve_bom_names": resolve_bom_names,
        },
        "created_at": timestamp,
        "updated_at": timestamp,
        "entries": {},
    }


def load_cache(path: str, base_url: str, resolve_bom_names: bool) -> dict[str, Any]:
    if not os.path.exists(path):
        print(f"No cache found at {path}; full scan required.", file=sys.stderr)
        return new_cache(base_url, resolve_bom_names)

    try:
        with open(path, encoding="utf-8") as cache_file:
            cache = json.load(cache_file)
    except (OSError, json.JSONDecodeError) as error:
        print(
            f"Warning: failed to read cache {path}: {error}; full scan required.",
            file=sys.stderr,
        )
        return new_cache(base_url, resolve_bom_names)

    if cache.get("schema_version") != CACHE_SCHEMA_VERSION:
        print(
            f"Cache schema mismatch in {path}; full scan required.",
            file=sys.stderr,
        )
        return new_cache(base_url, resolve_bom_names)

    if str(cache.get("base_url", "")).rstrip("/") != base_url.rstrip("/"):
        print(
            f"Cache base URL differs from current Black Duck URL; full scan required.",
            file=sys.stderr,
        )
        return new_cache(base_url, resolve_bom_names)

    cached_settings = cache.get("settings", {})

    if bool(cached_settings.get("resolve_bom_names")) != resolve_bom_names:
        print(
            "Cache was created with different --resolve-bom-names setting; "
            "full scan required.",
            file=sys.stderr,
        )
        return new_cache(base_url, resolve_bom_names)

    entries = cache.get("entries")
    if not isinstance(entries, dict):
        print(
            f"Cache entries are invalid in {path}; full scan required.",
            file=sys.stderr,
        )
        return new_cache(base_url, resolve_bom_names)

    print(f"Loaded cache from {path} with {len(entries)} entries.", file=sys.stderr)
    return cache


def save_cache(path: str, cache: dict[str, Any]) -> None:
    ensure_parent_dir(path)
    cache["updated_at"] = now_iso()
    tmp_path = f"{path}.tmp"

    with open(tmp_path, "w", encoding="utf-8") as cache_file:
        json.dump(cache, cache_file, indent=2, sort_keys=True)

    os.replace(tmp_path, path)
    print(f"Wrote cache: {path}", file=sys.stderr)

def cache_entry_for_version(cache: dict[str, Any], version_info: VersionInfo) -> dict[str, Any] | None:
    entry = cache.get("entries", {}).get(version_info.version_href)
    return entry if isinstance(entry, dict) else None


def cache_age_days(entry: dict[str, Any]) -> float | None:
    scanned_at = parse_iso(str(entry.get("scanned_at") or ""))

    if not scanned_at:
        return None

    return (datetime.now(timezone.utc) - scanned_at).total_seconds() / 86400


def scan_reason_for_version(
        version_info: VersionInfo,
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

    if entry.get("signature") != version_info.signature():
        return "version-changed"

    if entry.get("status") == "failed" and refresh_failed:
        return "previous-scan-failed"

    if not version_info.updated and not trust_cache_without_update_marker:
        return "no-update-marker"

    if refresh_older_than_days >= 0:
        age = cache_age_days(entry)
        if age is None:
            return "cache-age-unknown"
        if age >= refresh_older_than_days:
            return f"cache-older-than-{refresh_older_than_days}-days"

    return None


def relation_with_cache_metadata(
        relation: dict[str, str],
        entry: dict[str, Any],
) -> dict[str, str]:
    enriched = dict(relation)
    enriched.setdefault("parent_updated", "")
    enriched["cache_entry_status"] = str(entry.get("status") or "")
    enriched["cache_reuse_reason"] = str(entry.get("reuse_reason") or "")
    enriched["parent_scanned_at"] = str(entry.get("scanned_at") or "")
    enriched["parent_scan_error"] = str(entry.get("error") or "")
    return enriched


def collect_relations_from_cache(
        cache: dict[str, Any],
        inventory: list[VersionInfo],
) -> list[dict[str, str]]:
    relations: list[dict[str, str]] = []
    entries = cache.get("entries", {})

    for version_info in inventory:
        entry = entries.get(version_info.version_href)

        if not isinstance(entry, dict):
            continue

        for relation in entry.get("relations", []):
            if isinstance(relation, dict):
                relations.append(relation_with_cache_metadata(relation, entry))

    return dedupe_relations(relations)


def plan_scan(
        cache: dict[str, Any],
        inventory: list[VersionInfo],
        refresh_all: bool,
        refresh_failed: bool,
        refresh_older_than_days: float,
        trust_cache_without_update_marker: bool,
) -> tuple[list[tuple[VersionInfo, str]], int]:
    to_scan: list[tuple[VersionInfo, str]] = []
    reused_count = 0

    for version_info in inventory:
        entry = cache_entry_for_version(cache, version_info)
        reason = scan_reason_for_version(
            version_info=version_info,
            entry=entry,
            refresh_all=refresh_all,
            refresh_failed=refresh_failed,
            refresh_older_than_days=refresh_older_than_days,
            trust_cache_without_update_marker=trust_cache_without_update_marker,
        )

        if reason:
            to_scan.append((version_info, reason))
        else:
            reused_count += 1
            if entry is not None:
                entry["reuse_reason"] = "unchanged-cache-hit"

    return to_scan, reused_count


def scan_one_parent(
        client: BlackDuckClient,
        parent: VersionInfo,
        reason: str,
        versions_by_href: dict[str, VersionInfo],
        versions_by_name: dict[tuple[str, str], list[VersionInfo]],
        resolve_bom_names: bool,
        debug: bool,
) -> tuple[VersionInfo, str, list[dict[str, str]], str | None]:
    try:
        relations = discover_subprojects_for_version(
            client=client,
            parent=parent,
            versions_by_href=versions_by_href,
            versions_by_name=versions_by_name,
            resolve_bom_names=resolve_bom_names,
            debug=debug,
        )
        return parent, reason, relations, None
    except RuntimeError as error:
        return parent, reason, [], str(error)


def scan_versions(
        client: BlackDuckClient,
        scan_plan: list[tuple[VersionInfo, str]],
        versions_by_href: dict[str, VersionInfo],
        versions_by_name: dict[tuple[str, str], list[VersionInfo]],
        resolve_bom_names: bool,
        workers: int,
        debug: bool,
) -> list[tuple[VersionInfo, str, list[dict[str, str]], str | None]]:
    if not scan_plan:
        return []

    results: list[tuple[VersionInfo, str, list[dict[str, str]], str | None]] = []

    if workers <= 1:
        for index, (parent, reason) in enumerate(scan_plan, start=1):
            if debug:
                print(
                    f"[{index}/{len(scan_plan)}] Scanning "
                    f"{parent.project_name} / {parent.version_name} ({reason})",
                    file=sys.stderr,
                )

            results.append(
                scan_one_parent(
                    client=client,
                    parent=parent,
                    reason=reason,
                    versions_by_href=versions_by_href,
                    versions_by_name=versions_by_name,
                    resolve_bom_names=resolve_bom_names,
                    debug=debug,
                )
            )

        return results

    worker_count = max(1, min(workers, 4))

    print(
        f"Scanning {len(scan_plan)} project version(s) with {worker_count} worker(s).",
        file=sys.stderr,
    )

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(
                scan_one_parent,
                client,
                parent,
                reason,
                versions_by_href,
                versions_by_name,
                resolve_bom_names,
                debug,
            ): (parent, reason)
            for parent, reason in scan_plan
        }

        for index, future in enumerate(as_completed(futures), start=1):
            parent, reason = futures[future]

            if debug:
                print(
                    f"[{index}/{len(scan_plan)}] Completed "
                    f"{parent.project_name} / {parent.version_name} ({reason})",
                    file=sys.stderr,
                )

            results.append(future.result())

    return results


def update_cache_with_scan_results(
        cache: dict[str, Any],
        results: list[tuple[VersionInfo, str, list[dict[str, str]], str | None]],
) -> None:
    entries = cache.setdefault("entries", {})

    for version_info, reason, relations, error in results:
        previous_entry = entries.get(version_info.version_href, {})

        if error:
            previous_relations = []

            if isinstance(previous_entry, dict):
                previous_relations = previous_entry.get("relations", [])
                if not isinstance(previous_relations, list):
                    previous_relations = []

            entries[version_info.version_href] = {
                "signature": version_info.signature(),
                "project_name": version_info.project_name,
                "version_name": version_info.version_name,
                "version_href": version_info.version_href,
                "project_href": version_info.project_href,
                "phase": version_info.phase,
                "updated": version_info.updated,
                "created": version_info.created,
                "status": "failed",
                "reuse_reason": reason,
                "scanned_at": now_iso(),
                "error": error,
                "relations": previous_relations,
            }

            print(
                f"Warning: failed to scan {version_info.project_name} / "
                f"{version_info.version_name}: {error}",
                file=sys.stderr,
            )
            continue

        entries[version_info.version_href] = {
            "signature": version_info.signature(),
            "project_name": version_info.project_name,
            "version_name": version_info.version_name,
            "version_href": version_info.version_href,
            "project_href": version_info.project_href,
            "phase": version_info.phase,
            "updated": version_info.updated,
            "created": version_info.created,
            "status": "ok",
            "reuse_reason": reason,
            "scanned_at": now_iso(),
            "error": "",
            "relations": relations,
        }


def prune_cache_to_current_inventory(
        cache: dict[str, Any],
        inventory: list[VersionInfo],
) -> int:
    entries = cache.setdefault("entries", {})
    current_hrefs = {version_info.version_href for version_info in inventory}
    stale_hrefs = [href for href in entries.keys() if href not in current_hrefs]

    for href in stale_hrefs:
        del entries[href]

    return len(stale_hrefs)


def write_csv(relations: list[dict[str, str]], output_path: str) -> None:
    ensure_parent_dir(output_path)

    if output_path == "-":
        output_file = sys.stdout
        close_after = False
    else:
        output_file = open(output_path, "w", newline="", encoding="utf-8")
        close_after = True

    try:
        writer = csv.DictWriter(
            output_file,
            fieldnames=RELATION_FIELDNAMES,
        )
        writer.writeheader()

        for relation in relations:
            row = {
                field: relation.get(field, "")
                for field in RELATION_FIELDNAMES
            }
            writer.writerow(row)
    finally:
        if close_after:
            output_file.close()

def write_changes_csv(
        old_relations: list[dict[str, str]],
        new_relations: list[dict[str, str]],
        output_path: str,
) -> None:
    ensure_parent_dir(output_path)

    old_by_key = {
        relation_identity(relation): relation
        for relation in old_relations
    }
    new_by_key = {
        relation_identity(relation): relation
        for relation in new_relations
    }

    old_keys = set(old_by_key)
    new_keys = set(new_by_key)
    rows: list[dict[str, str]] = []

    for key in sorted(new_keys - old_keys):
        row = dict(new_by_key[key])
        row["change_type"] = "added"
        rows.append(row)

    for key in sorted(old_keys - new_keys):
        row = dict(old_by_key[key])
        row["change_type"] = "removed"
        rows.append(row)

    fieldnames = ["change_type"] + RELATION_FIELDNAMES

    with open(output_path, "w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()

        for row in rows:
            writer.writerow(
                {
                    field: row.get(field, "")
                    for field in fieldnames
                }
            )

    print(
        f"Wrote relationship changes: {output_path} "
        f"({len(rows)} added/removed row(s))",
        file=sys.stderr,
    )

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Find Black Duck project versions whose BOM appears to contain "
            "other Black Duck project versions."
        )
    )

    parser.add_argument(
        "--bd-url",
        default=os.getenv("BLACKDUCK_URL"),
        required=os.getenv("BLACKDUCK_URL") is None,
        help="Black Duck base URL, or BLACKDUCK_URL env var.",
    )
    parser.add_argument(
        "--api-token",
        default=os.getenv("BLACKDUCK_API_TOKEN"),
        required=os.getenv("BLACKDUCK_API_TOKEN") is None,
        help="Black Duck API token, or BLACKDUCK_API_TOKEN env var.",
    )
    parser.add_argument(
        "--resolve-bom-names",
        action="store_true",
        help=(
            "Also treat BOM rows as possible project/version references when "
            "componentName/componentVersionName exactly match a Black Duck "
            "project/version."
        ),
    )
    parser.add_argument(
        "--project-name-contains",
        help="Only scan projects whose names contain this text.",
    )
    parser.add_argument(
        "--max-projects",
        type=int,
        help="Optional safety limit for testing.",
    )
    parser.add_argument(
        "--out",
        default=jira_output_path("parent_projects.csv"),
        help="Relationship CSV output path.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Write JSON instead of CSV.",
    )
    parser.add_argument(
        "--changes-out",
        default=jira_output_path("parent_project_changes.csv"),
        help="CSV path for added and removed relationship changes.",
    )
    parser.add_argument(
        "--cache",
        default=jira_output_path(
            "cache",
            "parent_projects_cache.json",
        ),
        help="Incremental project relationship cache path.",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable cache and scan all selected project versions.",
    )
    parser.add_argument(
        "--refresh-all",
        action="store_true",
        help="Ignore cached scan results and rescan all selected versions.",
    )
    parser.add_argument(
        "--refresh-older-than-days",
        type=float,
        default=7.0,
        help=(
            "Rescan cached entries older than this many days. "
            "Use -1 to disable age-based refresh."
        ),
    )
    parser.add_argument(
        "--no-refresh-failed",
        action="store_true",
        help="Do not automatically retry previously failed versions.",
    )
    parser.add_argument(
        "--trust-cache-without-update-marker",
        action="store_true",
        help=(
            "Reuse cached entries when Black Duck provides no updated "
            "timestamp."
        ),
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate validation.",
    )
    parser.add_argument(
        "--ca-bundle",
        help="PEM CA bundle used to validate the Black Duck certificate.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="HTTP timeout seconds.",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Retry count for transient failures.",
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=2.0,
        help="Base retry delay seconds.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Concurrent project-version BOM checks. Use 1-4.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print progress and debugging information.",
    )

    return parser.parse_args()

def main() -> int:
    args = parse_args()

    client = BlackDuckClient(
        base_url=args.bd_url,
        api_token=args.api_token,
        insecure=args.insecure,
        ca_bundle=args.ca_bundle,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
    )
    client.authenticate()

    if args.debug:
        print("Building project/version inventory...", file=sys.stderr)

    inventory = build_version_inventory(
        client=client,
        project_name_contains=args.project_name_contains,
        max_projects=args.max_projects,
        debug=args.debug,
    )

    versions_by_href, versions_by_name = build_indexes(inventory)

    print(
        f"Indexed {len(inventory)} project versions.",
        file=sys.stderr,
    )

    if args.no_cache:
        cache = new_cache(args.bd_url, args.resolve_bom_names)
        old_relations: list[dict[str, str]] = []
        scan_plan = [
            (version_info, "no-cache")
            for version_info in inventory
        ]
        reused_count = 0
    else:
        cache = load_cache(
            path=args.cache,
            base_url=args.bd_url,
            resolve_bom_names=args.resolve_bom_names,
        )

        old_relations = collect_relations_from_cache(cache, inventory)

        pruned_count = prune_cache_to_current_inventory(
            cache,
            inventory,
        )

        if pruned_count:
            print(
                f"Pruned {pruned_count} cache entrie(s) for project "
                f"versions not present in the current inventory.",
                file=sys.stderr,
            )

        scan_plan, reused_count = plan_scan(
            cache=cache,
            inventory=inventory,
            refresh_all=args.refresh_all,
            refresh_failed=not args.no_refresh_failed,
            refresh_older_than_days=args.refresh_older_than_days,
            trust_cache_without_update_marker=(
                args.trust_cache_without_update_marker
            ),
        )

    print(
        f"Reusing {reused_count} cached project version scan(s); "
        f"scanning {len(scan_plan)} project version(s).",
        file=sys.stderr,
    )

    scan_results = scan_versions(
        client=client,
        scan_plan=scan_plan,
        versions_by_href=versions_by_href,
        versions_by_name=versions_by_name,
        resolve_bom_names=args.resolve_bom_names,
        workers=args.workers,
        debug=args.debug,
    )

    update_cache_with_scan_results(cache, scan_results)

    relations = collect_relations_from_cache(cache, inventory)
    relations = dedupe_relations(relations)

    parent_count = len(
        {
            (
                relation["parent_project"],
                relation["parent_version"],
            )
            for relation in relations
        }
    )

    if args.json:
        if args.out == "-":
            json.dump(relations, sys.stdout, indent=2)
            print()
        else:
            ensure_parent_dir(args.out)
            with open(args.out, "w", encoding="utf-8") as output_file:
                json.dump(relations, output_file, indent=2)
    else:
        write_csv(relations, args.out)

    if args.changes_out:
        write_changes_csv(
            old_relations=old_relations,
            new_relations=relations,
            output_path=args.changes_out,
        )

    if not args.no_cache:
        save_cache(args.cache, cache)

    print(
        f"Found {parent_count} parent project versions with "
        f"{len(relations)} subproject relationship(s).",
        file=sys.stderr,
    )

    if not relations and not args.resolve_bom_names:
        print(
            "No API-href relationships found. "
            "Try again with --resolve-bom-names.",
            file=sys.stderr,
        )

    return 0

if __name__ == "__main__":
    raise SystemExit(main())