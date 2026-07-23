#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import os
import re
import shlex
import ssl
import sys
import time
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

ROLLUP_API_CACHE_SCHEMA_VERSION = 1


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass
class FailedRelationship:
    parent_project: str
    parent_version: str
    child_project: str
    child_version: str
    child_version_href: str
    source: str
    stage: str
    elapsed_seconds: float
    timeout_seconds: int
    retries: int
    attempts_per_request: int
    error: str


class ApiResponseCache:
    def __init__(
            self,
            path: str,
            base_url: str,
            max_age_hours: float,
            max_entries: int,
            debug: bool,
    ):
        self.path = path
        self.base_url = base_url.rstrip("/")
        self.max_age_hours = max_age_hours
        self.max_entries = max_entries
        self.debug = debug
        self.data: dict[str, Any] = {
            "schema_version": ROLLUP_API_CACHE_SCHEMA_VERSION,
            "base_url": self.base_url,
            "created_at": now_iso(),
            "updated_at": now_iso(),
            "settings": {
                "max_age_hours": self.max_age_hours,
                "max_entries": self.max_entries,
            },
            "entries": {},
        }

    @classmethod
    def load(
            cls,
            path: str,
            base_url: str,
            max_age_hours: float,
            refresh: bool,
            max_entries: int,
            debug: bool,
    ) -> ApiResponseCache:
        cache = cls(
            path=path,
            base_url=base_url,
            max_age_hours=max_age_hours,
            max_entries=max_entries,
            debug=debug,
        )

        if refresh:
            print(
                f"Refreshing API cache; ignoring existing cache at {path}.",
                file=sys.stderr,
            )
            return cache

        if not os.path.exists(path):
            print(
                f"No API cache found at {path}; fresh API reads required.",
                file=sys.stderr,
            )
            return cache

        try:
            with open(path, encoding="utf-8") as cache_file:
                loaded = json.load(cache_file)
        except (OSError, json.JSONDecodeError) as error:
            print(
                f"Warning: failed to read API cache {path}: {error}; "
                f"fresh API reads required.",
                file=sys.stderr,
            )
            return cache

        if loaded.get("schema_version") != ROLLUP_API_CACHE_SCHEMA_VERSION:
            print(
                f"API cache schema mismatch in {path}; fresh API reads required.",
                file=sys.stderr,
            )
            return cache

        if str(loaded.get("base_url") or "").rstrip("/") != cache.base_url:
            print(
                "API cache base URL differs from current Black Duck URL; "
                "fresh API reads required.",
                file=sys.stderr,
            )
            return cache

        entries = loaded.get("entries")
        if not isinstance(entries, dict):
            print(
                f"API cache entries are invalid in {path}; fresh API reads required.",
                file=sys.stderr,
            )
            return cache

        cache.data = loaded
        cache.prune()

        print(
            f"Loaded API cache from {path} with "
            f"{len(cache.data.get('entries', {}))} entrie(s).",
            file=sys.stderr,
        )

        return cache

    def get_items(self, source_url: str) -> list[dict[str, Any]] | None:
        entry = self._entry_for_url(source_url)

        if not entry:
            return None

        if self._is_stale(entry):
            if self.debug:
                print(
                    f"API cache stale, fetching fresh: {source_url}",
                    file=sys.stderr,
                )
            return None

        items = entry.get("items")
        if not isinstance(items, list):
            return None

        entry["last_used_at"] = now_iso()
        entry["hit_count"] = int(entry.get("hit_count") or 0) + 1

        if self.debug:
            print(
                f"Reusing API cache: {source_url} "
                f"({len(items)} cached item(s), age={self._age_label(entry)})",
                file=sys.stderr,
            )

        return copy.deepcopy(items)

    def put_items(
            self,
            source_url: str,
            items: list[dict[str, Any]],
            total_count: int | None = None,
    ) -> None:
        entries = self.data.setdefault("entries", {})
        key = self._key_for_url(source_url)
        timestamp = now_iso()

        entries[key] = {
            "source_url": source_url,
            "cached_at": timestamp,
            "last_used_at": timestamp,
            "hit_count": 0,
            "item_count": len(items),
            "total_count": total_count,
            "items": copy.deepcopy(items),
        }

        if self.debug:
            total_label = total_count if total_count is not None else "unknown"
            print(
                f"Stored API cache: {source_url} "
                f"({len(items)} item(s), totalCount={total_label})",
                file=sys.stderr,
            )

        self.prune()

    def prune(self) -> None:
        entries = self.data.setdefault("entries", {})
        stale_keys = [
            key
            for key, entry in entries.items()
            if isinstance(entry, dict) and self._is_stale(entry)
        ]

        for key in stale_keys:
            del entries[key]

        if stale_keys and self.debug:
            print(
                f"Pruned {len(stale_keys)} stale API cache entrie(s).",
                file=sys.stderr,
            )

        if len(entries) <= self.max_entries:
            return

        sortable_entries: list[tuple[str, str]] = []

        for key, entry in entries.items():
            if isinstance(entry, dict):
                last_used_at = str(
                    entry.get("last_used_at")
                    or entry.get("cached_at")
                    or ""
                )
            else:
                last_used_at = ""

            sortable_entries.append((last_used_at, key))

        sortable_entries.sort()
        remove_count = len(entries) - self.max_entries

        for _, key in sortable_entries[:remove_count]:
            entries.pop(key, None)

        if remove_count and self.debug:
            print(
                f"Pruned {remove_count} old API cache entrie(s) to enforce "
                f"--api-cache-max-entries={self.max_entries}.",
                file=sys.stderr,
            )

    def save(self) -> None:
        self.prune()
        self.data["updated_at"] = now_iso()
        self.data.setdefault("settings", {})
        self.data["settings"]["max_age_hours"] = self.max_age_hours
        self.data["settings"]["max_entries"] = self.max_entries

        tmp_path = f"{self.path}.tmp"

        with open(tmp_path, "w", encoding="utf-8") as cache_file:
            json.dump(self.data, cache_file, indent=2, sort_keys=True)

        os.replace(tmp_path, self.path)

        print(
            f"Wrote API cache: {self.path} "
            f"({len(self.data.get('entries', {}))} entrie(s))",
            file=sys.stderr,
        )

    def _entry_for_url(self, source_url: str) -> dict[str, Any] | None:
        entries = self.data.get("entries", {})
        if not isinstance(entries, dict):
            return None

        entry = entries.get(self._key_for_url(source_url))
        return entry if isinstance(entry, dict) else None

    def _is_stale(self, entry: dict[str, Any]) -> bool:
        if self.max_age_hours < 0:
            return False

        cached_at = parse_iso(str(entry.get("cached_at") or ""))

        if not cached_at:
            return True

        age_hours = (datetime.now(timezone.utc) - cached_at).total_seconds() / 3600
        return age_hours >= self.max_age_hours

    def _age_label(self, entry: dict[str, Any]) -> str:
        cached_at = parse_iso(str(entry.get("cached_at") or ""))

        if not cached_at:
            return "unknown"

        age_seconds = (datetime.now(timezone.utc) - cached_at).total_seconds()

        if age_seconds < 60:
            return f"{age_seconds:.0f}s"

        age_minutes = age_seconds / 60

        if age_minutes < 60:
            return f"{age_minutes:.1f}m"

        age_hours = age_minutes / 60
        return f"{age_hours:.1f}h"

    @staticmethod
    def _key_for_url(source_url: str) -> str:
        return hashlib.sha256(source_url.encode("utf-8")).hexdigest()


class BlackDuckClient:
    def __init__(
            self,
            base_url: str,
            api_token: str,
            insecure: bool = False,
            timeout: int = 30,
            retries: int = 1,
            retry_delay: float = 2.0,
            page_limit: int = 100,
            debug: bool = False,
            api_cache: ApiResponseCache | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.bearer_token: str | None = None
        self.ssl_context = ssl._create_unverified_context() if insecure else None
        self.timeout = timeout
        self.retries = retries
        self.retry_delay = retry_delay
        self.page_limit = page_limit
        self.debug = debug
        self.api_cache = api_cache
        self.raw_get_cache: dict[str, dict[str, Any]] = {}
        self.paged_result_cache: dict[str, list[dict[str, Any]]] = {}
        self.vulnerability_summary_cache: dict[tuple[str, str, float], list[dict[str, Any]]] = {}

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
                    text = response.read().decode("utf-8")

                try:
                    payload = json.loads(text)
                except json.JSONDecodeError as error:
                    raise RuntimeError(
                        f"Authentication returned invalid JSON: {error}"
                    ) from error

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
                    f"retry {attempt + 1}/{self.retries}, sleeping {sleep_seconds}s",
                    file=sys.stderr,
                )
                time.sleep(sleep_seconds)

            except (TimeoutError, URLError, OSError) as error:
                if attempt >= self.retries:
                    raise RuntimeError(
                        f"Authentication failed after {self.retries + 1} "
                        f"attempt(s), timeout={self.timeout}s: {error}"
                    ) from error

                sleep_seconds = self.retry_delay * (attempt + 1)
                print(
                    f"Retrying authentication after network error: {error}; "
                    f"retry {attempt + 1}/{self.retries}, sleeping {sleep_seconds}s",
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

        raw_get_cache_key = ""
        if method.upper() == "GET" and body is None:
            raw_get_cache_key = url
            cached_payload = self.raw_get_cache.get(raw_get_cache_key)

            if cached_payload is not None:
                if self.debug:
                    print(
                        f"Reusing in-run GET cache: {url}",
                        file=sys.stderr,
                    )
                return copy.deepcopy(cached_payload)

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

                if not text:
                    payload: dict[str, Any] = {}
                else:
                    try:
                        payload = json.loads(text)
                    except json.JSONDecodeError as error:
                        raise RuntimeError(
                            f"{method} {url} returned invalid JSON: {error}"
                        ) from error

                if raw_get_cache_key:
                    self.raw_get_cache[raw_get_cache_key] = copy.deepcopy(payload)

                return payload

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
                    f"retry {attempt + 1}/{self.retries}, sleeping {sleep_seconds}s",
                    file=sys.stderr,
                )
                time.sleep(sleep_seconds)

            except (TimeoutError, URLError, OSError) as error:
                if attempt >= self.retries:
                    raise RuntimeError(
                        f"{method} {url} failed after {self.retries + 1} "
                        f"attempt(s), timeout={self.timeout}s: {error}"
                    ) from error

                sleep_seconds = self.retry_delay * (attempt + 1)
                print(
                    f"Retrying {method} {url} after network error: {error}; "
                    f"retry {attempt + 1}/{self.retries}, sleeping {sleep_seconds}s",
                    file=sys.stderr,
                )
                time.sleep(sleep_seconds)

        raise RuntimeError(f"{method} {url} failed unexpectedly")

    def paged_get(
            self,
            url_or_path: str,
            params: dict[str, Any] | None = None,
            limit: int | None = None,
    ) -> list[dict[str, Any]]:
        page_limit = limit if limit is not None else self.page_limit
        cache_source_url = self._make_url(url_or_path, params)

        in_run_cached_items = self.paged_result_cache.get(cache_source_url)
        if in_run_cached_items is not None:
            if self.debug:
                print(
                    f"Reusing in-run paged cache: {cache_source_url} "
                    f"({len(in_run_cached_items)} item(s))",
                    file=sys.stderr,
                )
            return in_run_cached_items

        if self.api_cache is not None:
            cached_items = self.api_cache.get_items(cache_source_url)

            if cached_items is not None:
                self.paged_result_cache[cache_source_url] = cached_items
                return cached_items

        all_items: list[dict[str, Any]] = []
        offset = 0
        final_total_count: int | None = None

        while True:
            page_params = dict(params or {})
            page_params["offset"] = offset
            page_params["limit"] = page_limit

            if self.debug:
                print(
                    f"Fetching page offset={offset}, limit={page_limit}: "
                    f"{self._make_url(url_or_path, page_params)}",
                    file=sys.stderr,
                )

            payload = self.get(url_or_path, params=page_params)

            if "items" not in payload:
                single_payload_result = [payload]

                if self.api_cache is not None:
                    self.api_cache.put_items(
                        cache_source_url,
                        single_payload_result,
                        total_count=1,
                    )

                self.paged_result_cache[cache_source_url] = single_payload_result
                return single_payload_result

            items = payload.get("items", [])
            all_items.extend(items)

            total_count = payload.get("totalCount")
            final_total_count = int(total_count) if total_count is not None else None

            if self.debug:
                total_label = total_count if total_count is not None else "unknown"
                print(
                    f"Fetched {len(items)} item(s) from page; "
                    f"running total={len(all_items)}, totalCount={total_label}",
                    file=sys.stderr,
                )

            if not items:
                break

            offset += len(items)

            if total_count is not None and offset >= total_count:
                break

            if len(items) < page_limit:
                break

        if self.api_cache is not None:
            self.api_cache.put_items(
                cache_source_url,
                all_items,
                total_count=final_total_count,
            )

        self.paged_result_cache[cache_source_url] = all_items
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


def canonical_href(href: str) -> str:
    if not href:
        return ""

    parsed = urlparse(href)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))


def get_self_href(resource: dict[str, Any]) -> str | None:
    meta = resource.get("_meta", {})
    href = meta.get("href")
    return href


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
            hrefs.append(f"{parsed.scheme}://{parsed.netloc}{path}")
        else:
            hrefs.append(f"{base_url}{path}")

    return hrefs


def project_href_from_version_href(version_href: str) -> str | None:
    match = re.search(r"(.*/api/projects/[0-9a-fA-F-]+)/versions/[0-9a-fA-F-]+", version_href)
    return match.group(1) if match else None


def version_name(version: dict[str, Any]) -> str:
    return str(version.get("versionName") or version.get("name") or "")


def find_project(client: BlackDuckClient, project_name: str) -> dict[str, Any]:
    projects = client.paged_get("/api/projects", params={"q": f"name:{project_name}"})
    exact = [project for project in projects if project.get("name") == project_name]

    if not exact:
        raise RuntimeError(f"Could not find Black Duck project named: {project_name}")

    if len(exact) > 1:
        raise RuntimeError(f"Multiple projects matched exactly: {project_name}")

    return exact[0]


def find_project_version(
        client: BlackDuckClient,
        project_name: str,
        project_version_name: str,
) -> dict[str, Any]:
    project = find_project(client, project_name)
    versions_url = get_link(project, ("versions",))

    if not versions_url:
        project_href = get_self_href(project)
        if not project_href:
            raise RuntimeError(f"Project {project_name} has no self href")
        versions_url = f"{project_href}/versions"

    versions = client.paged_get(
        versions_url,
        params={"q": f"versionName:{project_version_name}"},
    )

    exact = [
        version
        for version in versions
        if version_name(version) == project_version_name
    ]

    if not exact:
        versions = client.paged_get(versions_url)
        exact = [
            version
            for version in versions
            if version_name(version) == project_version_name
        ]

    if not exact:
        raise RuntimeError(
            f"Could not find version {project_version_name!r} "
            f"for project {project_name!r}"
        )

    if len(exact) > 1:
        raise RuntimeError(
            f"Multiple versions matched {project_version_name!r} "
            f"for project {project_name!r}"
        )

    return exact[0]


def describe_project_version(
        client: BlackDuckClient,
        version_href: str,
        version: dict[str, Any] | None = None,
        bom_item: dict[str, Any] | None = None,
) -> tuple[str, str]:
    version = version or client.get(version_href)

    child_version_name = (
            version.get("versionName")
            or version.get("name")
            or first_value_by_key(bom_item or {}, ["componentVersionName", "versionName"])
            or ""
    )

    child_project_name = (
            version.get("projectName")
            or first_value_by_key(bom_item or {}, ["componentName", "projectName"])
            or ""
    )

    if not child_project_name:
        project_href = project_href_from_version_href(version_href)
        if project_href:
            project = client.get(project_href)
            child_project_name = project.get("name") or ""

    return str(child_project_name), str(child_version_name)


def get_bom_components(client: BlackDuckClient, project_version: dict[str, Any]) -> list[dict[str, Any]]:
    components_url = get_link(
        project_version,
        (
            "components",
            "bom-components",
            "bomComponents",
        ),
    )

    if not components_url:
        version_href = get_self_href(project_version)
        if not version_href:
            raise RuntimeError("Project version has no self href")
        components_url = f"{version_href}/components"

    return client.paged_get(components_url)


def discover_direct_subprojects(
        client: BlackDuckClient,
        project_version: dict[str, Any],
        resolve_bom_names: bool,
        debug: bool,
) -> list[dict[str, Any]]:
    parent_href = get_self_href(project_version)

    if not parent_href:
        raise RuntimeError("Parent project version has no self href")

    parent_href = canonical_href(parent_href)

    discovered: list[dict[str, Any]] = []
    seen: set[str] = set()

    for bom_item in get_bom_components(client, project_version):
        candidate_hrefs: list[str] = []

        for raw_href in iter_hrefs(bom_item):
            candidate_hrefs.extend(extract_project_version_hrefs(raw_href, client.base_url))

        for candidate_href in candidate_hrefs:
            candidate_href = canonical_href(candidate_href)

            if candidate_href == parent_href:
                continue

            if candidate_href in seen:
                continue

            try:
                child_version = client.get(candidate_href)
            except RuntimeError as error:
                if debug:
                    print(
                        f"Skipping candidate project version {candidate_href}: {error}",
                        file=sys.stderr,
                    )
                continue

            child_project_name, child_version_name = describe_project_version(
                client,
                candidate_href,
                version=child_version,
                bom_item=bom_item,
            )

            seen.add(candidate_href)
            discovered.append(
                {
                    "project_name": child_project_name,
                    "version_name": child_version_name,
                    "version_href": candidate_href,
                    "version": child_version,
                    "source": "href",
                }
            )

        if resolve_bom_names and not candidate_hrefs:
            component_name = first_value_by_key(bom_item, ["componentName"])
            component_version_name = first_value_by_key(bom_item, ["componentVersionName"])

            if not component_name or not component_version_name:
                continue

            try:
                child_version = find_project_version(
                    client,
                    str(component_name),
                    str(component_version_name),
                )
            except RuntimeError:
                continue

            child_href = get_self_href(child_version)

            if not child_href:
                continue

            child_href = canonical_href(child_href)

            if child_href == parent_href or child_href in seen:
                continue

            seen.add(child_href)
            discovered.append(
                {
                    "project_name": str(component_name),
                    "version_name": str(component_version_name),
                    "version_href": child_href,
                    "version": child_version,
                    "source": "bom-name-resolution",
                }
            )

    return discovered


def walk_subprojects(
        client: BlackDuckClient,
        root_version: dict[str, Any],
        depth: int,
        resolve_bom_names: bool,
        debug: bool,
) -> list[dict[str, Any]]:
    root_href = get_self_href(root_version)

    if not root_href:
        raise RuntimeError("Root project version has no self href")

    root_href = canonical_href(root_href)

    queue: list[tuple[dict[str, Any], list[str], int]] = [(root_version, [], 0)]
    discovered_all: list[dict[str, Any]] = []
    seen: set[str] = set()

    while queue:
        current_version, current_path, current_depth = queue.pop(0)

        if current_depth >= depth:
            continue

        direct_refs = discover_direct_subprojects(
            client,
            current_version,
            resolve_bom_names=resolve_bom_names,
            debug=debug,
        )

        for ref in direct_refs:
            href = canonical_href(ref["version_href"])

            if href == root_href:
                continue

            label = f"{ref['project_name']}/{ref['version_name']}"
            path = current_path + [label]

            ref["path"] = " > ".join(path)

            if href not in seen:
                seen.add(href)
                discovered_all.append(ref)
                queue.append((ref["version"], path, current_depth + 1))

    return discovered_all


def get_vulnerable_bom_components(
        client: BlackDuckClient,
        project_version: dict[str, Any],
) -> list[dict[str, Any]]:
    vulnerable_components_url = get_link(
        project_version,
        (
            "vulnerable-bom-components",
            "vulnerableBomComponents",
            "vulnerable-components",
        ),
    )

    if not vulnerable_components_url:
        version_href = get_self_href(project_version)
        if not version_href:
            raise RuntimeError("Project version has no self href")
        vulnerable_components_url = f"{version_href}/vulnerable-bom-components"

    return client.paged_get(vulnerable_components_url)


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


def custom_field_value_text(value: Any) -> str:
    if value in (None, ""):
        return ""

    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, (str, int, float)):
        return str(value).strip()

    if isinstance(value, list):
        rendered = {
            custom_field_value_text(item)
            for item in value
        }
        return ";".join(sorted(item for item in rendered if item))

    if isinstance(value, dict):
        for key in (
            "displayValue",
            "displayName",
            "value",
            "label",
            "name",
        ):
            if key in value:
                rendered = custom_field_value_text(value.get(key))
                if rendered:
                    return rendered

        rendered = {
            custom_field_value_text(item)
            for item in value.values()
        }
        return ";".join(sorted(item for item in rendered if item))

    return str(value).strip()


def custom_field_candidate_name(item: dict[str, Any]) -> str:
    for key in (
        "fieldName",
        "customFieldName",
        "name",
        "label",
        "displayName",
    ):
        value = item.get(key)

        if value not in (None, "") and not isinstance(value, (dict, list)):
            return str(value).strip()

    for key in (
        "customField",
        "field",
        "definition",
        "customFieldDefinition",
    ):
        nested = item.get(key)

        if not isinstance(nested, dict):
            continue

        for name_key in (
            "fieldName",
            "customFieldName",
            "name",
            "label",
            "displayName",
        ):
            value = nested.get(name_key)

            if value not in (None, "") and not isinstance(
                value,
                (dict, list),
            ):
                return str(value).strip()

    return ""


def custom_field_candidate_value(item: dict[str, Any]) -> str:
    for key in (
        "values",
        "value",
        "fieldValue",
        "customFieldValue",
        "selectedValues",
        "selectedValue",
        "displayValue",
    ):
        if key not in item:
            continue

        rendered = custom_field_value_text(item.get(key))

        if rendered:
            return rendered

    return ""


def find_named_custom_field(
        value: Any,
        field_name: str,
) -> tuple[bool, str]:
    wanted = str(field_name or "").strip().casefold()

    if not wanted:
        return False, ""

    if isinstance(value, dict):
        candidate_name = custom_field_candidate_name(value)

        if candidate_name.casefold() == wanted:
            return True, custom_field_candidate_value(value)

        for key, item in value.items():
            if str(key).strip().casefold() == wanted:
                return True, custom_field_value_text(item)

        for item in value.values():
            found, rendered = find_named_custom_field(item, field_name)

            if found:
                return True, rendered

    elif isinstance(value, list):
        for item in value:
            found, rendered = find_named_custom_field(item, field_name)

            if found:
                return True, rendered

    return False, ""


def read_project_custom_field(
        client: BlackDuckClient,
        version_href: str,
        version: dict[str, Any],
        field_name: str,
) -> str:
    field_name = str(field_name or "").strip()

    if not field_name:
        return ""

    project_href = project_href_from_version_href(
        canonical_href(version_href)
    )

    if not project_href:
        if client.debug:
            print(
                f"Could not derive project href from version href: "
                f"{version_href}",
                file=sys.stderr,
            )
        return ""

    cache = getattr(client, "_project_custom_field_cache", None)

    if not isinstance(cache, dict):
        cache = {}
        setattr(client, "_project_custom_field_cache", cache)

    cache_key = (
        canonical_href(project_href),
        field_name.casefold(),
    )

    if cache_key in cache:
        return str(cache[cache_key] or "")

    try:
        project = client.get(project_href)
    except RuntimeError as error:
        if client.debug:
            print(
                f"Could not read project while resolving custom field "
                f"{field_name!r}: {error}",
                file=sys.stderr,
            )

        cache[cache_key] = ""
        return ""

    for resource in (project, version):
        found, rendered = find_named_custom_field(
            resource,
            field_name,
        )

        if found:
            cache[cache_key] = rendered
            return rendered

    linked_url = get_link(
        project,
        (
            "custom-fields",
            "customFields",
            "custom-field-values",
            "customFieldValues",
        ),
    )

    candidate_urls = [
        candidate
        for candidate in (
            linked_url,
            f"{canonical_href(project_href)}/custom-fields",
        )
        if candidate
    ]

    seen_urls: set[str] = set()

    for candidate_url in candidate_urls:
        candidate_url = canonical_href(candidate_url)

        if candidate_url in seen_urls:
            continue

        seen_urls.add(candidate_url)

        try:
            custom_fields = client.paged_get(candidate_url)
        except RuntimeError as error:
            if client.debug:
                print(
                    f"Could not read Black Duck project custom fields "
                    f"from {candidate_url}: {error}",
                    file=sys.stderr,
                )
            continue

        found, rendered = find_named_custom_field(
            custom_fields,
            field_name,
        )

        if found:
            cache[cache_key] = rendered
            return rendered

    cache[cache_key] = ""
    return ""

def to_float(value: Any) -> float | None:
    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def looks_like_vulnerability(value: dict[str, Any], score_field: str) -> bool:
    id_keys = [
        "vulnerabilityName",
        "vulnerabilityId",
        "vulnerabilityExternalId",
        "externalId",
        "cveId",
        "cve",
        "bdsaId",
    ]

    has_id = first_value_by_key(value, id_keys) is not None
    has_score = first_value_by_key(value, [score_field]) is not None
    has_severity = first_value_by_key(value, ["severity", "vulnerabilitySeverity"]) is not None

    return has_id and (has_score or has_severity)


def extract_vulnerability_candidates(value: Any, score_field: str) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            nested_vulnerability = item.get("vulnerability")

            if isinstance(nested_vulnerability, dict):
                merged = dict(nested_vulnerability)

                for key, nested_item in item.items():
                    if key != "vulnerability" and key not in merged:
                        merged[key] = nested_item

                if looks_like_vulnerability(merged, score_field):
                    candidates.append(merged)

            if looks_like_vulnerability(item, score_field):
                candidates.append(item)

            for nested_item in item.values():
                walk(nested_item)

        elif isinstance(item, list):
            for nested_item in item:
                walk(nested_item)

    walk(value)

    unique: list[dict[str, Any]] = []
    seen: set[str] = set()

    for candidate in candidates:
        vulnerability_id = vulnerability_identifier(candidate)
        score = first_value_by_key(candidate, [score_field])
        key = f"{vulnerability_id}|{score}|{json.dumps(candidate, sort_keys=True, default=str)[:500]}"

        if key not in seen:
            seen.add(key)
            unique.append(candidate)

    return unique


def vulnerability_identifier(vulnerability: dict[str, Any]) -> str:
    value = first_value_by_key(
        vulnerability,
        [
            "vulnerabilityName",
            "vulnerabilityId",
            "vulnerabilityExternalId",
            "externalId",
            "cveId",
            "cve",
            "bdsaId",
            "name",
            "id",
        ],
    )

    return str(value or "UNKNOWN")


def vulnerability_severity(vulnerability: dict[str, Any]) -> str:
    value = first_value_by_key(
        vulnerability,
        [
            "severity",
            "vulnerabilitySeverity",
            "sourceSeverity",
        ],
    )

    return str(value or "")


def summarize_vulnerabilities_for_component(
        client: BlackDuckClient,
        vulnerable_component: dict[str, Any],
        component_name: str,
        component_version: str,
        threshold: float,
        score_field: str,
) -> list[dict[str, Any]]:
    vulnerabilities_url = get_link(
        vulnerable_component,
        (
            "vulnerabilities",
            "vulnerability",
        ),
    )

    summary_cache_key: tuple[str, str, float] | None = None

    if vulnerabilities_url:
        summary_cache_key = (
            vulnerabilities_url,
            score_field,
            threshold,
        )
        cached_summaries = client.vulnerability_summary_cache.get(
            summary_cache_key
        )

        if cached_summaries is not None:
            if client.debug:
                print(
                    f"Reusing parsed vulnerability summary cache: "
                    f"{vulnerabilities_url} "
                    f"({len(cached_summaries)} matching item(s))",
                    file=sys.stderr,
                )

            return cached_summaries

    vulnerabilities: list[dict[str, Any]] = []

    if vulnerabilities_url:
        try:
            vulnerability_items = client.paged_get(vulnerabilities_url)

            for vulnerability_item in vulnerability_items:
                extracted = extract_vulnerability_candidates(
                    vulnerability_item,
                    score_field,
                )
                vulnerabilities.extend(
                    extracted or [vulnerability_item]
                )
        except RuntimeError as error:
            raise RuntimeError(
                f"Failed reading vulnerabilities for component "
                f"{component_name} {component_version}: {error}"
            ) from error
    else:
        vulnerabilities.extend(
            extract_vulnerability_candidates(
                vulnerable_component,
                score_field,
            )
        )

    summaries: list[dict[str, Any]] = []

    for vulnerability in vulnerabilities:
        score = to_float(
            first_value_by_key(vulnerability, [score_field])
        )

        if score is None or score < threshold:
            continue

        cvss_vector = first_value_by_key(
            vulnerability,
            [
                "cvssVector",
                "cvss3Vector",
                "cvss31Vector",
                "cvssV3Vector",
                "cvssV31Vector",
                "cvss2Vector",
                "vector",
            ],
        )

        summaries.append(
            {
                "vulnerability": vulnerability_identifier(vulnerability),
                "score": score,
                "severity": vulnerability_severity(vulnerability),
                "cvss_vector": str(cvss_vector or ""),
                "blackduck_url": (
                    get_link(vulnerability, ("self",))
                    or get_self_href(vulnerability)
                    or ""
                ),
            }
        )

    if summary_cache_key is not None:
        client.vulnerability_summary_cache[
            summary_cache_key
        ] = summaries

    return summaries

def looks_like_resource_url(value: Any) -> bool:
    text = str(value or "").strip().lower()

    return (
        text.startswith("http://")
        or text.startswith("https://")
        or text.startswith("/api/")
    )


def component_version_href_from_resource(
        resource: dict[str, Any],
) -> str:
    direct_candidates = [
        resource.get("componentVersionHref"),
        resource.get("componentVersionUrl"),
        resource.get("componentVersion"),
    ]

    for candidate in direct_candidates:
        if isinstance(candidate, str):
            if looks_like_resource_url(candidate):
                if "/api/components/" in candidate and "/versions/" in candidate:
                    return canonical_href(candidate)

        if isinstance(candidate, dict):
            for href in iter_hrefs(candidate):
                if "/api/components/" in href and "/versions/" in href:
                    return canonical_href(href)

    for link in resource.get("_meta", {}).get("links", []):
        rel = str(link.get("rel") or "").lower()
        href = str(link.get("href") or "")

        if (
            href
            and rel in {
                "component-version",
                "componentversion",
                "component_version",
            }
        ):
            return canonical_href(href)

    for href in iter_hrefs(resource):
        if "/api/components/" in href and "/versions/" in href:
            return canonical_href(href)

    return ""


def extract_component_version_details(
        client: BlackDuckClient,
        vulnerable_component: dict[str, Any],
) -> tuple[str, str]:
    display_value = first_value_by_key(
        vulnerable_component,
        [
            "componentVersionName",
            "versionName",
        ],
    )
    display_name = str(display_value or "").strip()

    if looks_like_resource_url(display_name):
        display_name = ""

    direct_version = vulnerable_component.get(
        "componentVersion"
    )

    if not display_name and isinstance(
        direct_version,
        (str, int, float),
    ):
        direct_text = str(direct_version).strip()

        if not looks_like_resource_url(direct_text):
            display_name = direct_text

    version_href = component_version_href_from_resource(
        vulnerable_component
    )

    if version_href and not display_name:
        try:
            version_resource = client.get(version_href)
        except RuntimeError as error:
            if client.debug:
                print(
                    f"Could not resolve component version name "
                    f"from {version_href}: {error}",
                    file=sys.stderr,
                )
        else:
            display_name = str(
                version_resource.get("versionName")
                or version_resource.get("name")
                or first_value_by_key(
                    version_resource,
                    [
                        "componentVersionName",
                        "versionName",
                    ],
                )
                or ""
            ).strip()

            if looks_like_resource_url(display_name):
                display_name = ""

    return display_name, version_href

def collect_findings_for_subproject(
        client: BlackDuckClient,
        parent_project: str,
        parent_version: str,
        subproject_ref: dict[str, Any],
        threshold: float,
        score_field: str,
        entity_custom_field: str,
        require_entity: bool,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_component_vulnerability_keys: set[
        tuple[str, str, str]
    ] = set()

    entity = read_project_custom_field(
        client=client,
        version_href=str(
            subproject_ref.get("version_href") or ""
        ),
        version=subproject_ref["version"],
        field_name=entity_custom_field,
    )

    if require_entity and entity_custom_field and not entity:
        raise RuntimeError(
            f"Black Duck project "
            f"{subproject_ref.get('project_name', '')!r} "
            f"does not have a populated "
            f"{entity_custom_field!r} custom field"
        )

    vulnerable_components = get_vulnerable_bom_components(
        client,
        subproject_ref["version"],
    )

    for vulnerable_component in vulnerable_components:
        component_name = str(
            first_value_by_key(
                vulnerable_component,
                [
                    "componentName",
                    "name",
                ],
            )
            or ""
        )
        (
            component_version,
            component_version_href,
        ) = extract_component_version_details(
            client,
            vulnerable_component,
        )

        vulnerabilities_url = get_link(
            vulnerable_component,
            (
                "vulnerabilities",
                "vulnerability",
            ),
        )

        if vulnerabilities_url:
            component_vulnerability_key = (
                component_name,
                component_version or component_version_href,
                vulnerabilities_url,
            )

            if (
                component_vulnerability_key
                in seen_component_vulnerability_keys
            ):
                if client.debug:
                    print(
                        f"Skipping duplicate vulnerable component "
                        f"URL for {component_name} "
                        f"{component_version}: "
                        f"{vulnerabilities_url}",
                        file=sys.stderr,
                    )
                continue

            seen_component_vulnerability_keys.add(
                component_vulnerability_key
            )

        vulnerability_summaries = (
            summarize_vulnerabilities_for_component(
                client=client,
                vulnerable_component=vulnerable_component,
                component_name=component_name,
                component_version=(
                    component_version
                    or component_version_href
                ),
                threshold=threshold,
                score_field=score_field,
            )
        )

        for vulnerability_summary in vulnerability_summaries:
            vulnerability_id = str(
                vulnerability_summary["vulnerability"]
            )
            score = float(vulnerability_summary["score"])
            severity = str(
                vulnerability_summary["severity"]
            )
            cvss_vector = str(
                vulnerability_summary.get("cvss_vector")
                or ""
            )
            vulnerability_url = str(
                vulnerability_summary["blackduck_url"]
            )

            version_identity = (
                component_version
                or component_version_href
            )

            rollup_key = "|".join(
                [
                    parent_project,
                    parent_version,
                    subproject_ref["project_name"],
                    subproject_ref["version_name"],
                    component_name,
                    version_identity,
                    vulnerability_id,
                ]
            )

            findings.append(
                {
                    "parent_project": parent_project,
                    "parent_version": parent_version,
                    "parent_version_href": (
                        subproject_ref.get(
                            "parent_version_href",
                            "",
                        )
                    ),
                    "subproject_path": subproject_ref.get(
                        "path",
                        "",
                    ),
                    "subproject": subproject_ref[
                        "project_name"
                    ],
                    "subproject_version": subproject_ref[
                        "version_name"
                    ],
                    "subproject_version_href": (
                        subproject_ref.get(
                            "version_href",
                            "",
                        )
                    ),
                    "relationship_detection_method": (
                        subproject_ref.get("source", "")
                    ),
                    "component": component_name,
                    "component_version": component_version,
                    "component_version_href": (
                        component_version_href
                    ),
                    "vulnerability": vulnerability_id,
                    "score_field": score_field,
                    "score": score,
                    "severity": severity,
                    "cvss_vector": cvss_vector,
                    "entity": entity,
                    "blackduck_url": vulnerability_url,
                    "rollup_key": rollup_key,
                }
            )

    return findings

def dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()

    for finding in findings:
        key = finding["rollup_key"]

        if key not in seen:
            seen.add(key)
            unique.append(finding)

    return unique


def relationship_key(row: dict[str, str]) -> tuple[str, str, str]:
    return (
        row.get("parent_project", ""),
        row.get("parent_version", ""),
        canonical_href(row.get("child_version_href", "")),
    )


def failed_relationship_from_subproject(
        subproject: dict[str, Any],
        stage: str,
        elapsed_seconds: float,
        client: BlackDuckClient,
        error: Exception | str,
        default_parent_project: str = "",
        default_parent_version: str = "",
) -> FailedRelationship:
    return FailedRelationship(
        parent_project=str(subproject.get("parent_project") or default_parent_project),
        parent_version=str(subproject.get("parent_version") or default_parent_version),
        child_project=str(subproject.get("project_name") or ""),
        child_version=str(subproject.get("version_name") or ""),
        child_version_href=canonical_href(str(subproject.get("version_href") or "")),
        source=str(subproject.get("source") or ""),
        stage=stage,
        elapsed_seconds=elapsed_seconds,
        timeout_seconds=client.timeout,
        retries=client.retries,
        attempts_per_request=client.retries + 1,
        error=str(error),
    )


def load_subproject_refs_from_parent_csv(
        client: BlackDuckClient,
        csv_path: str,
        parent_project_filter: str | None,
        parent_version_filter: str | None,
        debug: bool,
        failures: list[FailedRelationship] | None = None,
) -> list[dict[str, Any]]:
    required_columns = {
        "parent_project",
        "parent_version",
        "child_project",
        "child_version",
        "parent_version_href",
        "child_version_href",
    }

    with open(csv_path, newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        fieldnames = set(reader.fieldnames or [])

        missing_columns = required_columns - fieldnames
        if missing_columns:
            raise RuntimeError(
                f"{csv_path} is missing required column(s): "
                f"{', '.join(sorted(missing_columns))}"
            )

        rows = [dict(row) for row in reader]

    subproject_refs: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for row in rows:
        parent_project = str(row.get("parent_project") or "")
        parent_version = str(row.get("parent_version") or "")

        if parent_project_filter and parent_project != parent_project_filter:
            continue

        if parent_version_filter and parent_version != parent_version_filter:
            continue

        child_version_href = canonical_href(str(row.get("child_version_href") or ""))

        if not child_version_href:
            continue

        key = relationship_key(row)

        if key in seen:
            continue

        seen.add(key)

        child_project = str(row.get("child_project") or "")
        child_version_name = str(row.get("child_version") or "")

        subproject_stub = {
            "parent_project": parent_project,
            "parent_version": parent_version,
            "parent_version_href": canonical_href(str(row.get("parent_version_href") or "")),
            "project_name": child_project,
            "version_name": child_version_name,
            "version_href": child_version_href,
            "source": str(row.get("detection_method") or "parent-csv"),
            "path": f"{child_project}/{child_version_name}",
        }

        start_seconds = time.monotonic()

        try:
            child_version = client.get(child_version_href)
        except RuntimeError as error:
            elapsed_seconds = time.monotonic() - start_seconds

            print(
                f"Warning: failed to read child version {child_version_href} "
                f"for {parent_project} / {parent_version} after "
                f"{format_duration(elapsed_seconds)}: {error}",
                file=sys.stderr,
            )

            if failures is not None:
                failures.append(
                    failed_relationship_from_subproject(
                        subproject_stub,
                        stage="load-child-version",
                        elapsed_seconds=elapsed_seconds,
                        client=client,
                        error=error,
                    )
                )

            continue

        if debug:
            print(
                f"Loaded relationship from CSV: "
                f"{parent_project} / {parent_version} -> "
                f"{child_project} / {child_version_name}",
                file=sys.stderr,
            )

        subproject_ref = dict(subproject_stub)
        subproject_ref["version"] = child_version
        subproject_refs.append(subproject_ref)

    return subproject_refs


def filter_subprojects_for_targeting(
        subprojects: list[dict[str, Any]],
        only_child_project: str | None,
        only_child_version: str | None,
        only_child_href: str | None,
) -> list[dict[str, Any]]:
    target_href = canonical_href(only_child_href or "")

    filtered: list[dict[str, Any]] = []

    for subproject in subprojects:
        if target_href:
            if canonical_href(str(subproject.get("version_href") or "")) != target_href:
                continue

        if only_child_project:
            if str(subproject.get("project_name") or "") != only_child_project:
                continue

        if only_child_version:
            if str(subproject.get("version_name") or "") != only_child_version:
                continue

        filtered.append(subproject)

    return filtered


def relationship_label(
        subproject: dict[str, Any],
        default_parent_project: str = "",
        default_parent_version: str = "",
) -> str:
    parent_project = str(subproject.get("parent_project") or default_parent_project)
    parent_version = str(subproject.get("parent_version") or default_parent_version)

    if parent_project or parent_version:
        return (
            f"{parent_project} {parent_version} -> "
            f"{subproject['project_name']} {subproject['version_name']}"
        )

    return f"{subproject['project_name']} {subproject['version_name']}"


def collect_findings_for_subprojects(
        client: BlackDuckClient,
        subprojects: list[dict[str, Any]],
        args: argparse.Namespace,
        default_parent_project: str = "",
        default_parent_version: str = "",
) -> tuple[list[dict[str, Any]], list[FailedRelationship]]:
    findings: list[dict[str, Any]] = []
    failures: list[FailedRelationship] = []
    total = len(subprojects)

    for index, subproject in enumerate(subprojects, start=1):
        label = relationship_label(
            subproject,
            default_parent_project=default_parent_project,
            default_parent_version=default_parent_version,
        )

        if args.debug:
            print(
                f"[{index}/{total}] Checking {label} from "
                f"{subproject.get('source')}",
                file=sys.stderr,
            )

        parent_project = str(
            subproject.get("parent_project")
            or default_parent_project
        )
        parent_version = str(
            subproject.get("parent_version")
            or default_parent_version
        )

        start_seconds = time.monotonic()

        try:
            child_findings = collect_findings_for_subproject(
                client,
                parent_project=parent_project,
                parent_version=parent_version,
                subproject_ref=subproject,
                threshold=args.threshold,
                score_field=args.score_field,
                entity_custom_field=args.entity_custom_field,
                require_entity=args.require_entity,
            )

            elapsed_seconds = time.monotonic() - start_seconds
            findings.extend(child_findings)

            if args.debug:
                print(
                    f"[{index}/{total}] Completed {label}: "
                    f"{len(child_findings)} finding(s) in "
                    f"{format_duration(elapsed_seconds)}",
                    file=sys.stderr,
                )

        except RuntimeError as error:
            elapsed_seconds = time.monotonic() - start_seconds

            print(
                f"Warning: failed checking {label} after "
                f"{format_duration(elapsed_seconds)}; continuing: "
                f"{error}",
                file=sys.stderr,
            )

            failures.append(
                failed_relationship_from_subproject(
                    subproject,
                    stage="collect-vulnerabilities",
                    elapsed_seconds=elapsed_seconds,
                    client=client,
                    error=error,
                    default_parent_project=default_parent_project,
                    default_parent_version=default_parent_version,
                )
            )

    return findings, failures

def write_csv(
        findings: list[dict[str, Any]],
        output_path: str,
) -> None:
    fieldnames = [
        "parent_project",
        "parent_version",
        "parent_version_href",
        "subproject_path",
        "subproject",
        "subproject_version",
        "subproject_version_href",
        "relationship_detection_method",
        "component",
        "component_version",
        "component_version_href",
        "vulnerability",
        "score_field",
        "score",
        "severity",
        "cvss_vector",
        "entity",
        "blackduck_url",
        "rollup_key",
    ]

    ensure_parent_dir(output_path)

    if output_path == "-":
        output_file = sys.stdout
        close_after = False
    else:
        output_file = open(
            output_path,
            "w",
            newline="",
            encoding="utf-8",
        )
        close_after = True

    try:
        writer = csv.DictWriter(
            output_file,
            fieldnames=fieldnames,
        )
        writer.writeheader()

        for finding in findings:
            writer.writerow(
                {
                    field: finding.get(field, "")
                    for field in fieldnames
                }
            )
    finally:
        if close_after:
            output_file.close()

def write_failures_csv(
        failures: list[FailedRelationship],
        output_path: str,
) -> None:
    fieldnames = [
        "parent_project",
        "parent_version",
        "child_project",
        "child_version",
        "child_version_href",
        "source",
        "stage",
        "elapsed_seconds",
        "elapsed_human",
        "timeout_seconds",
        "retries",
        "attempts_per_request",
        "error",
    ]

    ensure_parent_dir(output_path)

    with open(
        output_path,
        "w",
        newline="",
        encoding="utf-8",
    ) as output_file:
        writer = csv.DictWriter(
            output_file,
            fieldnames=fieldnames,
        )
        writer.writeheader()

        for failure in failures:
            writer.writerow(
                {
                    "parent_project": failure.parent_project,
                    "parent_version": failure.parent_version,
                    "child_project": failure.child_project,
                    "child_version": failure.child_version,
                    "child_version_href": failure.child_version_href,
                    "source": failure.source,
                    "stage": failure.stage,
                    "elapsed_seconds": (
                        f"{failure.elapsed_seconds:.3f}"
                    ),
                    "elapsed_human": format_duration(
                        failure.elapsed_seconds
                    ),
                    "timeout_seconds": failure.timeout_seconds,
                    "retries": failure.retries,
                    "attempts_per_request": (
                        failure.attempts_per_request
                    ),
                    "error": failure.error,
                }
            )

def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"

    minutes = int(seconds // 60)
    remainder = seconds % 60

    if minutes < 60:
        return f"{minutes}m {remainder:.1f}s"

    hours = minutes // 60
    remaining_minutes = minutes % 60
    return f"{hours}h {remaining_minutes}m {remainder:.1f}s"


def safe_filename(value: str, max_length: int = 120) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")
    return (cleaned or "retry")[:max_length]


def build_retry_command(
        args: argparse.Namespace,
        failure: FailedRelationship,
) -> str:
    retry_timeout = max(args.timeout * 3, 120)
    retry_retries = max(args.retries, 2)

    retry_basename = safe_filename(
        "-".join(
            [
                "retry",
                failure.parent_project,
                failure.parent_version,
                failure.child_project,
                failure.child_version,
            ]
        )
    )
    retry_filename = (
        f"{retry_basename}.json"
        if args.json
        else f"{retry_basename}.csv"
    )
    retry_out = jira_output_path("retries", retry_filename)

    parts: list[str] = [
        sys.executable,
        "-m",
        "harness.jira.subp_vuln_rollup",
    ]

    if args.parents_csv:
        parts.extend(
            [
                "--parents-csv",
                args.parents_csv,
                "--parent-project",
                failure.parent_project,
                "--parent-version",
                failure.parent_version,
            ]
        )
    else:
        parts.extend(
            [
                "--parent-project",
                failure.parent_project,
                "--parent-version",
                failure.parent_version,
                "--depth",
                str(args.depth),
            ]
        )

        if args.resolve_bom_names:
            parts.append("--resolve-bom-names")

    if failure.child_version_href:
        parts.extend(
            [
                "--only-child-href",
                failure.child_version_href,
            ]
        )
    else:
        if failure.child_project:
            parts.extend(
                [
                    "--only-child-project",
                    failure.child_project,
                ]
            )

        if failure.child_version:
            parts.extend(
                [
                    "--only-child-version",
                    failure.child_version,
                ]
            )

    parts.extend(
        [
            "--threshold",
            str(args.threshold),
            "--score-field",
            args.score_field,
            "--out",
            retry_out,
            "--timeout",
            str(retry_timeout),
            "--retries",
            str(retry_retries),
            "--retry-delay",
            str(args.retry_delay),
            "--page-limit",
            str(args.page_limit),
        ]
    )

    if args.entity_custom_field:
        parts.extend(
            [
                "--entity-custom-field",
                args.entity_custom_field,
            ]
        )

    if args.require_entity:
        parts.append("--require-entity")

    if args.no_api_cache:
        parts.append("--no-api-cache")
    else:
        parts.extend(
            [
                "--api-cache",
                args.api_cache,
                "--api-cache-max-age-hours",
                str(args.api_cache_max_age_hours),
                "--api-cache-max-entries",
                str(args.api_cache_max_entries),
            ]
        )

    if args.json:
        parts.append("--json")

    if args.insecure:
        parts.append("--insecure")

    if args.debug:
        parts.append("--debug")

    return " ".join(
        shlex.quote(str(part))
        for part in parts
    )

def print_failed_relationship_summary(
        failures: list[FailedRelationship],
        args: argparse.Namespace,
) -> None:
    if not failures:
        return

    print(file=sys.stderr)
    print(
        "Hey, these relationship(s) failed after the main run finished. "
        "Why don't we individually retry them?",
        file=sys.stderr,
    )
    print(
        f"Failed relationship count: {len(failures)}",
        file=sys.stderr,
    )
    print(
        "The retry commands below intentionally omit --bd-url and --api-token; "
        "use BLACKDUCK_URL and BLACKDUCK_API_TOKEN env vars, or add those flags yourself.",
        file=sys.stderr,
    )

    for index, failure in enumerate(failures, start=1):
        error_text = " ".join(str(failure.error).split())
        if len(error_text) > 700:
            error_text = f"{error_text[:700]}..."

        print(file=sys.stderr)
        print(
            f"{index}. {failure.parent_project} {failure.parent_version} -> "
            f"{failure.child_project} {failure.child_version}",
            file=sys.stderr,
        )
        print(f"   stage: {failure.stage}", file=sys.stderr)
        print(f"   child href: {failure.child_version_href}", file=sys.stderr)
        print(
            f"   attempted for: {format_duration(failure.elapsed_seconds)}",
            file=sys.stderr,
        )
        print(
            f"   HTTP settings used: timeout={failure.timeout_seconds}s, "
            f"retries={failure.retries}, "
            f"attempts/request={failure.attempts_per_request}",
            file=sys.stderr,
        )
        print(f"   error: {error_text}", file=sys.stderr)
        print("   suggested individual retry:", file=sys.stderr)
        print(f"     {build_retry_command(args, failure)}", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Roll up Black Duck vulnerabilities from manually added "
            "subprojects to parent product project/version context."
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
        "--parents-csv",
        help="Relationship CSV from blackduck-find-parents.",
    )
    parser.add_argument(
        "--parent-project",
        help="Parent project name or parent-project filter.",
    )
    parser.add_argument(
        "--parent-version",
        help="Parent version name or parent-version filter.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=7.0,
    )
    parser.add_argument(
        "--score-field",
        default="overallScore",
        help="Vulnerability score field used for filtering.",
    )
    parser.add_argument(
        "--entity-custom-field",
        default="E+H Entity",
        help=(
            "Black Duck project custom-field name copied into findings. "
            "Use an empty string to disable."
        ),
    )
    parser.add_argument(
        "--require-entity",
        action="store_true",
        help="Fail a subproject pull when Entity is missing or blank.",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=1,
        help="Added-project traversal depth.",
    )
    parser.add_argument(
        "--resolve-bom-names",
        action="store_true",
        help="Resolve BOM names as Black Duck project versions.",
    )
    parser.add_argument(
        "--only-child-project",
        help="Only check this child project.",
    )
    parser.add_argument(
        "--only-child-version",
        help="Only check this child version.",
    )
    parser.add_argument(
        "--only-child-href",
        help="Only check this exact child version href.",
    )
    parser.add_argument(
        "--out",
        default=jira_output_path("findings.csv"),
        help="Findings CSV or JSON output path.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Write JSON instead of CSV.",
    )
    parser.add_argument(
        "--failures-out",
        default=jira_output_path(
            "subp_vuln_rollup_failures.csv"
        ),
        help="Failed child relationship CSV output path.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate validation.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="HTTP timeout seconds.",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=1,
        help="Retry count for transient errors.",
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=2.0,
        help="Base retry delay seconds.",
    )
    parser.add_argument(
        "--page-limit",
        type=int,
        default=100,
        help="Black Duck API page size.",
    )
    parser.add_argument(
        "--api-cache",
        default=jira_output_path(
            "cache",
            "subp_vuln_rollup_cache.json",
        ),
        help="Persistent Black Duck API response cache path.",
    )
    parser.add_argument(
        "--no-api-cache",
        action="store_true",
        help="Disable the persistent API cache.",
    )
    parser.add_argument(
        "--refresh-api-cache",
        action="store_true",
        help="Ignore and rebuild the existing API cache.",
    )
    parser.add_argument(
        "--api-cache-max-age-hours",
        type=float,
        default=20.0,
        help="Maximum persistent API cache entry age.",
    )
    parser.add_argument(
        "--api-cache-max-entries",
        type=int,
        default=5000,
        help="Maximum persistent API cache entry count.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
    )

    return parser.parse_args()

def validate_args(args: argparse.Namespace) -> None:
    if args.timeout <= 0:
        raise RuntimeError("--timeout must be greater than 0")

    if args.retries < 0:
        raise RuntimeError("--retries must be 0 or greater")

    if args.retry_delay < 0:
        raise RuntimeError("--retry-delay must be 0 or greater")

    if args.page_limit <= 0:
        raise RuntimeError("--page-limit must be greater than 0")

    if args.depth < 1:
        raise RuntimeError("--depth must be 1 or greater")

    if args.api_cache_max_age_hours < -1:
        raise RuntimeError(
            "--api-cache-max-age-hours must be -1 or greater"
        )

    if args.api_cache_max_entries <= 0:
        raise RuntimeError(
            "--api-cache-max-entries must be greater than 0"
        )

    if args.require_entity and not args.entity_custom_field.strip():
        raise RuntimeError(
            "--require-entity requires --entity-custom-field"
        )

def resolve_rollup_input(
        args: argparse.Namespace,
) -> str:
    if args.parents_csv:
        if not os.path.isfile(args.parents_csv):
            raise RuntimeError(
                f"Parent relationship CSV does not exist: "
                f"{args.parents_csv}"
            )

        return "parents-csv"

    if args.parent_project and args.parent_version:
        return "single-parent"

    default_parents_csv = jira_output_path(
        "parent_projects.csv"
    )

    if not os.path.isfile(default_parents_csv):
        raise RuntimeError(
            "No parent relationship input was supplied and the "
            f"default file does not exist: {default_parents_csv}. "
            "Run blackduck-find-parents first, provide "
            "--parents-csv, or provide both --parent-project "
            "and --parent-version."
        )

    args.parents_csv = default_parents_csv

    if args.debug:
        print(
            f"No --parents-csv supplied; using default: "
            f"{args.parents_csv}",
            file=sys.stderr,
        )

    return "parents-csv"

def save_api_cache(api_cache: ApiResponseCache | None) -> None:
    if api_cache is None:
        return

    try:
        ensure_parent_dir(api_cache.path)
        api_cache.save()
    except (OSError, TypeError, ValueError) as error:
        print(
            f"Warning: failed to write API cache "
            f"{api_cache.path}: {error}",
            file=sys.stderr,
        )

def main() -> int:
    args = parse_args()
    validate_args(args)
    resolve_rollup_input(args)

    api_cache: ApiResponseCache | None = None

    if not args.no_api_cache:
        api_cache = ApiResponseCache.load(
            path=args.api_cache,
            base_url=args.bd_url,
            max_age_hours=args.api_cache_max_age_hours,
            refresh=args.refresh_api_cache,
            max_entries=args.api_cache_max_entries,
            debug=args.debug,
        )

    client = BlackDuckClient(
        base_url=args.bd_url,
        api_token=args.api_token,
        insecure=args.insecure,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        page_limit=args.page_limit,
        debug=args.debug,
        api_cache=api_cache,
    )

    try:
        client.authenticate()

        findings: list[dict[str, Any]] = []
        failed_relationships: list[FailedRelationship] = []

        if args.parents_csv:
            subprojects = load_subproject_refs_from_parent_csv(
                client=client,
                csv_path=args.parents_csv,
                parent_project_filter=args.parent_project,
                parent_version_filter=args.parent_version,
                debug=args.debug,
                failures=failed_relationships,
            )

            subprojects = filter_subprojects_for_targeting(
                subprojects,
                only_child_project=args.only_child_project,
                only_child_version=args.only_child_version,
                only_child_href=args.only_child_href,
            )

            if not subprojects:
                print(
                    "No parent/child relationships were loaded from the CSV after filters. "
                    "Check --parents-csv, optional --parent-project/--parent-version, "
                    "and optional --only-child-* filters.",
                    file=sys.stderr,
                )

            child_findings, child_failures = collect_findings_for_subprojects(
                client=client,
                subprojects=subprojects,
                args=args,
            )
            findings.extend(child_findings)
            failed_relationships.extend(child_failures)

        else:
            if not args.parent_project or not args.parent_version:
                raise RuntimeError(
                    "Either provide --parents-csv, or provide both "
                    "--parent-project and --parent-version."
                )

            parent_version = find_project_version(
                client,
                args.parent_project,
                args.parent_version,
            )

            subprojects = walk_subprojects(
                client,
                root_version=parent_version,
                depth=args.depth,
                resolve_bom_names=args.resolve_bom_names,
                debug=args.debug,
            )

            subprojects = filter_subprojects_for_targeting(
                subprojects,
                only_child_project=args.only_child_project,
                only_child_version=args.only_child_version,
                only_child_href=args.only_child_href,
            )

            if not subprojects:
                print(
                    "No added subprojects were discovered after filters. "
                    "Try running again with --resolve-bom-names, inspect the parent BOM API links, "
                    "or check optional --only-child-* filters.",
                    file=sys.stderr,
                )

            child_findings, child_failures = collect_findings_for_subprojects(
                client=client,
                subprojects=subprojects,
                args=args,
                default_parent_project=args.parent_project,
                default_parent_version=args.parent_version,
            )
            findings.extend(child_findings)
            failed_relationships.extend(child_failures)

        findings = dedupe_findings(findings)

        if args.json:
            if args.out == "-":
                json.dump(findings, sys.stdout, indent=2)
                print()
            else:
                with open(args.out, "w", encoding="utf-8") as output_file:
                    json.dump(findings, output_file, indent=2)
        else:
            write_csv(findings, args.out)

        print(
            f"Found {len(findings)} rolled-up vulnerabilities "
            f"with {args.score_field} >= {args.threshold}",
            file=sys.stderr,
        )

        if failed_relationships and args.failures_out:
            write_failures_csv(failed_relationships, args.failures_out)
            print(
                f"Wrote failed relationship report: {args.failures_out}",
                file=sys.stderr,
            )

        print_failed_relationship_summary(failed_relationships, args)

        return 0

    finally:
        save_api_cache(api_cache)


if __name__ == "__main__":
    raise SystemExit(main())