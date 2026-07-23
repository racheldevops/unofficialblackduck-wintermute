#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import ssl
import sys
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

from harness.paths import datadog_output_path, ensure_parent_dir


SCHEMA_VERSION = 1
CACHE_SCHEMA_VERSION = 1
MAX_WORKERS = 8

FIELDNAMES = [
    "project",
    "project_version",
    "project_phase",
    "project_updated",
    "project_href",
    "project_version_href",
    "candidate_reason",
    "candidate_policy_name",
    "candidate_policy_rule_href",
    "candidate_vulnerable_component_count",
    "candidate_policy_violation_count",
    "candidate_security_violation_count",
    "candidate_detected_at",
    "cache_entry_status",
    "cache_reuse_reason",
    "scan_error",
    "candidate_key",
    "candidate_external_id",
]


@dataclass(frozen=True)
class ScanSettings:
    base_url: str
    api_token: str
    bearer_token: str
    insecure: bool
    timeout: int
    retries: int
    retry_delay: float
    page_limit: int
    debug: bool
    candidate_mode: str
    policy_name: str
    policy_rule_id: str
    skip_policy_rules: bool


@dataclass(frozen=True)
class ScanTarget:
    project: dict[str, Any]
    version: dict[str, Any]
    signature: str
    project_version_href: str


@dataclass
class CandidateScanResult:
    version_href: str
    signature: str
    row: dict[str, str]
    is_candidate: bool
    status: str
    error: str
    elapsed_seconds: float
    from_cache: bool = False


def now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_href(href: str) -> str:
    href = str(href or "").strip()
    if not href:
        return ""
    parsed = urlparse(href)
    if not parsed.scheme or not parsed.netloc:
        return href.rstrip("/")
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))


def get_self_href(resource: dict[str, Any]) -> str:
    return str((resource.get("_meta") or {}).get("href") or "")


def get_link(resource: dict[str, Any], rel_names: tuple[str, ...]) -> str:
    wanted = {rel.lower() for rel in rel_names}
    links = (resource.get("_meta") or {}).get("links") or []

    for link in links:
        rel = str(link.get("rel") or "").lower()
        href = str(link.get("href") or "")
        if href and rel in wanted:
            return href

    for link in links:
        rel = str(link.get("rel") or "").lower()
        href = str(link.get("href") or "")
        if href and any(wanted_rel in rel for wanted_rel in wanted):
            return href

    return ""


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


def version_name(version: dict[str, Any]) -> str:
    return str(version.get("versionName") or version.get("name") or "")


def version_updated(version: dict[str, Any]) -> str:
    return str(
        first_value_by_key(
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
        or ""
    )


def candidate_key(project: str, project_version: str, project_version_href: str) -> str:
    return "|".join([project, project_version, canonical_href(project_version_href)])


def stable_candidate(row: dict[str, str]) -> dict[str, str]:
    return {
        key: str(row.get(key, ""))
        for key in [
            "project",
            "project_version",
            "project_phase",
            "project_updated",
            "project_href",
            "project_version_href",
            "candidate_reason",
            "candidate_policy_name",
            "candidate_policy_rule_href",
            "candidate_vulnerable_component_count",
            "candidate_policy_violation_count",
            "candidate_security_violation_count",
            "candidate_key",
            "candidate_external_id",
        ]
    }


def format_duration(seconds: float) -> str:
    seconds = max(0.0, seconds)
    if seconds < 60:
        return f"0m {int(seconds)}s"

    minutes = int(seconds // 60)
    remainder = int(seconds % 60)

    if minutes < 60:
        return f"{minutes}m {remainder}s"

    hours = minutes // 60
    remaining_minutes = minutes % 60
    return f"{hours}h {remaining_minutes}m {remainder}s"


class BlackDuckClient:
    def __init__(
        self,
        base_url: str,
        api_token: str,
        insecure: bool,
        timeout: int,
        retries: int,
        retry_delay: float,
        page_limit: int,
        debug: bool,
        bearer_token: str | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.timeout = timeout
        self.retries = retries
        self.retry_delay = retry_delay
        self.page_limit = page_limit
        self.debug = debug
        self.bearer_token: str | None = bearer_token
        self.ssl_context = ssl._create_unverified_context() if insecure else None

    def authenticate(self) -> None:
        url = f"{self.base_url}/api/tokens/authenticate"
        headers = {
            "Authorization": f"token {self.api_token}",
            "Accept": "application/json",
        }

        for attempt in range(self.retries + 1):
            request = Request(url, data=b"", headers=headers, method="POST")

            try:
                with urlopen(
                    request,
                    timeout=self.timeout,
                    context=self.ssl_context,
                ) as response:
                    text = response.read().decode("utf-8")

                try:
                    payload = json.loads(text)
                except json.JSONDecodeError as error:
                    raise RuntimeError(f"Authentication returned invalid JSON: {error}") from error

                self.bearer_token = str(payload["bearerToken"])
                return

            except (HTTPError, URLError, TimeoutError, OSError) as error:
                if isinstance(error, HTTPError):
                    body = error.read().decode("utf-8", errors="replace")
                    retryable = error.code in {429, 500, 502, 503, 504}
                    message = f"HTTP {error.code} {error.reason}: {body[:1000]}"
                else:
                    retryable = True
                    message = str(error)

                if not retryable or attempt >= self.retries:
                    raise RuntimeError(f"Authentication failed: {message}") from error

                time.sleep(self.retry_delay * (attempt + 1))

        raise RuntimeError("Authentication failed unexpectedly")

    def _make_url(self, url_or_path: str, params: dict[str, Any] | None = None) -> str:
        if url_or_path.startswith(("http://", "https://")):
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

    def get(self, url_or_path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = self._make_url(url_or_path, params)

        headers = {
            "Accept": "application/json",
        }

        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"

        for attempt in range(self.retries + 1):
            request = Request(url, headers=headers, method="GET")

            try:
                with urlopen(
                    request,
                    timeout=self.timeout,
                    context=self.ssl_context,
                ) as response:
                    text = response.read().decode("utf-8")

                if not text:
                    return {}

                try:
                    return json.loads(text)
                except json.JSONDecodeError as error:
                    raise RuntimeError(f"GET {url} returned invalid JSON: {error}") from error

            except (HTTPError, URLError, TimeoutError, OSError) as error:
                if isinstance(error, HTTPError):
                    body = error.read().decode("utf-8", errors="replace")
                    retryable = error.code in {429, 500, 502, 503, 504}
                    message = f"HTTP {error.code} {error.reason}: {body[:1000]}"
                else:
                    retryable = True
                    message = str(error)

                if not retryable or attempt >= self.retries:
                    raise RuntimeError(f"GET {url} failed: {message}") from error

                if self.debug:
                    print(f"Retrying GET {url}: {message}", file=sys.stderr)

                time.sleep(self.retry_delay * (attempt + 1))

        raise RuntimeError(f"GET {url} failed unexpectedly")

    def paged_get(
        self,
        url_or_path: str,
        params: dict[str, Any] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        page_limit = limit or self.page_limit
        offset = 0
        all_items: list[dict[str, Any]] = []

        while True:
            page_params = dict(params or {})
            page_params["offset"] = offset
            page_params["limit"] = page_limit

            payload = self.get(url_or_path, page_params)

            if "items" not in payload:
                return [payload] if payload else []

            items = payload.get("items") or []
            all_items.extend(items)

            total_count = payload.get("totalCount")
            total_int = int(total_count) if total_count is not None else None

            if not items:
                break

            offset += len(items)

            if total_int is not None and offset >= total_int:
                break

            if len(items) < page_limit:
                break

        return all_items

    def collection_count_and_items(
        self,
        url_or_path: str,
        params: dict[str, Any] | None = None,
        limit: int = 1,
    ) -> tuple[int, list[dict[str, Any]]]:
        page_params = dict(params or {})
        page_params["offset"] = 0
        page_params["limit"] = limit

        payload = self.get(url_or_path, page_params)

        if "items" in payload:
            items = payload.get("items") or []
            if payload.get("totalCount") is not None:
                return int(payload["totalCount"]), list(items)
            return len(items), list(items)

        return (1, [payload]) if payload else (0, [])

    def count_items(self, url_or_path: str, params: dict[str, Any] | None = None) -> int:
        count, _ = self.collection_count_and_items(url_or_path, params=params, limit=1)
        return count


def cache_settings(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "candidate_mode": str(args.candidate_mode or ""),
        "policy_name": str(args.policy_name or ""),
        "policy_rule_id": str(args.policy_rule_id or ""),
        "skip_policy_rules": bool(args.skip_policy_rules),
    }


def fresh_cache(base_url: str, settings: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": CACHE_SCHEMA_VERSION,
        "base_url": base_url.rstrip("/"),
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "settings": dict(settings),
        "candidates": {},
    }


def load_cache(
    path: str,
    base_url: str,
    refresh_all: bool,
    settings: dict[str, Any],
) -> dict[str, Any]:
    fresh = fresh_cache(base_url, settings)

    if refresh_all or not os.path.exists(path):
        return fresh

    try:
        with open(path, encoding="utf-8") as input_file:
            cache = json.load(input_file)
    except (OSError, json.JSONDecodeError) as error:
        print(f"Warning: failed reading cache {path}: {error}; starting fresh.", file=sys.stderr)
        return fresh

    if cache.get("schema_version") != CACHE_SCHEMA_VERSION:
        print("Cache schema changed; starting fresh cache.", file=sys.stderr)
        return fresh

    if str(cache.get("base_url") or "").rstrip("/") != base_url.rstrip("/"):
        print("Cache Black Duck URL differs from current URL; starting fresh cache.", file=sys.stderr)
        return fresh

    if dict(cache.get("settings") or {}) != settings:
        print(
            "Cache scan settings differ from current run; starting fresh cache.",
            file=sys.stderr,
        )
        return fresh

    cache.setdefault("settings", dict(settings))
    cache.setdefault("candidates", {})
    return cache


def save_cache(path: str, cache: dict[str, Any]) -> None:
    ensure_parent_dir(path)
    cache["updated_at"] = now_iso()
    tmp_path = f"{path}.tmp"

    with open(tmp_path, "w", encoding="utf-8") as output_file:
        json.dump(cache, output_file, indent=2, sort_keys=True)

    os.replace(tmp_path, path)


def cache_entry_settings_match(entry: dict[str, Any], settings: dict[str, Any]) -> bool:
    for key, value in settings.items():
        if entry.get(key) != value:
            return False
    return True


def cache_stale(row: dict[str, Any], max_age_hours: float) -> bool:
    if max_age_hours < 0:
        return False

    scanned_at = parse_iso(str(row.get("scanned_at") or ""))

    if not scanned_at:
        return True

    age_hours = (datetime.now(timezone.utc) - scanned_at).total_seconds() / 3600
    return age_hours >= max_age_hours


def get_project_versions(client: BlackDuckClient, project: dict[str, Any]) -> list[dict[str, Any]]:
    versions_url = get_link(project, ("versions",))

    if not versions_url:
        project_href = get_self_href(project)
        if not project_href:
            return []
        versions_url = f"{project_href}/versions"

    return client.paged_get(versions_url)


def build_inventory(
    client: BlackDuckClient,
    args: argparse.Namespace,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    projects = client.paged_get("/api/projects")
    inventory: list[tuple[dict[str, Any], dict[str, Any]]] = []
    seen_projects = 0

    for project in projects:
        project_name = str(project.get("name") or "")

        if args.project_name and project_name != args.project_name:
            continue

        if args.project_name_contains and args.project_name_contains.lower() not in project_name.lower():
            continue

        seen_projects += 1

        if args.max_projects is not None and seen_projects > args.max_projects:
            break

        try:
            versions = get_project_versions(client, project)
        except RuntimeError as error:
            print(f"Warning: failed reading versions for {project_name}: {error}", file=sys.stderr)
            continue

        for version in versions:
            if args.max_versions is not None and len(inventory) >= args.max_versions:
                return inventory

            if args.version_name and version_name(version) != args.version_name:
                continue

            if args.phase and str(version.get("phase") or "") != args.phase:
                continue

            inventory.append((project, version))

            if args.max_versions is not None and len(inventory) >= args.max_versions:
                return inventory

    return inventory


def signature(project: dict[str, Any], version: dict[str, Any]) -> str:
    payload = {
        "project": str(project.get("name") or ""),
        "version": version_name(version),
        "phase": str(version.get("phase") or ""),
        "project_href": canonical_href(get_self_href(project)),
        "project_version_href": canonical_href(get_self_href(version)),
        "updated": version_updated(version),
    }

    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def count_vulnerable_components(
    client: BlackDuckClient,
    version: dict[str, Any],
    project_version_href: str,
) -> int:
    if not project_version_href:
        return 0

    try:
        return client.count_items(f"{project_version_href}/vulnerable-bom-components")
    except RuntimeError as direct_error:
        if client.debug:
            print(
                f"Direct vulnerable-bom-components check failed for {project_version_href}: {direct_error}",
                file=sys.stderr,
            )

    vulnerable_link = get_link(
        version,
        (
            "vulnerable-bom-components",
            "vulnerableBomComponents",
            "vulnerable-components",
        ),
    )

    if not vulnerable_link:
        try:
            fresh_version = client.get(project_version_href)
            vulnerable_link = get_link(
                fresh_version,
                (
                    "vulnerable-bom-components",
                    "vulnerableBomComponents",
                    "vulnerable-components",
                ),
            )
        except RuntimeError as error:
            if client.debug:
                print(
                    f"Could not resolve vulnerable component link for {project_version_href}: {error}",
                    file=sys.stderr,
                )

    if not vulnerable_link:
        return 0

    try:
        return client.count_items(vulnerable_link)
    except RuntimeError as fallback_error:
        if client.debug:
            print(
                f"Linked vulnerable component check failed for {project_version_href}: {fallback_error}",
                file=sys.stderr,
            )
        return 0


def count_policy_violations(
    client: BlackDuckClient,
    project_version_href: str,
    settings: ScanSettings,
) -> tuple[int, int, str, str]:
    if not project_version_href:
        return 0, 0, "", ""

    security_count = 0
    matched_policy_name = ""
    matched_policy_href = ""

    need_rule_details = (
        not settings.skip_policy_rules
        and (
            bool(settings.policy_name or settings.policy_rule_id)
            or settings.candidate_mode == "both"
        )
    )

    component_limit = 25 if need_rule_details else 1

    try:
        policy_count, components = client.collection_count_and_items(
            f"{project_version_href}/components",
            params={"filter": "policyStatus:IN_VIOLATION"},
            limit=component_limit,
        )
    except RuntimeError as error:
        if client.debug:
            print(f"Policy violation count failed for {project_version_href}: {error}", file=sys.stderr)
        return 0, 0, "", ""

    if not need_rule_details:
        return policy_count, 0, "", ""

    for component in components[:25]:
        policy_rules_url = get_link(component, ("policy-rules", "policyRules", "policy-rule"))

        if not policy_rules_url:
            continue

        try:
            _, rules = client.collection_count_and_items(policy_rules_url, limit=25)
        except RuntimeError as error:
            if client.debug:
                print(f"Policy rule check failed for {project_version_href}: {error}", file=sys.stderr)
            continue

        for rule in rules[:25]:
            category = str(first_value_by_key(rule, ["category", "policyCategory"]) or "").upper()
            name = str(first_value_by_key(rule, ["name", "policyName", "policyRuleName"]) or "")
            href = canonical_href(get_self_href(rule) or get_link(rule, ("self",)))

            if category == "SECURITY":
                security_count += 1

            if settings.policy_name and name == settings.policy_name:
                matched_policy_name = name
                matched_policy_href = href

            if settings.policy_rule_id and settings.policy_rule_id in href:
                matched_policy_name = name
                matched_policy_href = href

    return policy_count, security_count, matched_policy_name, matched_policy_href


def build_failed_row(
    project: dict[str, Any],
    version: dict[str, Any],
    settings: ScanSettings,
    error: Exception | str,
) -> dict[str, str]:
    project_name = str(project.get("name") or "")
    project_version = version_name(version)
    project_href = canonical_href(get_self_href(project))
    project_version_href = canonical_href(get_self_href(version))
    key = candidate_key(project_name, project_version, project_version_href)

    return {
        "project": project_name,
        "project_version": project_version,
        "project_phase": str(version.get("phase") or ""),
        "project_updated": version_updated(version),
        "project_href": project_href,
        "project_version_href": project_version_href,
        "candidate_reason": "",
        "candidate_policy_name": settings.policy_name,
        "candidate_policy_rule_href": "",
        "candidate_vulnerable_component_count": "0",
        "candidate_policy_violation_count": "0",
        "candidate_security_violation_count": "0",
        "candidate_detected_at": now_iso(),
        "cache_entry_status": "failed",
        "cache_reuse_reason": "fresh-scan",
        "scan_error": str(error),
        "candidate_key": key,
        "candidate_external_id": sha256_hex(key),
    }


def scan_candidate(
    client: BlackDuckClient,
    project: dict[str, Any],
    version: dict[str, Any],
    settings: ScanSettings,
) -> dict[str, str]:
    project_name = str(project.get("name") or "")
    project_version = version_name(version)
    project_href = canonical_href(get_self_href(project))
    project_version_href = canonical_href(get_self_href(version))
    key = candidate_key(project_name, project_version, project_version_href)

    vulnerable_count = 0
    policy_count = 0
    security_count = 0
    policy_name = ""
    policy_href = ""

    if settings.candidate_mode in {"vulnerable-only", "both"}:
        vulnerable_count = count_vulnerable_components(
            client=client,
            version=version,
            project_version_href=project_version_href,
        )

    if settings.candidate_mode in {"policy-only", "both"}:
        policy_count, security_count, policy_name, policy_href = count_policy_violations(
            client=client,
            project_version_href=project_version_href,
            settings=settings,
        )

    reasons: list[str] = []

    if vulnerable_count > 0:
        reasons.append("vulnerable-bom-components")

    if policy_count > 0:
        reasons.append("policy-violation")

    if security_count > 0:
        reasons.append("security-policy-violation")

    if settings.policy_name or settings.policy_rule_id:
        if policy_name or policy_href:
            reasons.append("requested-policy-match")
        else:
            reasons = []

    return {
        "project": project_name,
        "project_version": project_version,
        "project_phase": str(version.get("phase") or ""),
        "project_updated": version_updated(version),
        "project_href": project_href,
        "project_version_href": project_version_href,
        "candidate_reason": ";".join(sorted(set(reasons))),
        "candidate_policy_name": policy_name or settings.policy_name,
        "candidate_policy_rule_href": policy_href,
        "candidate_vulnerable_component_count": str(vulnerable_count),
        "candidate_policy_violation_count": str(policy_count),
        "candidate_security_violation_count": str(security_count),
        "candidate_detected_at": now_iso(),
        "cache_entry_status": "ok",
        "cache_reuse_reason": "fresh-scan",
        "scan_error": "",
        "candidate_key": key,
        "candidate_external_id": sha256_hex(key),
    }


def scan_one_candidate_version(
    settings: ScanSettings,
    project: dict[str, Any],
    version: dict[str, Any],
    sig: str,
) -> CandidateScanResult:
    start_seconds = time.monotonic()
    project_version_href = canonical_href(get_self_href(version))

    client = BlackDuckClient(
        base_url=settings.base_url,
        api_token=settings.api_token,
        insecure=settings.insecure,
        timeout=settings.timeout,
        retries=settings.retries,
        retry_delay=settings.retry_delay,
        page_limit=settings.page_limit,
        debug=settings.debug,
        bearer_token=settings.bearer_token,
    )

    try:
        row = scan_candidate(client, project, version, settings)
        is_candidate = bool(row["candidate_reason"])
        return CandidateScanResult(
            version_href=project_version_href,
            signature=sig,
            row=row,
            is_candidate=is_candidate,
            status="ok",
            error="",
            elapsed_seconds=time.monotonic() - start_seconds,
        )
    except Exception as error:
        row = build_failed_row(project, version, settings, error)
        return CandidateScanResult(
            version_href=project_version_href,
            signature=sig,
            row=row,
            is_candidate=False,
            status="failed",
            error=str(error),
            elapsed_seconds=time.monotonic() - start_seconds,
        )


def write_csv_file(path: str, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    ensure_parent_dir(path)
    if path == "-":
        output_file = sys.stdout
        close_after = False
        tmp_path = ""
    else:
        tmp_path = f"{path}.tmp"
        output_file = open(tmp_path, "w", newline="", encoding="utf-8")
        close_after = True

    try:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()

        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})
    finally:
        if close_after:
            output_file.close()

    if path != "-":
        os.replace(tmp_path, path)


def atomic_write_json(path: str, payload: Any) -> None:
    ensure_parent_dir(path)
    if path == "-":
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        print()
        return

    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as output_file:
        json.dump(payload, output_file, indent=2, sort_keys=True)
    os.replace(tmp_path, path)


def write_rows(path: str, rows: list[dict[str, str]], json_mode: bool) -> None:
    if json_mode:
        atomic_write_json(path, rows)
    else:
        write_csv_file(path, rows, FIELDNAMES)


def sorted_candidate_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return sorted(
        rows,
        key=lambda row: (
            row.get("project", "").lower(),
            row.get("project_version", "").lower(),
            row.get("project_version_href", ""),
        ),
    )


def write_changes(
    path: str,
    old_rows: list[dict[str, str]],
    new_rows: list[dict[str, str]],
) -> tuple[int, int, int, int]:
    old_by_id = {
        row["candidate_external_id"]: row
        for row in old_rows
        if row.get("candidate_external_id")
    }
    new_by_id = {
        row["candidate_external_id"]: row
        for row in new_rows
        if row.get("candidate_external_id")
    }

    change_rows: list[dict[str, str]] = []
    added = 0
    removed = 0
    changed = 0
    unchanged = 0

    for external_id in sorted(set(new_by_id) - set(old_by_id)):
        added += 1
        change_rows.append({"change_type": "added", **new_by_id[external_id]})

    for external_id in sorted(set(old_by_id) - set(new_by_id)):
        removed += 1
        change_rows.append({"change_type": "removed", **old_by_id[external_id]})

    for external_id in sorted(set(old_by_id) & set(new_by_id)):
        if stable_candidate(old_by_id[external_id]) != stable_candidate(new_by_id[external_id]):
            changed += 1
            change_rows.append({"change_type": "changed", **new_by_id[external_id]})
        else:
            unchanged += 1

    if path:
        write_csv_file(path, change_rows, ["change_type"] + FIELDNAMES)

    return added, removed, changed, unchanged


def print_progress(
    completed: int,
    total: int,
    candidate_count: int,
    failed_count: int,
    reused_count: int,
    start_seconds: float,
    progress_every: int,
    force: bool = False,
) -> None:
    if total <= 0:
        return

    if not force and completed % progress_every != 0:
        return

    remaining = max(0, total - completed)
    elapsed = format_duration(time.monotonic() - start_seconds)
    print(
        f"[{completed}/{total}] scanned, candidates={candidate_count}, "
        f"failed={failed_count}, reused={reused_count}, remaining={remaining}, "
        f"elapsed={elapsed}",
        file=sys.stderr,
    )


def runtime_limit_reached(args: argparse.Namespace, start_seconds: float) -> bool:
    if args.max_runtime_minutes is None:
        return False
    return (time.monotonic() - start_seconds) >= (args.max_runtime_minutes * 60.0)


def persist_checkpoint(
    cache: dict[str, Any],
    current_rows: list[dict[str, str]],
    args: argparse.Namespace,
    partial_out: str,
) -> None:
    if not args.no_cache:
        save_cache(args.cache, cache)
        print(f"Saved cache: {args.cache}", file=sys.stderr)

    if partial_out:
        write_rows(partial_out, sorted_candidate_rows(current_rows), args.json)
        print(f"Wrote partial candidates: {partial_out}", file=sys.stderr)


def remove_partial_output(partial_out: str) -> None:
    if not partial_out or partial_out == "-":
        return
    try:
        if os.path.exists(partial_out):
            os.remove(partial_out)
    except OSError as error:
        print(f"Warning: failed removing partial output {partial_out}: {error}", file=sys.stderr)


def process(args: argparse.Namespace) -> int:
    run_start_seconds = time.monotonic()

    if (args.policy_name or args.policy_rule_id) and args.candidate_mode == "vulnerable-only":
        print(
            "Policy filter supplied with --candidate-mode vulnerable-only; "
            "upgrading candidate mode to both.",
            file=sys.stderr,
        )
        args.candidate_mode = "both"

    partial_out = args.partial_out
    if partial_out is None:
        partial_out = "" if args.out == "-" else f"{args.out}.partial"

    client = BlackDuckClient(
        base_url=args.bd_url,
        api_token=args.api_token,
        insecure=args.insecure,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        page_limit=args.page_limit,
        debug=args.debug,
    )
    client.authenticate()

    if not client.bearer_token:
        raise RuntimeError("Authentication succeeded but no bearer token was returned")

    settings_dict = cache_settings(args)
    cache = (
        fresh_cache(args.bd_url, settings_dict)
        if args.no_cache
        else load_cache(args.cache, args.bd_url, args.refresh_all, settings_dict)
    )

    cached_candidates = cache.setdefault("candidates", {})
    old_candidates = [
        dict(entry.get("row") or {})
        for entry in cached_candidates.values()
        if isinstance(entry, dict)
        and entry.get("is_candidate")
        and isinstance(entry.get("row"), dict)
    ]

    print("Building project/version inventory...", file=sys.stderr)
    inventory = build_inventory(client, args)
    print(f"Indexed {len(inventory):,} project version(s).", file=sys.stderr)
    print(f"Loaded cache: {len(cached_candidates):,} entrie(s).", file=sys.stderr)

    settings = ScanSettings(
        base_url=args.bd_url,
        api_token=args.api_token,
        bearer_token=client.bearer_token,
        insecure=args.insecure,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        page_limit=args.page_limit,
        debug=args.debug,
        candidate_mode=args.candidate_mode,
        policy_name=args.policy_name or "",
        policy_rule_id=args.policy_rule_id or "",
        skip_policy_rules=bool(args.skip_policy_rules),
    )

    current_rows: list[dict[str, str]] = []
    scan_targets: list[ScanTarget] = []
    reused_count = 0
    failed_count = 0

    for project, version in inventory:
        project_version_href = canonical_href(get_self_href(version))

        if not project_version_href:
            failed_count += 1
            print(
                f"Warning: skipping {project.get('name')} / {version_name(version)}: "
                "project version has no self href.",
                file=sys.stderr,
            )
            continue

        sig = signature(project, version)
        cached = cached_candidates.get(project_version_href)

        if (
            not args.no_cache
            and isinstance(cached, dict)
            and not args.refresh_all
            and cached.get("signature") == sig
            and cache_entry_settings_match(cached, settings_dict)
            and not cache_stale(cached, args.refresh_older_than_hours)
            and (version_updated(version) or args.trust_cache_without_update_marker)
            and (cached.get("status") != "failed" or args.no_refresh_failed)
        ):
            reused_count += 1
            row = dict(cached.get("row") or {})
            if row:
                row["cache_reuse_reason"] = "unchanged-cache-hit"
                row["cache_entry_status"] = str(cached.get("status") or "")
                if cached.get("is_candidate"):
                    current_rows.append(row)
            continue

        scan_targets.append(
            ScanTarget(
                project=project,
                version=version,
                signature=sig,
                project_version_href=project_version_href,
            )
        )

    print(
        f"Reusing {reused_count:,} cached project version candidate scan(s); "
        f"scanning {len(scan_targets):,}.",
        file=sys.stderr,
    )
    print(
        f"Scanning with workers={args.workers}, candidate_mode={args.candidate_mode}.",
        file=sys.stderr,
    )

    scanned_count = 0
    runtime_limited = False
    interrupted = False

    def apply_result(result: CandidateScanResult) -> None:
        nonlocal failed_count

        entry = {
            "signature": result.signature,
            "status": result.status,
            "error": result.error,
            "is_candidate": result.is_candidate,
            "row": result.row,
            "scanned_at": now_iso(),
            "elapsed_seconds": result.elapsed_seconds,
            **settings_dict,
        }

        cached_candidates[result.version_href] = entry

        if result.status == "failed":
            failed_count += 1
            print(
                f"Warning: failed scanning candidate "
                f"{result.row.get('project', '')} / {result.row.get('project_version', '')}: "
                f"{result.error}",
                file=sys.stderr,
            )
            return

        if result.is_candidate:
            current_rows.append(result.row)

    try:
        if args.workers == 1:
            for index, target in enumerate(scan_targets, start=1):
                if runtime_limit_reached(args, run_start_seconds):
                    runtime_limited = True
                    break

                if args.debug:
                    print(
                        f"[{index}/{len(scan_targets)}] Scanning "
                        f"{target.project.get('name')} / {version_name(target.version)}",
                        file=sys.stderr,
                    )

                result = scan_one_candidate_version(
                    settings=settings,
                    project=target.project,
                    version=target.version,
                    sig=target.signature,
                )
                apply_result(result)
                scanned_count += 1

                print_progress(
                    completed=scanned_count,
                    total=len(scan_targets),
                    candidate_count=len(current_rows),
                    failed_count=failed_count,
                    reused_count=reused_count,
                    start_seconds=run_start_seconds,
                    progress_every=args.progress_every,
                )

                if scanned_count % args.cache_save_every == 0:
                    persist_checkpoint(cache, current_rows, args, partial_out)

        elif scan_targets:
            executor: ThreadPoolExecutor | None = ThreadPoolExecutor(max_workers=args.workers)
            pending: dict[Future[CandidateScanResult], ScanTarget] = {}
            next_index = 0

            def submit_more() -> None:
                nonlocal next_index, runtime_limited

                while executor is not None and len(pending) < args.workers and next_index < len(scan_targets):
                    if runtime_limit_reached(args, run_start_seconds):
                        runtime_limited = True
                        return

                    target = scan_targets[next_index]
                    next_index += 1

                    if args.debug:
                        print(
                            f"[schedule {next_index}/{len(scan_targets)}] Scanning "
                            f"{target.project.get('name')} / {version_name(target.version)}",
                            file=sys.stderr,
                        )

                    future = executor.submit(
                        scan_one_candidate_version,
                        settings,
                        target.project,
                        target.version,
                        target.signature,
                    )
                    pending[future] = target

            try:
                submit_more()

                while pending:
                    done, _ = wait(pending, timeout=1.0, return_when=FIRST_COMPLETED)

                    if not done:
                        if runtime_limit_reached(args, run_start_seconds):
                            runtime_limited = True
                        continue

                    for future in done:
                        target = pending.pop(future)

                        try:
                            result = future.result()
                        except Exception as error:
                            row = build_failed_row(target.project, target.version, settings, error)
                            result = CandidateScanResult(
                                version_href=target.project_version_href,
                                signature=target.signature,
                                row=row,
                                is_candidate=False,
                                status="failed",
                                error=str(error),
                                elapsed_seconds=0.0,
                            )

                        apply_result(result)
                        scanned_count += 1

                        print_progress(
                            completed=scanned_count,
                            total=len(scan_targets),
                            candidate_count=len(current_rows),
                            failed_count=failed_count,
                            reused_count=reused_count,
                            start_seconds=run_start_seconds,
                            progress_every=args.progress_every,
                        )

                        if scanned_count % args.cache_save_every == 0:
                            persist_checkpoint(cache, current_rows, args, partial_out)

                    if runtime_limit_reached(args, run_start_seconds):
                        runtime_limited = True

                    if not runtime_limited:
                        submit_more()

            finally:
                if executor is not None:
                    executor.shutdown(wait=True, cancel_futures=False)

    except KeyboardInterrupt:
        interrupted = True
        print("Interrupted; saving cache and partial output...", file=sys.stderr)

    if interrupted:
        persist_checkpoint(cache, current_rows, args, partial_out)
        return 130

    if runtime_limited:
        print(
            f"Runtime limit reached after {format_duration(time.monotonic() - run_start_seconds)}; "
            "writing outputs for completed work.",
            file=sys.stderr,
        )

    print_progress(
        completed=scanned_count,
        total=len(scan_targets),
        candidate_count=len(current_rows),
        failed_count=failed_count,
        reused_count=reused_count,
        start_seconds=run_start_seconds,
        progress_every=args.progress_every,
        force=True,
    )

    current_rows = sorted_candidate_rows(current_rows)

    write_rows(args.out, current_rows, args.json)

    added, removed, changed, unchanged = write_changes(args.changes_out or "", old_candidates, current_rows)

    should_trigger = bool(
        added
        or removed
        or changed
        or (args.trigger_on_any_candidate and len(current_rows) > 0)
    )

    elapsed_seconds = time.monotonic() - run_start_seconds
    remaining_count = max(0, len(scan_targets) - scanned_count)

    if args.trigger_out:
        trigger = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": now_iso(),
            "should_trigger_pull": should_trigger,
            "candidate_count": len(current_rows),
            "added_count": added,
            "removed_count": removed,
            "changed_count": changed,
            "unchanged_count": unchanged,
            "inventory_count": len(inventory),
            "reused_count": reused_count,
            "scanned_count": scanned_count,
            "failed_count": failed_count,
            "runtime_limited": runtime_limited,
            "completed_count": scanned_count,
            "remaining_count": remaining_count,
            "elapsed_seconds": round(elapsed_seconds, 3),
            "candidate_mode": args.candidate_mode,
            "workers": args.workers,
            "candidates_out": args.out,
            "changes_out": args.changes_out or "",
            "recommended_next_command": f"blackduck-policy-vuln-pull --candidates {args.out} --out {datadog_output_path('policy_findings.csv')}",
        }
        atomic_write_json(args.trigger_out, trigger)

    if not args.no_cache:
        save_cache(args.cache, cache)
        print(f"Saved cache: {args.cache}", file=sys.stderr)

    remove_partial_output(partial_out)

    print(
        f"Indexed {len(inventory):,} project version(s); "
        f"reused {reused_count:,}; scanned {scanned_count:,}; "
        f"failed {failed_count:,}; found {len(current_rows):,} candidate(s); "
        f"elapsed {format_duration(elapsed_seconds)}.",
        file=sys.stderr,
    )

    if args.trigger_out:
        print(f"Trigger pull: {should_trigger}", file=sys.stderr)

    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fast Black Duck candidate finder for high-risk vulnerability Datadog workflow."
    )
    parser.add_argument("--bd-url", default=os.getenv("BLACKDUCK_URL"), required=os.getenv("BLACKDUCK_URL") is None)
    parser.add_argument("--api-token", default=os.getenv("BLACKDUCK_API_TOKEN"), required=os.getenv("BLACKDUCK_API_TOKEN") is None)
    parser.add_argument("--project-name")
    parser.add_argument("--project-name-contains")
    parser.add_argument("--version-name")
    parser.add_argument("--phase")
    parser.add_argument("--policy-name")
    parser.add_argument("--policy-rule-id")
    parser.add_argument(
        "--out",
        default=datadog_output_path(
            "policy_candidate_projects.csv"
        ),
        help="Candidate project/version output path.",
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--changes-out",
        default=datadog_output_path(
            "policy_candidate_changes.csv"
        ),
        help="Candidate added, removed, and changed report.",
    )
    parser.add_argument(
        "--trigger-out",
        default=datadog_output_path(
            "policy_candidate_trigger.json"
        ),
        help="Candidate pull trigger metadata JSON.",
    )
    parser.add_argument(
        "--cache",
        default=datadog_output_path(
            "cache",
            "policy_vuln_find_cache.json",
        ),
        help="Candidate scan cache path.",
    )
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--refresh-all", action="store_true")
    parser.add_argument("--refresh-older-than-hours", type=float, default=6.0)
    parser.add_argument("--no-refresh-failed", action="store_true")
    parser.add_argument("--trust-cache-without-update-marker", action="store_true")
    parser.add_argument("--trigger-on-any-candidate", action="store_true")
    parser.add_argument("--max-projects", type=int)
    parser.add_argument("--max-versions", type=int)
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Concurrent project-version candidate scans. Values above 8 are clamped to 8. Default: 4.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=25,
        help="Print progress after every N completed project-version scans. Default: 25.",
    )
    parser.add_argument(
        "--cache-save-every",
        type=int,
        default=100,
        help="Save cache and partial output after every N completed scans. Default: 100.",
    )
    parser.add_argument(
        "--partial-out",
        default=None,
        help="Partial candidate output path written during scan. Default: <out>.partial; disabled when --out is '-'.",
    )
    parser.add_argument(
        "--candidate-mode",
        choices=["vulnerable-only", "policy-only", "both"],
        default="vulnerable-only",
        help="Candidate detection mode. Default: vulnerable-only.",
    )
    parser.add_argument(
        "--skip-policy-rules",
        action="store_true",
        help="When checking policy violations, avoid following policy-rules links.",
    )
    parser.add_argument(
        "--max-runtime-minutes",
        type=float,
        help="Optional runtime cutoff. Completed work is saved and the run exits 0 with runtime_limited metadata.",
    )
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--retry-delay", type=float, default=2.0)
    parser.add_argument("--page-limit", type=int, default=100)
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--debug", action="store_true")
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
    if args.refresh_older_than_hours < -1:
        raise RuntimeError("--refresh-older-than-hours must be -1 or greater")
    if args.workers <= 0:
        raise RuntimeError("--workers must be greater than 0")
    if args.workers > MAX_WORKERS:
        print(f"Warning: --workers {args.workers} exceeds max {MAX_WORKERS}; clamping to {MAX_WORKERS}.", file=sys.stderr)
        args.workers = MAX_WORKERS
    if args.progress_every <= 0:
        raise RuntimeError("--progress-every must be greater than 0")
    if args.cache_save_every <= 0:
        raise RuntimeError("--cache-save-every must be greater than 0")
    if args.max_runtime_minutes is not None and args.max_runtime_minutes <= 0:
        raise RuntimeError("--max-runtime-minutes must be greater than 0")
    if (args.policy_name or args.policy_rule_id) and args.skip_policy_rules:
        raise RuntimeError("--skip-policy-rules cannot be used with --policy-name or --policy-rule-id")


def main() -> int:
    args = parse_args()

    try:
        validate_args(args)
        return process(args)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
