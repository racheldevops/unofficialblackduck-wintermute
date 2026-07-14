#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import os
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen


FIELDNAMES = [
    "project",
    "project_version",
    "project_href",
    "project_version_href",
    "project_group_key",
    "project_group_external_id",
    "candidate_key",
    "candidate_external_id",
    "component",
    "component_version",
    "component_origin_id",
    "vulnerability",
    "severity",
    "score_field",
    "score",
    "exploit_available",
    "exploitable",
    "reachable",
    "reachability",
    "reachability_source",
    "policy_name",
    "policy_rule_href",
    "policy_matched",
    "blackduck_url",
    "bom_component_url",
    "finding_key",
    "finding_external_id",
    "first_seen_source",
]

FAILURE_FIELDNAMES = [
    "project",
    "project_version",
    "project_version_href",
    "candidate_external_id",
    "stage",
    "error",
]

CACHE_SCHEMA_VERSION = 1
STATE_SCHEMA_VERSION = 2
MAX_WORKERS = 8
MAX_COMPONENT_WORKERS = 16


@dataclass(frozen=True)
class PullSettings:
    base_url: str
    api_token: str
    bearer_token: str
    insecure: bool
    timeout: int
    retries: int
    retry_delay: float
    page_limit: int
    debug: bool
    threshold: float
    score_operator: str
    score_field: str
    require_exploit_available: bool
    require_reachable: bool
    reachability_mode: str
    policy_name: str
    policy_rule_id: str
    group_by: str
    skip_policy_rules: bool
    include_policy_rule_details: bool
    component_workers: int


@dataclass(frozen=True)
class PullTarget:
    index: int
    candidate: dict[str, str]


@dataclass
class ComponentPullResult:
    findings: list[dict[str, str]]
    failures: list[dict[str, str]]


@dataclass
class CandidatePullResult:
    index: int
    candidate: dict[str, str]
    findings: list[dict[str, str]]
    failures: list[dict[str, str]]
    elapsed_seconds: float
    status: str
    error: str = ""


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


def to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value

    text = str(value or "").strip().lower()

    return text in {
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


def vulnerability_identifier(value: dict[str, Any]) -> str:
    return str(
        first_value_by_key(
            value,
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
        or "UNKNOWN"
    )


def vulnerability_severity(value: dict[str, Any]) -> str:
    return str(
        first_value_by_key(
            value,
            [
                "severity",
                "vulnerabilitySeverity",
                "sourceSeverity",
            ],
        )
        or ""
    ).upper()


def looks_like_vulnerability(value: dict[str, Any], score_field: str) -> bool:
    has_id = first_value_by_key(
        value,
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
    ) is not None

    has_score = first_value_by_key(
        value,
        [
            score_field,
            "overallScore",
            "baseScore",
            "cvssScore",
        ],
    ) is not None

    has_severity = first_value_by_key(
        value,
        [
            "severity",
            "vulnerabilitySeverity",
            "sourceSeverity",
        ],
    ) is not None

    return has_id and (has_score or has_severity)


def extract_vulnerability_candidates(value: Any, score_field: str) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            nested = item.get("vulnerability")

            if isinstance(nested, dict):
                merged = dict(nested)

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
        key = (
            f"{vulnerability_identifier(candidate)}|"
            f"{first_value_by_key(candidate, [score_field, 'overallScore'])}|"
            f"{json.dumps(candidate, sort_keys=True, default=str)[:300]}"
        )

        if key not in seen:
            seen.add(key)
            unique.append(candidate)

    return unique


def extract_exploit_available(value: dict[str, Any]) -> tuple[bool, str]:
    direct = first_value_by_key(
        value,
        [
            "exploitAvailable",
            "exploit_available",
            "exploitable",
            "hasExploit",
            "exploitability",
            "exploitStatus",
        ],
    )

    if direct not in (None, ""):
        return boolish(direct), str(direct)

    for key, item in value.items():
        key_lower = str(key).lower()

        if "exploit" in key_lower and "score" not in key_lower and boolish(item):
            return True, str(item)

    return False, ""


def extract_reachability(value: dict[str, Any]) -> tuple[bool, str, str]:
    direct = first_value_by_key(
        value,
        [
            "reachable",
            "reachability",
            "reachabilityStatus",
            "isReachable",
        ],
    )

    if direct not in (None, ""):
        return boolish(direct), str(direct), "field"

    return False, "", ""


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


class ApiResponseCache:
    def __init__(
        self,
        path: str,
        base_url: str,
        max_age_hours: float,
        max_entries: int,
        refresh: bool,
        debug: bool = False,
    ):
        self.path = path
        self.base_url = base_url.rstrip("/")
        self.max_age_hours = max_age_hours
        self.max_entries = max_entries
        self.debug = debug
        self.lock = threading.RLock()
        self.data: dict[str, Any] = {
            "schema_version": CACHE_SCHEMA_VERSION,
            "base_url": self.base_url,
            "created_at": now_iso(),
            "updated_at": now_iso(),
            "entries": {},
        }

        if refresh:
            print(f"Refreshing API cache; ignoring existing cache at {path}.", file=sys.stderr)
            return

        if not os.path.exists(path):
            print(f"No API cache found at {path}; fresh API reads required.", file=sys.stderr)
            return

        try:
            with open(path, encoding="utf-8") as input_file:
                loaded = json.load(input_file)
        except (OSError, json.JSONDecodeError) as error:
            print(f"Warning: failed to read API cache {path}: {error}; starting fresh.", file=sys.stderr)
            return

        if loaded.get("schema_version") != CACHE_SCHEMA_VERSION:
            print(f"API cache schema mismatch in {path}; starting fresh.", file=sys.stderr)
            return

        if str(loaded.get("base_url") or "").rstrip("/") != self.base_url:
            print("API cache base URL differs from current Black Duck URL; starting fresh.", file=sys.stderr)
            return

        loaded.setdefault("entries", {})
        self.data = loaded
        self.prune()

        print(
            f"Loaded API cache from {path} with {len(self.data.get('entries', {})):,} entrie(s).",
            file=sys.stderr,
        )

    def get_items(self, url: str) -> list[dict[str, Any]] | None:
        key = sha256_hex(url)

        with self.lock:
            entry = self.data.setdefault("entries", {}).get(key)

            if not isinstance(entry, dict):
                return None

            cached_at = parse_iso(str(entry.get("cached_at") or ""))

            if self.max_age_hours >= 0 and (
                not cached_at
                or (datetime.now(timezone.utc) - cached_at).total_seconds() / 3600 >= self.max_age_hours
            ):
                return None

            items = entry.get("items")

            if not isinstance(items, list):
                return None

            entry["last_used_at"] = now_iso()
            entry["hit_count"] = int(entry.get("hit_count") or 0) + 1

            return copy.deepcopy(items)

    def put_items(self, url: str, items: list[dict[str, Any]]) -> None:
        with self.lock:
            entries = self.data.setdefault("entries", {})
            entries[sha256_hex(url)] = {
                "source_url": url,
                "cached_at": now_iso(),
                "last_used_at": now_iso(),
                "hit_count": 0,
                "items": copy.deepcopy(items),
            }

            self.prune_locked()

    def prune(self) -> None:
        with self.lock:
            self.prune_locked()

    def prune_locked(self) -> None:
        entries = self.data.setdefault("entries", {})

        if self.max_age_hours >= 0:
            stale_keys: list[str] = []
            for key, entry in entries.items():
                if not isinstance(entry, dict):
                    stale_keys.append(key)
                    continue

                cached_at = parse_iso(str(entry.get("cached_at") or ""))
                if not cached_at:
                    stale_keys.append(key)
                    continue

                age_hours = (datetime.now(timezone.utc) - cached_at).total_seconds() / 3600
                if age_hours >= self.max_age_hours:
                    stale_keys.append(key)

            for key in stale_keys:
                entries.pop(key, None)

        if len(entries) <= self.max_entries:
            return

        remove_count = len(entries) - self.max_entries
        remove_keys = sorted(
            entries,
            key=lambda key: str((entries.get(key) or {}).get("last_used_at") or ""),
        )[:remove_count]

        for key in remove_keys:
            entries.pop(key, None)

    def save(self) -> None:
        with self.lock:
            self.prune_locked()
            self.data["updated_at"] = now_iso()
            tmp_path = f"{self.path}.tmp"

            with open(tmp_path, "w", encoding="utf-8") as output_file:
                json.dump(self.data, output_file, indent=2, sort_keys=True)

            os.replace(tmp_path, self.path)

        print(
            f"Wrote API cache: {self.path} ({len(self.data.get('entries', {})):,} entrie(s)).",
            file=sys.stderr,
        )


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
        api_cache: ApiResponseCache | None,
        bearer_token: str | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.timeout = timeout
        self.retries = retries
        self.retry_delay = retry_delay
        self.page_limit = page_limit
        self.debug = debug
        self.api_cache = api_cache
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
        headers = {"Accept": "application/json"}

        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"

        token_refreshed = False
        attempt = 0
        max_attempt = self.retries

        while attempt <= max_attempt:
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
                    message = f"HTTP {error.code} {error.reason}: {body[:1000]}"

                    if error.code == 401 and not token_refreshed:
                        token_refreshed = True
                        max_attempt += 1

                        if self.debug:
                            print(
                                f"GET {url} returned HTTP 401; refreshing Black Duck bearer token and retrying once.",
                                file=sys.stderr,
                            )

                        try:
                            self.authenticate()
                        except RuntimeError as auth_error:
                            raise RuntimeError(
                                f"GET {url} failed: HTTP 401 Unauthorized and bearer-token refresh failed: {auth_error}"
                            ) from error

                        if self.bearer_token:
                            headers["Authorization"] = f"Bearer {self.bearer_token}"

                        continue

                    retryable = error.code in {429, 500, 502, 503, 504}
                else:
                    retryable = True
                    message = str(error)

                if not retryable or attempt >= max_attempt:
                    raise RuntimeError(f"GET {url} failed: {message}") from error

                if self.debug:
                    print(f"Retrying GET {url}: {message}", file=sys.stderr)

                time.sleep(self.retry_delay * (attempt + 1))
                attempt += 1

        raise RuntimeError(f"GET {url} failed unexpectedly")

    def paged_get(
        self,
        url_or_path: str,
        params: dict[str, Any] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        source_url = self._make_url(url_or_path, params)

        if self.api_cache:
            cached = self.api_cache.get_items(source_url)
            if cached is not None:
                return cached

        page_limit = limit or self.page_limit
        offset = 0
        all_items: list[dict[str, Any]] = []

        while True:
            page_params = dict(params or {})
            page_params["offset"] = offset
            page_params["limit"] = page_limit

            payload = self.get(url_or_path, page_params)

            if "items" not in payload:
                result = [payload] if payload else []

                if self.api_cache:
                    self.api_cache.put_items(source_url, result)

                return result

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

        if self.api_cache:
            self.api_cache.put_items(source_url, all_items)

        return all_items


def read_candidates(path: str) -> list[dict[str, str]]:
    if path.endswith(".json"):
        with open(path, encoding="utf-8") as input_file:
            payload = json.load(input_file)

        if not isinstance(payload, list):
            raise RuntimeError(f"{path} must contain a JSON array")

        return [
            {str(key): str(value or "") for key, value in row.items()}
            for row in payload
            if isinstance(row, dict)
        ]

    with open(path, newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)

        if not reader.fieldnames:
            raise RuntimeError(f"{path} has no header row")

        return [dict(row) for row in reader]


def read_candidates_with_fieldnames(path: str) -> tuple[list[dict[str, str]], list[str]]:
    if path.endswith(".json"):
        rows = read_candidates(path)
        fieldnames = sorted({key for row in rows for key in row})
        return rows, fieldnames

    with open(path, newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)

        if not reader.fieldnames:
            raise RuntimeError(f"{path} has no header row")

        return [dict(row) for row in reader], list(reader.fieldnames)


def write_candidates_csv(path: str, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp_path = f"{path}.tmp"

    with open(tmp_path, "w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()

        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})

    os.replace(tmp_path, path)


def candidate_matches(row: dict[str, str], args: argparse.Namespace) -> bool:
    if args.project_name and row.get("project") != args.project_name:
        return False

    if args.project_name_contains and args.project_name_contains.lower() not in row.get("project", "").lower():
        return False

    if args.version_name and row.get("project_version") != args.version_name:
        return False

    if args.only_candidate_external_id and row.get("candidate_external_id") != args.only_candidate_external_id:
        return False

    return True


def candidate_identity(candidate: dict[str, str]) -> str:
    explicit = str(candidate.get("candidate_external_id") or "").strip()

    if explicit:
        return explicit

    key = str(candidate.get("candidate_key") or "").strip()

    if not key:
        key = "|".join(
            [
                candidate.get("project", ""),
                candidate.get("project_version", ""),
                canonical_href(candidate.get("project_version_href", "")),
            ]
        )

    return sha256_hex(key)


def get_vulnerable_components(
    client: BlackDuckClient,
    project_version_href: str,
) -> list[dict[str, Any]]:
    try:
        return client.paged_get(f"{project_version_href}/vulnerable-bom-components")
    except RuntimeError:
        version = client.get(project_version_href)
        linked = get_link(
            version,
            (
                "vulnerable-bom-components",
                "vulnerableBomComponents",
                "vulnerable-components",
            ),
        )

        if linked:
            return client.paged_get(linked)

        raise


def should_fetch_policy_rules(settings: PullSettings) -> bool:
    if settings.skip_policy_rules:
        return False

    return bool(
        settings.policy_name
        or settings.policy_rule_id
        or settings.include_policy_rule_details
    )


def get_policy_rules(client: BlackDuckClient, component: dict[str, Any]) -> list[dict[str, Any]]:
    url = get_link(
        component,
        (
            "policy-rules",
            "policyRules",
            "policy-rule",
        ),
    )

    if not url:
        return []

    try:
        return client.paged_get(url)
    except RuntimeError:
        return []


def policy_match(
    policy_rules: list[dict[str, Any]],
    settings: PullSettings,
) -> tuple[bool, str, str]:
    names: list[str] = []
    hrefs: list[str] = []

    if not settings.policy_name and not settings.policy_rule_id:
        if not policy_rules:
            return True, "", ""

    for rule in policy_rules:
        name = str(first_value_by_key(rule, ["name", "policyName", "policyRuleName"]) or "")
        href = canonical_href(get_self_href(rule) or get_link(rule, ("self",)))

        if name:
            names.append(name)

        if href:
            hrefs.append(href)

        if settings.policy_name and name == settings.policy_name:
            return True, name, href

        if settings.policy_rule_id and settings.policy_rule_id in href:
            return True, name, href

    if settings.policy_name or settings.policy_rule_id:
        return False, "", ""

    return True, ";".join(sorted(set(names))), ";".join(sorted(set(hrefs)))


def score_passes(score: float | None, settings: PullSettings) -> bool:
    if score is None:
        return False

    if settings.score_operator == "gte":
        return score >= settings.threshold

    return score > settings.threshold


def build_project_group_key(project: str, project_version: str, group_by: str) -> str:
    if group_by == "project-version":
        return "|".join([project, project_version])

    return project


def build_finding_key(
    project: str,
    project_version: str,
    component: str,
    component_version: str,
    vulnerability: str,
) -> str:
    return "|".join([project, project_version, component, component_version, vulnerability])


def failure_for_candidate(
    candidate: dict[str, str],
    stage: str,
    error: Exception | str,
) -> dict[str, str]:
    return {
        "project": candidate.get("project", ""),
        "project_version": candidate.get("project_version", ""),
        "project_version_href": candidate.get("project_version_href", ""),
        "candidate_external_id": candidate_identity(candidate),
        "stage": stage,
        "error": str(error),
    }


def collect_for_component(
    client: BlackDuckClient,
    candidate: dict[str, str],
    component: dict[str, Any],
    settings: PullSettings,
    fetch_policy_rules: bool,
) -> ComponentPullResult:
    project = candidate.get("project", "")
    project_version = candidate.get("project_version", "")
    project_href = candidate.get("project_href", "")
    project_version_href = canonical_href(candidate.get("project_version_href", ""))

    try:
        component_name = str(first_value_by_key(component, ["componentName", "name"]) or "")
        component_version = str(
            first_value_by_key(
                component,
                [
                    "componentVersionName",
                    "componentVersion",
                    "versionName",
                ],
            )
            or ""
        )
        component_origin_id = str(
            first_value_by_key(
                component,
                [
                    "componentOriginId",
                    "originId",
                    "externalId",
                ],
            )
            or ""
        )
        bom_component_url = canonical_href(get_self_href(component))

        policy_rules = get_policy_rules(client, component) if fetch_policy_rules else []
        matched_policy, policy_name, policy_href = policy_match(policy_rules, settings)

        if not matched_policy:
            return ComponentPullResult(findings=[], failures=[])

        vulnerabilities_url = get_link(component, ("vulnerabilities", "vulnerability"))
        vulnerability_items: list[dict[str, Any]] = []

        if vulnerabilities_url:
            for item in client.paged_get(vulnerabilities_url):
                extracted = extract_vulnerability_candidates(item, settings.score_field)
                vulnerability_items.extend(extracted or [item])
        else:
            vulnerability_items.extend(extract_vulnerability_candidates(component, settings.score_field))

        findings: list[dict[str, str]] = []

        for vulnerability in vulnerability_items:
            vulnerability_id = vulnerability_identifier(vulnerability)
            score = to_float(
                first_value_by_key(
                    vulnerability,
                    [
                        settings.score_field,
                        "overallScore",
                        "baseScore",
                        "cvssScore",
                    ],
                )
            )

            if not score_passes(score, settings):
                continue

            exploit_available, exploit_raw = extract_exploit_available(vulnerability)

            if settings.require_exploit_available and not exploit_available:
                continue

            reachable, reachability_raw, reachability_source = extract_reachability(vulnerability)

            if settings.require_reachable and not reachable:
                continue

            if settings.reachability_mode == "ai" and not reachability_source:
                reachability_source = "ai-reserved"

            group_key = build_project_group_key(project, project_version, settings.group_by)
            finding_key = build_finding_key(
                project,
                project_version,
                component_name,
                component_version,
                vulnerability_id,
            )

            blackduck_url = canonical_href(
                get_link(vulnerability, ("self",)) or get_self_href(vulnerability)
            )

            findings.append(
                {
                    "project": project,
                    "project_version": project_version,
                    "project_href": project_href,
                    "project_version_href": project_version_href,
                    "project_group_key": group_key,
                    "project_group_external_id": sha256_hex(group_key),
                    "candidate_key": candidate.get("candidate_key", ""),
                    "candidate_external_id": candidate_identity(candidate),
                    "component": component_name,
                    "component_version": component_version,
                    "component_origin_id": component_origin_id,
                    "vulnerability": vulnerability_id,
                    "severity": vulnerability_severity(vulnerability),
                    "score_field": settings.score_field,
                    "score": "" if score is None else str(score),
                    "exploit_available": str(bool(exploit_available)).lower(),
                    "exploitable": exploit_raw,
                    "reachable": str(bool(reachable)).lower(),
                    "reachability": reachability_raw,
                    "reachability_source": reachability_source,
                    "policy_name": policy_name,
                    "policy_rule_href": policy_href,
                    "policy_matched": str(bool(matched_policy)).lower(),
                    "blackduck_url": blackduck_url,
                    "bom_component_url": bom_component_url,
                    "finding_key": finding_key,
                    "finding_external_id": sha256_hex(finding_key),
                    "first_seen_source": "blackduck-policy-vuln-pull",
                }
            )

        return ComponentPullResult(findings=findings, failures=[])

    except Exception as error:
        component_label = " ".join(
            str(part or "").strip()
            for part in [
                first_value_by_key(component, ["componentName", "name"]),
                first_value_by_key(component, ["componentVersionName", "componentVersion", "versionName"]),
            ]
            if str(part or "").strip()
        ) or canonical_href(get_self_href(component)) or "unknown component"

        return ComponentPullResult(
            findings=[],
            failures=[
                failure_for_candidate(
                    candidate,
                    "component-details",
                    f"{component_label}: {error}",
                )
            ],
        )


def collect_for_candidate(
    client: BlackDuckClient,
    candidate: dict[str, str],
    settings: PullSettings,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    project_version_href = canonical_href(candidate.get("project_version_href", ""))

    if not project_version_href:
        raise RuntimeError("candidate row has no project_version_href")

    components = get_vulnerable_components(client, project_version_href)
    fetch_policy_rules = should_fetch_policy_rules(settings)

    if settings.debug:
        print(
            f"Candidate {candidate.get('project', '')} / {candidate.get('project_version', '')}: "
            f"{len(components):,} vulnerable component(s), component_workers={settings.component_workers}",
            file=sys.stderr,
        )

    findings: list[dict[str, str]] = []
    failures: list[dict[str, str]] = []

    if settings.component_workers <= 1 or len(components) <= 1:
        for component in components:
            result = collect_for_component(
                client=client,
                candidate=candidate,
                component=component,
                settings=settings,
                fetch_policy_rules=fetch_policy_rules,
            )
            findings.extend(result.findings)
            failures.extend(result.failures)
        return findings, failures

    max_workers = min(settings.component_workers, len(components))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_component = {
            executor.submit(
                collect_for_component,
                client,
                candidate,
                component,
                settings,
                fetch_policy_rules,
            ): component
            for component in components
        }

        for future in future_to_component:
            try:
                result = future.result()
            except Exception as error:
                component = future_to_component[future]
                component_label = canonical_href(get_self_href(component)) or "unknown component"
                result = ComponentPullResult(
                    findings=[],
                    failures=[
                        failure_for_candidate(
                            candidate,
                            "component-details",
                            f"{component_label}: {error}",
                        )
                    ],
                )

            findings.extend(result.findings)
            failures.extend(result.failures)

    return findings, failures


def is_auth_failure_text(value: object) -> bool:
    text = str(value or "").lower()

    return (
        "http 401" in text
        or "401 unauthorized" in text
        or "unauthorized" in text
        or "bearer-token refresh" in text
    )


def result_has_auth_failures(result: CandidatePullResult) -> bool:
    if is_auth_failure_text(result.error):
        return True

    for failure in result.failures:
        if is_auth_failure_text(failure.get("error", "")):
            return True

    return False


def build_candidate_client(
    settings: PullSettings,
    api_cache: ApiResponseCache | None,
    bearer_token: str | None = None,
) -> BlackDuckClient:
    return BlackDuckClient(
        base_url=settings.base_url,
        api_token=settings.api_token,
        insecure=settings.insecure,
        timeout=settings.timeout,
        retries=settings.retries,
        retry_delay=settings.retry_delay,
        page_limit=settings.page_limit,
        debug=settings.debug,
        api_cache=api_cache,
        bearer_token=bearer_token if bearer_token is not None else settings.bearer_token,
    )


def pull_one_candidate(
    settings: PullSettings,
    api_cache: ApiResponseCache | None,
    target: PullTarget,
) -> CandidatePullResult:
    start_seconds = time.monotonic()
    max_auth_retry_count = 2
    last_result: CandidatePullResult | None = None

    for auth_retry_index in range(max_auth_retry_count + 1):
        client = build_candidate_client(settings, api_cache)

        if auth_retry_index > 0:
            try:
                client.authenticate()
            except Exception as auth_error:
                result = CandidatePullResult(
                    index=target.index,
                    candidate=target.candidate,
                    findings=[],
                    failures=[
                        failure_for_candidate(
                            target.candidate,
                            "refresh-auth",
                            auth_error,
                        )
                    ],
                    elapsed_seconds=time.monotonic() - start_seconds,
                    status="failed",
                    error=str(auth_error),
                )
                last_result = result

                if auth_retry_index >= max_auth_retry_count:
                    return result

                time.sleep(settings.retry_delay * auth_retry_index)
                continue

        try:
            findings, failures = collect_for_candidate(client, target.candidate, settings)
            result = CandidatePullResult(
                index=target.index,
                candidate=target.candidate,
                findings=findings,
                failures=failures,
                elapsed_seconds=time.monotonic() - start_seconds,
                status="partial" if failures else "ok",
            )
        except Exception as error:
            result = CandidatePullResult(
                index=target.index,
                candidate=target.candidate,
                findings=[],
                failures=[failure_for_candidate(target.candidate, "collect-details", error)],
                elapsed_seconds=time.monotonic() - start_seconds,
                status="failed",
                error=str(error),
            )

        last_result = result

        if not result_has_auth_failures(result):
            return result

        if auth_retry_index >= max_auth_retry_count:
            return result

        print(
            f"Warning: auth-related failure while pulling "
            f"{target.candidate.get('project', '')} / "
            f"{target.candidate.get('project_version', '')}; "
            f"refreshing bearer token and retrying candidate "
            f"{auth_retry_index + 1}/{max_auth_retry_count}.",
            file=sys.stderr,
        )

        time.sleep(settings.retry_delay * (auth_retry_index + 1))

    assert last_result is not None
    return last_result

def atomic_write_json(path: str, payload: Any) -> None:
    if path == "-":
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        print()
        return

    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as output_file:
        json.dump(payload, output_file, indent=2, sort_keys=True)
    os.replace(tmp_path, path)


def write_findings(path: str, rows: list[dict[str, str]], json_mode: bool) -> None:
    if json_mode:
        atomic_write_json(path, rows)
        return

    if path == "-":
        output_file = sys.stdout
        close_after = False
        tmp_path = ""
    else:
        tmp_path = f"{path}.tmp"
        output_file = open(tmp_path, "w", newline="", encoding="utf-8")
        close_after = True

    try:
        writer = csv.DictWriter(output_file, fieldnames=FIELDNAMES)
        writer.writeheader()

        for row in rows:
            writer.writerow({field: row.get(field, "") for field in FIELDNAMES})
    finally:
        if close_after:
            output_file.close()

    if path != "-":
        os.replace(tmp_path, path)


def write_failures(path: str, rows: list[dict[str, str]]) -> None:
    if not path:
        return

    tmp_path = f"{path}.tmp"

    with open(tmp_path, "w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=FAILURE_FIELDNAMES)
        writer.writeheader()

        for row in rows:
            writer.writerow({field: row.get(field, "") for field in FAILURE_FIELDNAMES})

    os.replace(tmp_path, path)


def sort_findings(findings: list[dict[str, str]]) -> list[dict[str, str]]:
    return sorted(
        findings,
        key=lambda row: (
            row.get("project", "").lower(),
            row.get("project_version", "").lower(),
            -(to_float(row.get("score")) or 0.0),
            row.get("vulnerability", ""),
        ),
    )


def sort_failures(failures: list[dict[str, str]]) -> list[dict[str, str]]:
    return sorted(
        failures,
        key=lambda row: (
            row.get("project", "").lower(),
            row.get("project_version", "").lower(),
            row.get("stage", ""),
            row.get("error", ""),
        ),
    )


def runtime_limit_reached(args: argparse.Namespace, start_seconds: float) -> bool:
    if args.max_runtime_minutes is None:
        return False
    return (time.monotonic() - start_seconds) >= (args.max_runtime_minutes * 60.0)


def print_progress(
    completed: int,
    total: int,
    finding_count: int,
    failure_count: int,
    start_seconds: float,
    progress_every: int,
    force: bool = False,
) -> None:
    if total <= 0:
        return

    if not force and completed % progress_every != 0:
        return

    elapsed = format_duration(time.monotonic() - start_seconds)
    remaining = max(0, total - completed)
    print(
        f"[{completed}/{total}] candidates pulled, findings={finding_count}, "
        f"failures={failure_count}, remaining={remaining}, elapsed={elapsed}",
        file=sys.stderr,
    )


def state_path_for_args(args: argparse.Namespace) -> str:
    if args.state:
        return args.state

    if args.out and args.out != "-":
        return f"{args.out}.state.json"

    return "policy_vuln_pull_state.json"


def settings_signature(args: argparse.Namespace) -> str:
    payload = {
        "bd_url": str(args.bd_url or "").rstrip("/"),
        "threshold": args.threshold,
        "score_operator": args.score_operator,
        "score_field": args.score_field,
        "require_exploit_available": bool(args.require_exploit_available),
        "require_reachable": bool(args.require_reachable),
        "reachability_mode": args.reachability_mode,
        "policy_name": args.policy_name or "",
        "policy_rule_id": args.policy_rule_id or "",
        "group_by": args.group_by,
        "skip_policy_rules": bool(args.skip_policy_rules),
        "include_policy_rule_details": bool(args.include_policy_rule_details),
    }
    return sha256_hex(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def fresh_state(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "settings_signature": settings_signature(args),
        "completed_candidates": {},
    }


def load_state(path: str, args: argparse.Namespace) -> dict[str, Any]:
    if not args.resume or not path or not os.path.exists(path):
        return fresh_state(args)

    try:
        with open(path, encoding="utf-8") as input_file:
            state = json.load(input_file)
    except (OSError, json.JSONDecodeError) as error:
        print(f"Warning: failed reading resume state {path}: {error}; starting fresh.", file=sys.stderr)
        return fresh_state(args)

    if not isinstance(state, dict) or state.get("schema_version") != STATE_SCHEMA_VERSION:
        print(f"Warning: resume state {path} has incompatible schema; starting fresh.", file=sys.stderr)
        return fresh_state(args)

    if str(state.get("settings_signature") or "") != settings_signature(args):
        print(
            f"Warning: resume state {path} was created with different pull settings; starting fresh.",
            file=sys.stderr,
        )
        return fresh_state(args)

    state.setdefault("completed_candidates", {})
    return state


def save_state(path: str, state: dict[str, Any]) -> None:
    if not path:
        return

    state["updated_at"] = now_iso()
    tmp_path = f"{path}.tmp"

    with open(tmp_path, "w", encoding="utf-8") as output_file:
        json.dump(state, output_file, indent=2, sort_keys=True)

    os.replace(tmp_path, path)


def state_entry_from_result(result: CandidatePullResult) -> dict[str, Any]:
    return {
        "candidate_external_id": candidate_identity(result.candidate),
        "candidate": result.candidate,
        "status": result.status,
        "error": result.error,
        "elapsed_seconds": round(result.elapsed_seconds, 3),
        "completed_at": now_iso(),
        "finding_count": len(result.findings),
        "failure_count": len(result.failures),
        "findings": result.findings,
        "failures": result.failures,
    }


def load_completed_from_state(
    state: dict[str, Any],
    candidates: list[dict[str, str]],
) -> tuple[list[dict[str, str]], list[dict[str, str]], set[str], set[str]]:
    wanted_candidate_ids = {candidate_identity(candidate) for candidate in candidates}
    completed_candidates = state.setdefault("completed_candidates", {})

    findings: list[dict[str, str]] = []
    failures: list[dict[str, str]] = []
    seen_finding_ids: set[str] = set()
    completed_candidate_ids: set[str] = set()

    for candidate_id, entry in completed_candidates.items():
        if candidate_id not in wanted_candidate_ids:
            continue

        if not isinstance(entry, dict):
            continue

        completed_candidate_ids.add(candidate_id)

        for finding in entry.get("findings") or []:
            if not isinstance(finding, dict):
                continue

            finding_id = str(finding.get("finding_external_id") or "")
            if not finding_id or finding_id in seen_finding_ids:
                continue

            seen_finding_ids.add(finding_id)
            findings.append({str(key): str(value or "") for key, value in finding.items()})

        for failure in entry.get("failures") or []:
            if isinstance(failure, dict):
                failures.append({str(key): str(value or "") for key, value in failure.items()})

    return findings, failures, seen_finding_ids, completed_candidate_ids


def persist_checkpoint(
    api_cache: ApiResponseCache | None,
    state_path: str,
    state: dict[str, Any],
    findings: list[dict[str, str]],
    failures: list[dict[str, str]],
    args: argparse.Namespace,
    partial_out: str,
) -> None:
    save_state(state_path, state)
    print(f"Saved resume state: {state_path}", file=sys.stderr)

    if api_cache is not None:
        api_cache.save()

    if partial_out:
        write_findings(partial_out, sort_findings(findings), args.json)
        print(f"Wrote partial findings: {partial_out}", file=sys.stderr)

    if args.failures_out:
        partial_failures = f"{args.failures_out}.partial"
        write_failures(partial_failures, sort_failures(failures))
        print(f"Wrote partial failures: {partial_failures}", file=sys.stderr)


def remove_partial_output(path: str) -> None:
    if not path or path == "-":
        return

    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError as error:
        print(f"Warning: failed removing partial output {path}: {error}", file=sys.stderr)


def build_settings(args: argparse.Namespace, bearer_token: str) -> PullSettings:
    return PullSettings(
        base_url=args.bd_url,
        api_token=args.api_token,
        bearer_token=bearer_token,
        insecure=args.insecure,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        page_limit=args.page_limit,
        debug=args.debug,
        threshold=args.threshold,
        score_operator=args.score_operator,
        score_field=args.score_field,
        require_exploit_available=bool(args.require_exploit_available),
        require_reachable=bool(args.require_reachable),
        reachability_mode=args.reachability_mode,
        policy_name=args.policy_name or "",
        policy_rule_id=args.policy_rule_id or "",
        group_by=args.group_by,
        skip_policy_rules=bool(args.skip_policy_rules),
        include_policy_rule_details=bool(args.include_policy_rule_details),
        component_workers=args.component_workers,
    )


def maybe_print_heartbeat(
    args: argparse.Namespace,
    last_heartbeat_seconds: float,
    run_start_seconds: float,
    completed_count: int,
    total: int,
    finding_count: int,
    failure_count: int,
    pending: dict[Future[CandidatePullResult], PullTarget],
    active_started_at: dict[Future[CandidatePullResult], float],
    force: bool = False,
) -> float:
    if args.heartbeat_every <= 0:
        return last_heartbeat_seconds

    now_seconds = time.monotonic()

    if not force and (now_seconds - last_heartbeat_seconds) < args.heartbeat_every:
        return last_heartbeat_seconds

    elapsed = format_duration(now_seconds - run_start_seconds)
    active_count = len(pending)
    remaining = max(0, total - completed_count)

    active_rows: list[tuple[float, PullTarget]] = []
    for future, target in pending.items():
        active_rows.append((now_seconds - active_started_at.get(future, now_seconds), target))

    active_rows.sort(key=lambda item: item[0], reverse=True)
    longest = format_duration(active_rows[0][0]) if active_rows else "0m 0s"
    active_labels = [
        f"#{target.index} {target.candidate.get('project', '')} / "
        f"{target.candidate.get('project_version', '')} active={format_duration(age)}"
        for age, target in active_rows[: min(5, len(active_rows))]
    ]

    print(
        f"[heartbeat] completed={completed_count}/{total}, active={active_count}, "
        f"findings={finding_count}, failures={failure_count}, remaining={remaining}, "
        f"longest_active={longest}, elapsed={elapsed}",
        file=sys.stderr,
    )

    for label in active_labels:
        print(f"[heartbeat]   {label}", file=sys.stderr)

    return now_seconds


def process(args: argparse.Namespace) -> int:
    if args.shard_count > 1 and not args.shard_worker:
        return run_sharded(args)

    run_start_seconds = time.monotonic()

    partial_out = args.partial_out
    if partial_out is None:
        partial_out = "" if args.out == "-" else f"{args.out}.partial"

    state_path = state_path_for_args(args)
    state = load_state(state_path, args)

    api_cache = (
        None
        if args.no_api_cache
        else ApiResponseCache(
            path=args.api_cache,
            base_url=args.bd_url,
            max_age_hours=args.api_cache_max_age_hours,
            max_entries=args.api_cache_max_entries,
            refresh=args.refresh_api_cache,
            debug=args.debug,
        )
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

        if not client.bearer_token:
            raise RuntimeError("Authentication succeeded but no bearer token was returned")

        settings = build_settings(args, client.bearer_token)

        candidates = [
            row
            for row in read_candidates(args.candidates)
            if candidate_matches(row, args)
        ]

        if args.limit_candidates is not None:
            candidates = candidates[: args.limit_candidates]

        findings, failures, seen_finding_ids, completed_candidate_ids = load_completed_from_state(
            state,
            candidates,
        )

        targets = [
            PullTarget(index=index, candidate=candidate)
            for index, candidate in enumerate(candidates, start=1)
            if candidate_identity(candidate) not in completed_candidate_ids
        ]

        completed_count = len(completed_candidate_ids)

        print(
            f"Loaded {len(candidates):,} candidate(s) from {args.candidates}.",
            file=sys.stderr,
        )
        print(
            f"Resume state: {state_path}; already completed={completed_count:,}; "
            f"remaining to schedule={len(targets):,}.",
            file=sys.stderr,
        )
        print(
            f"Pulling with workers={args.workers}, component_workers={args.component_workers}, "
            f"threshold={args.score_operator} {args.threshold}, score_field={args.score_field}, "
            f"require_exploit_available={args.require_exploit_available}.",
            file=sys.stderr,
        )

        if args.policy_name or args.policy_rule_id:
            print("Policy filter enabled; policy-rule links will be followed as needed.", file=sys.stderr)
        elif args.include_policy_rule_details:
            print("Policy rule detail collection enabled; this can be slower.", file=sys.stderr)
        else:
            print("Policy rule detail traversal disabled unless policy filters are supplied.", file=sys.stderr)

        runtime_limited = False
        finding_limit_reached = False
        interrupted = False
        last_heartbeat_seconds = 0.0

        def apply_result(result: CandidatePullResult) -> None:
            nonlocal finding_limit_reached

            candidate_id = candidate_identity(result.candidate)
            state.setdefault("completed_candidates", {})[candidate_id] = state_entry_from_result(result)
            save_state(state_path, state)

            failures.extend(result.failures)

            if result.status == "failed":
                print(
                    f"Warning: failed pulling {result.candidate.get('project', '')} / "
                    f"{result.candidate.get('project_version', '')}: {result.error}",
                    file=sys.stderr,
                )
            elif result.status == "partial":
                print(
                    f"Warning: partial pull for {result.candidate.get('project', '')} / "
                    f"{result.candidate.get('project_version', '')}: "
                    f"{len(result.failures)} component-level failure(s)",
                    file=sys.stderr,
                )

            for finding in result.findings:
                finding_id = finding["finding_external_id"]

                if finding_id in seen_finding_ids:
                    continue

                if args.limit_findings is not None and len(findings) >= args.limit_findings:
                    finding_limit_reached = True
                    break

                seen_finding_ids.add(finding_id)
                findings.append(finding)

                if args.limit_findings is not None and len(findings) >= args.limit_findings:
                    finding_limit_reached = True
                    break

        try:
            if args.workers == 1:
                for target in targets:
                    if runtime_limit_reached(args, run_start_seconds):
                        runtime_limited = True
                        break

                    if finding_limit_reached:
                        break

                    if args.debug:
                        print(
                            f"[{target.index}/{len(candidates)}] Pulling "
                            f"{target.candidate.get('project')} / {target.candidate.get('project_version')}",
                            file=sys.stderr,
                        )

                    result = pull_one_candidate(settings, api_cache, target)
                    apply_result(result)
                    completed_count += 1

                    print_progress(
                        completed=completed_count,
                        total=len(candidates),
                        finding_count=len(findings),
                        failure_count=len(failures),
                        start_seconds=run_start_seconds,
                        progress_every=args.progress_every,
                    )

                    if completed_count % args.cache_save_every == 0:
                        persist_checkpoint(api_cache, state_path, state, findings, failures, args, partial_out)

            elif targets:
                executor: ThreadPoolExecutor | None = ThreadPoolExecutor(max_workers=args.workers)
                pending: dict[Future[CandidatePullResult], PullTarget] = {}
                active_started_at: dict[Future[CandidatePullResult], float] = {}
                next_index = 0

                def submit_more() -> None:
                    nonlocal next_index, runtime_limited

                    while (
                        executor is not None
                        and len(pending) < args.workers
                        and next_index < len(targets)
                        and not finding_limit_reached
                    ):
                        if runtime_limit_reached(args, run_start_seconds):
                            runtime_limited = True
                            return

                        target = targets[next_index]
                        next_index += 1

                        if args.debug:
                            print(
                                f"[schedule {target.index}/{len(candidates)}] Pulling "
                                f"{target.candidate.get('project')} / {target.candidate.get('project_version')}",
                                file=sys.stderr,
                            )

                        future = executor.submit(pull_one_candidate, settings, api_cache, target)
                        pending[future] = target
                        active_started_at[future] = time.monotonic()

                try:
                    submit_more()

                    while pending:
                        done, _ = wait(pending, timeout=1.0, return_when=FIRST_COMPLETED)

                        if not done:
                            last_heartbeat_seconds = maybe_print_heartbeat(
                                args=args,
                                last_heartbeat_seconds=last_heartbeat_seconds,
                                run_start_seconds=run_start_seconds,
                                completed_count=completed_count,
                                total=len(candidates),
                                finding_count=len(findings),
                                failure_count=len(failures),
                                pending=pending,
                                active_started_at=active_started_at,
                            )

                            if runtime_limit_reached(args, run_start_seconds):
                                runtime_limited = True
                            continue

                        for future in done:
                            target = pending.pop(future)
                            active_started_at.pop(future, None)

                            try:
                                result = future.result()
                            except Exception as error:
                                result = CandidatePullResult(
                                    index=target.index,
                                    candidate=target.candidate,
                                    findings=[],
                                    failures=[failure_for_candidate(target.candidate, "collect-details", error)],
                                    elapsed_seconds=0.0,
                                    status="failed",
                                    error=str(error),
                                )

                            apply_result(result)
                            completed_count += 1

                            print_progress(
                                completed=completed_count,
                                total=len(candidates),
                                finding_count=len(findings),
                                failure_count=len(failures),
                                start_seconds=run_start_seconds,
                                progress_every=args.progress_every,
                            )

                            if completed_count % args.cache_save_every == 0:
                                persist_checkpoint(api_cache, state_path, state, findings, failures, args, partial_out)

                        if runtime_limit_reached(args, run_start_seconds):
                            runtime_limited = True

                        if not runtime_limited and not finding_limit_reached:
                            submit_more()

                except KeyboardInterrupt:
                    interrupted = True
                    for future in pending:
                        future.cancel()
                    raise

                finally:
                    if executor is not None:
                        executor.shutdown(wait=not interrupted, cancel_futures=interrupted)

        except KeyboardInterrupt:
            interrupted = True
            print("Interrupted; saving API cache, resume state, and partial output...", file=sys.stderr)

        persist_checkpoint(api_cache, state_path, state, findings, failures, args, partial_out)

        if interrupted:
            return 130

        if runtime_limited:
            print(
                f"Runtime limit reached after {format_duration(time.monotonic() - run_start_seconds)}; "
                "writing outputs for completed work.",
                file=sys.stderr,
            )

        if finding_limit_reached:
            print(
                f"Finding limit reached at {len(findings):,} finding(s); writing completed output.",
                file=sys.stderr,
            )

        print_progress(
            completed=completed_count,
            total=len(candidates),
            finding_count=len(findings),
            failure_count=len(failures),
            start_seconds=run_start_seconds,
            progress_every=args.progress_every,
            force=True,
        )

        findings = sort_findings(findings)
        failures = sort_failures(failures)

        write_findings(args.out, findings, args.json)
        write_failures(args.failures_out or "", failures)

        remove_partial_output(partial_out)

        if args.failures_out:
            remove_partial_output(f"{args.failures_out}.partial")

        elapsed_seconds = time.monotonic() - run_start_seconds
        remaining_count = max(0, len(candidates) - completed_count)

        print(
            f"Pulled {len(findings):,} high-risk finding(s) from "
            f"{completed_count:,}/{len(candidates):,} completed candidate(s); "
            f"failures={len(failures):,}; remaining={remaining_count:,}; "
            f"elapsed={format_duration(elapsed_seconds)}.",
            file=sys.stderr,
        )

        if runtime_limited:
            print("Runtime limited: true", file=sys.stderr)

        return 1 if failures else 0

    finally:
        if api_cache is not None:
            api_cache.save()


def merge_findings_files(paths: list[str], output_path: str, json_mode: bool) -> int:
    rows: list[dict[str, str]] = []
    seen: set[str] = set()

    for path in paths:
        if not os.path.exists(path):
            continue

        if path.endswith(".json"):
            with open(path, encoding="utf-8") as input_file:
                payload = json.load(input_file)
            shard_rows = payload if isinstance(payload, list) else []
        else:
            with open(path, newline="", encoding="utf-8") as input_file:
                reader = csv.DictReader(input_file)
                shard_rows = [dict(row) for row in reader]

        for row in shard_rows:
            if not isinstance(row, dict):
                continue

            finding_id = str(row.get("finding_external_id") or row.get("finding_key") or "")

            if not finding_id:
                finding_id = sha256_hex(json.dumps(row, sort_keys=True, default=str))

            if finding_id in seen:
                continue

            seen.add(finding_id)
            rows.append({str(key): str(value or "") for key, value in row.items()})

    write_findings(output_path, sort_findings(rows), json_mode)
    return len(rows)


def merge_failure_files(paths: list[str], output_path: str) -> int:
    if not output_path:
        return 0

    rows: list[dict[str, str]] = []

    for path in paths:
        if not os.path.exists(path):
            continue

        with open(path, newline="", encoding="utf-8") as input_file:
            reader = csv.DictReader(input_file)
            rows.extend({str(key): str(value or "") for key, value in row.items()} for row in reader)

    write_failures(output_path, sort_failures(rows))
    return len(rows)


def run_sharded(args: argparse.Namespace) -> int:
    run_start_seconds = time.monotonic()
    os.makedirs(args.shard_dir, exist_ok=True)

    rows, fieldnames = read_candidates_with_fieldnames(args.candidates)
    rows = [row for row in rows if candidate_matches(row, args)]

    if args.limit_candidates is not None:
        rows = rows[: args.limit_candidates]

    if not rows:
        raise RuntimeError("No candidates matched filters; nothing to shard")

    shard_count = min(args.shard_count, len(rows))
    shard_rows: list[list[dict[str, str]]] = [[] for _ in range(shard_count)]

    for index, row in enumerate(rows):
        shard_rows[index % shard_count].append(row)

    shard_candidate_paths: list[str] = []
    shard_findings_paths: list[str] = []
    shard_failures_paths: list[str] = []
    shard_state_paths: list[str] = []
    shard_cache_paths: list[str] = []
    processes: list[tuple[int, subprocess.Popen[bytes]]] = []

    base_out = os.path.basename(args.out if args.out != "-" else "policy_findings.csv")
    base_failures = os.path.basename(args.failures_out or "policy_pull_failures.csv")
    base_cache = os.path.basename(args.api_cache)
    script_path = os.path.abspath(__file__)

    for shard_index, shard in enumerate(shard_rows, start=1):
        shard_name = f"part{shard_index:02d}-of-{shard_count:02d}"
        shard_candidate_path = os.path.join(args.shard_dir, f"policy_candidate_projects.{shard_name}.csv")
        shard_findings_path = os.path.join(args.shard_dir, f"{base_out}.{shard_name}")
        shard_failures_path = os.path.join(args.shard_dir, f"{base_failures}.{shard_name}")
        shard_state_path = os.path.join(args.shard_dir, f"{base_out}.{shard_name}.state.json")
        shard_cache_path = os.path.join(args.shard_dir, f"{base_cache}.{shard_name}")

        write_candidates_csv(shard_candidate_path, shard, fieldnames)

        shard_candidate_paths.append(shard_candidate_path)
        shard_findings_paths.append(shard_findings_path)
        shard_failures_paths.append(shard_failures_path)
        shard_state_paths.append(shard_state_path)
        shard_cache_paths.append(shard_cache_path)

    print(
        f"Sharded {len(rows):,} candidate(s) into {shard_count} shard(s) in {args.shard_dir}.",
        file=sys.stderr,
    )
    print(
        f"Each shard uses workers={args.workers}, component_workers={args.component_workers}; "
        f"maximum theoretical API lanes ~= {shard_count * args.workers * args.component_workers}.",
        file=sys.stderr,
    )

    env = os.environ.copy()
    env["BLACKDUCK_URL"] = args.bd_url
    env["BLACKDUCK_API_TOKEN"] = args.api_token

    for shard_index in range(shard_count):
        command = [
            sys.executable,
            script_path,
            "--shard-worker",
            "--candidates",
            shard_candidate_paths[shard_index],
            "--out",
            shard_findings_paths[shard_index],
            "--failures-out",
            shard_failures_paths[shard_index],
            "--state",
            shard_state_paths[shard_index],
            "--threshold",
            str(args.threshold),
            "--score-operator",
            args.score_operator,
            "--score-field",
            args.score_field,
            "--group-by",
            args.group_by,
            "--workers",
            str(args.workers),
            "--component-workers",
            str(args.component_workers),
            "--page-limit",
            str(args.page_limit),
            "--timeout",
            str(args.timeout),
            "--retries",
            str(args.retries),
            "--retry-delay",
            str(args.retry_delay),
            "--progress-every",
            str(args.progress_every),
            "--cache-save-every",
            str(args.cache_save_every),
            "--heartbeat-every",
            str(args.heartbeat_every),
            "--partial-out",
            f"{shard_findings_paths[shard_index]}.partial",
        ]

        if not args.no_api_cache:
            command.extend(
                [
                    "--api-cache",
                    shard_cache_paths[shard_index],
                    "--api-cache-max-age-hours",
                    str(args.api_cache_max_age_hours),
                    "--api-cache-max-entries",
                    str(args.api_cache_max_entries),
                ]
            )
        else:
            command.append("--no-api-cache")

        if args.refresh_api_cache:
            command.append("--refresh-api-cache")
        if args.insecure:
            command.append("--insecure")
        if args.json:
            command.append("--json")
        if args.debug:
            command.append("--debug")
        if args.resume:
            command.append("--resume")
        else:
            command.append("--no-resume")
        if args.require_exploit_available:
            command.append("--require-exploit-available")
        else:
            command.append("--no-require-exploit-available")
        if args.require_reachable:
            command.append("--require-reachable")
        if args.reachability_mode:
            command.extend(["--reachability-mode", args.reachability_mode])
        if args.policy_name:
            command.extend(["--policy-name", args.policy_name])
        if args.policy_rule_id:
            command.extend(["--policy-rule-id", args.policy_rule_id])
        if args.skip_policy_rules:
            command.append("--skip-policy-rules")
        if args.include_policy_rule_details:
            command.append("--include-policy-rule-details")
        if args.limit_findings is not None:
            print(
                "Warning: --limit-findings is not applied globally in sharded mode; "
                "omit sharding when using --limit-findings for precise tests.",
                file=sys.stderr,
            )

        print(f"[shard {shard_index + 1}/{shard_count}] starting: {shard_candidate_paths[shard_index]}", file=sys.stderr)
        processes.append((shard_index + 1, subprocess.Popen(command, env=env)))

    last_heartbeat_seconds = 0.0
    interrupted = False

    try:
        while processes:
            remaining: list[tuple[int, subprocess.Popen[bytes]]] = []

            for shard_index, process_handle in processes:
                return_code = process_handle.poll()

                if return_code is None:
                    remaining.append((shard_index, process_handle))
                else:
                    print(f"[shard {shard_index}/{shard_count}] exited with code {return_code}", file=sys.stderr)

            processes = remaining

            now_seconds = time.monotonic()
            if args.heartbeat_every > 0 and (now_seconds - last_heartbeat_seconds) >= args.heartbeat_every:
                running = ", ".join(str(shard_index) for shard_index, _ in processes) or "none"
                print(
                    f"[shard heartbeat] running_shards={running}, "
                    f"remaining_processes={len(processes)}, elapsed={format_duration(now_seconds - run_start_seconds)}",
                    file=sys.stderr,
                )
                last_heartbeat_seconds = now_seconds

            if processes:
                time.sleep(1.0)

    except KeyboardInterrupt:
        interrupted = True
        print("Interrupted; terminating shard processes. Shard state files remain for resume.", file=sys.stderr)

        for _, process_handle in processes:
            process_handle.terminate()

        deadline = time.monotonic() + 20.0

        for _, process_handle in processes:
            remaining_seconds = max(0.1, deadline - time.monotonic())
            try:
                process_handle.wait(timeout=remaining_seconds)
            except subprocess.TimeoutExpired:
                process_handle.kill()

    if interrupted:
        return 130

    return_codes: list[int] = []
    for shard_index in range(1, shard_count + 1):
        state_path = shard_state_paths[shard_index - 1]
        if not os.path.exists(state_path):
            print(f"Warning: shard {shard_index} state file missing: {state_path}", file=sys.stderr)

    finding_count = merge_findings_files(shard_findings_paths, args.out, args.json)
    failure_count = merge_failure_files(shard_failures_paths, args.failures_out or "")

    elapsed_seconds = time.monotonic() - run_start_seconds
    print(
        f"Shard merge complete: findings={finding_count:,}, failures={failure_count:,}, "
        f"out={args.out}, failures_out={args.failures_out or ''}, elapsed={format_duration(elapsed_seconds)}.",
        file=sys.stderr,
    )

    for _, process_handle in processes:
        return_codes.append(process_handle.returncode or 0)

    return 1 if failure_count else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Pull detailed high-risk Black Duck vulnerability findings for candidate project versions."
    )
    parser.add_argument("--bd-url", default=os.getenv("BLACKDUCK_URL"), required=os.getenv("BLACKDUCK_URL") is None)
    parser.add_argument("--api-token", default=os.getenv("BLACKDUCK_API_TOKEN"), required=os.getenv("BLACKDUCK_API_TOKEN") is None)
    parser.add_argument("--candidates", default="policy_candidate_projects.csv")
    parser.add_argument("--project-name")
    parser.add_argument("--project-name-contains")
    parser.add_argument("--version-name")
    parser.add_argument("--only-candidate-external-id")
    parser.add_argument("--threshold", type=float, default=8.9)
    parser.add_argument("--score-operator", choices=["gt", "gte"], default="gt")
    parser.add_argument("--score-field", default="overallScore")
    parser.set_defaults(require_exploit_available=True)
    parser.add_argument("--require-exploit-available", dest="require_exploit_available", action="store_true")
    parser.add_argument("--no-require-exploit-available", dest="require_exploit_available", action="store_false")
    parser.add_argument("--require-reachable", action="store_true")
    parser.add_argument("--reachability-mode", choices=["none", "field", "ai"], default="none")
    parser.add_argument("--policy-name")
    parser.add_argument("--policy-rule-id")
    parser.add_argument("--group-by", choices=["project", "project-version"], default="project")
    parser.add_argument("--out", default="policy_findings.csv")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--failures-out")
    parser.add_argument("--api-cache", default="policy_vuln_pull_cache.json")
    parser.add_argument("--no-api-cache", action="store_true")
    parser.add_argument("--refresh-api-cache", action="store_true")
    parser.add_argument("--api-cache-max-age-hours", type=float, default=20.0)
    parser.add_argument("--api-cache-max-entries", type=int, default=5000)
    parser.add_argument("--state", help="Resume state path. Default: <out>.state.json.")
    parser.set_defaults(resume=True)
    parser.add_argument("--resume", dest="resume", action="store_true", help="Resume completed candidates from state. Default: enabled.")
    parser.add_argument("--no-resume", dest="resume", action="store_false", help="Ignore resume state and start fresh.")
    parser.add_argument("--limit-candidates", type=int)
    parser.add_argument("--limit-findings", type=int)
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Concurrent candidate detail pulls. Values above 8 are clamped to 8. Default: 4.",
    )
    parser.add_argument(
        "--component-workers",
        type=int,
        default=1,
        help=(
            "Concurrent vulnerable-component/vulnerability-link pulls inside each candidate. "
            "Use 1 for old behavior. Try 2-4 for heavy candidates. Values above 16 are clamped."
        ),
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=10,
        help="Print progress after every N completed candidate pulls. Default: 10.",
    )
    parser.add_argument(
        "--heartbeat-every",
        type=float,
        default=60.0,
        help="Print heartbeat status every N seconds while work is active. Use 0 to disable. Default: 60.",
    )
    parser.add_argument(
        "--cache-save-every",
        type=int,
        default=25,
        help="Save API cache and partial output every N completed candidate pulls. Default: 25.",
    )
    parser.add_argument(
        "--partial-out",
        default=None,
        help="Partial findings output path during long pulls. Default: <out>.partial; disabled when --out is '-'.",
    )
    parser.add_argument(
        "--max-runtime-minutes",
        type=float,
        help="Optional runtime cutoff. Completed work is saved and the run exits after writing output.",
    )
    parser.add_argument(
        "--skip-policy-rules",
        action="store_true",
        help="Do not follow policy-rules links. Cannot be combined with --policy-name or --policy-rule-id.",
    )
    parser.add_argument(
        "--include-policy-rule-details",
        action="store_true",
        help="Follow policy-rules links even when no policy filter is supplied. Slower, but populates policy detail fields.",
    )
    parser.add_argument(
        "--shard-count",
        type=int,
        default=1,
        help=(
            "Split candidates and run this many independent pull subprocesses, then merge outputs. "
            "Use carefully; each shard also uses --workers and --component-workers."
        ),
    )
    parser.add_argument(
        "--shard-dir",
        default=".policy_vuln_pull_shards",
        help="Directory for shard candidate files, outputs, caches, and state. Default: .policy_vuln_pull_shards.",
    )
    parser.add_argument("--shard-worker", action="store_true", help=argparse.SUPPRESS)
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
    if args.api_cache_max_age_hours < -1:
        raise RuntimeError("--api-cache-max-age-hours must be -1 or greater")
    if args.api_cache_max_entries <= 0:
        raise RuntimeError("--api-cache-max-entries must be greater than 0")
    if args.limit_candidates is not None and args.limit_candidates <= 0:
        raise RuntimeError("--limit-candidates must be greater than 0")
    if args.limit_findings is not None and args.limit_findings <= 0:
        raise RuntimeError("--limit-findings must be greater than 0")
    if args.workers <= 0:
        raise RuntimeError("--workers must be greater than 0")
    if args.workers > MAX_WORKERS:
        print(f"Warning: --workers {args.workers} exceeds max {MAX_WORKERS}; clamping to {MAX_WORKERS}.", file=sys.stderr)
        args.workers = MAX_WORKERS
    if args.component_workers <= 0:
        raise RuntimeError("--component-workers must be greater than 0")
    if args.component_workers > MAX_COMPONENT_WORKERS:
        print(
            f"Warning: --component-workers {args.component_workers} exceeds max "
            f"{MAX_COMPONENT_WORKERS}; clamping to {MAX_COMPONENT_WORKERS}.",
            file=sys.stderr,
        )
        args.component_workers = MAX_COMPONENT_WORKERS
    if args.progress_every <= 0:
        raise RuntimeError("--progress-every must be greater than 0")
    if args.heartbeat_every < 0:
        raise RuntimeError("--heartbeat-every must be 0 or greater")
    if args.cache_save_every <= 0:
        raise RuntimeError("--cache-save-every must be greater than 0")
    if args.max_runtime_minutes is not None and args.max_runtime_minutes <= 0:
        raise RuntimeError("--max-runtime-minutes must be greater than 0")
    if (args.policy_name or args.policy_rule_id) and args.skip_policy_rules:
        raise RuntimeError("--skip-policy-rules cannot be used with --policy-name or --policy-rule-id")
    if args.shard_count <= 0:
        raise RuntimeError("--shard-count must be greater than 0")
    if args.shard_count > 32:
        print("Warning: --shard-count above 32 is unsafe; clamping to 32.", file=sys.stderr)
        args.shard_count = 32
    if args.shard_count > 1 and args.out == "-":
        raise RuntimeError("--shard-count cannot be used with --out -")


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
