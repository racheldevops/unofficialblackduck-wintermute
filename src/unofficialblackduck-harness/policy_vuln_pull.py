#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import os
import ssl
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
MAX_WORKERS = 8


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


@dataclass(frozen=True)
class PullTarget:
    index: int
    candidate: dict[str, str]


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


def collect_for_candidate(
    client: BlackDuckClient,
    candidate: dict[str, str],
    settings: PullSettings,
) -> list[dict[str, str]]:
    project = candidate.get("project", "")
    project_version = candidate.get("project_version", "")
    project_href = candidate.get("project_href", "")
    project_version_href = canonical_href(candidate.get("project_version_href", ""))

    if not project_version_href:
        raise RuntimeError("candidate row has no project_version_href")

    components = get_vulnerable_components(client, project_version_href)
    findings: list[dict[str, str]] = []

    fetch_policy_rules = should_fetch_policy_rules(settings)

    for component in components:
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
            continue

        vulnerabilities_url = get_link(component, ("vulnerabilities", "vulnerability"))
        vulnerability_items: list[dict[str, Any]] = []

        if vulnerabilities_url:
            for item in client.paged_get(vulnerabilities_url):
                extracted = extract_vulnerability_candidates(item, settings.score_field)
                vulnerability_items.extend(extracted or [item])
        else:
            vulnerability_items.extend(extract_vulnerability_candidates(component, settings.score_field))

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
                    "candidate_external_id": candidate.get("candidate_external_id", ""),
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

    return findings


def failure_for_candidate(
    candidate: dict[str, str],
    stage: str,
    error: Exception | str,
) -> dict[str, str]:
    return {
        "project": candidate.get("project", ""),
        "project_version": candidate.get("project_version", ""),
        "project_version_href": candidate.get("project_version_href", ""),
        "candidate_external_id": candidate.get("candidate_external_id", ""),
        "stage": stage,
        "error": str(error),
    }


def pull_one_candidate(
    settings: PullSettings,
    api_cache: ApiResponseCache | None,
    target: PullTarget,
) -> CandidatePullResult:
    start_seconds = time.monotonic()

    client = BlackDuckClient(
        base_url=settings.base_url,
        api_token=settings.api_token,
        insecure=settings.insecure,
        timeout=settings.timeout,
        retries=settings.retries,
        retry_delay=settings.retry_delay,
        page_limit=settings.page_limit,
        debug=settings.debug,
        api_cache=api_cache,
        bearer_token=settings.bearer_token,
    )

    try:
        findings = collect_for_candidate(client, target.candidate, settings)
        return CandidatePullResult(
            index=target.index,
            candidate=target.candidate,
            findings=findings,
            failures=[],
            elapsed_seconds=time.monotonic() - start_seconds,
            status="ok",
        )
    except Exception as error:
        return CandidatePullResult(
            index=target.index,
            candidate=target.candidate,
            findings=[],
            failures=[failure_for_candidate(target.candidate, "collect-details", error)],
            elapsed_seconds=time.monotonic() - start_seconds,
            status="failed",
            error=str(error),
        )


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


def persist_checkpoint(
    api_cache: ApiResponseCache | None,
    findings: list[dict[str, str]],
    failures: list[dict[str, str]],
    args: argparse.Namespace,
    partial_out: str,
) -> None:
    if api_cache is not None:
        api_cache.save()

    if partial_out:
        write_findings(partial_out, sort_findings(findings), args.json)
        print(f"Wrote partial findings: {partial_out}", file=sys.stderr)

    if args.failures_out:
        partial_failures = f"{args.failures_out}.partial"
        write_failures(partial_failures, failures)
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
    )


def process(args: argparse.Namespace) -> int:
    run_start_seconds = time.monotonic()

    partial_out = args.partial_out
    if partial_out is None:
        partial_out = "" if args.out == "-" else f"{args.out}.partial"

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

        targets = [
            PullTarget(index=index, candidate=candidate)
            for index, candidate in enumerate(candidates, start=1)
        ]

        print(
            f"Loaded {len(candidates):,} candidate(s) from {args.candidates}.",
            file=sys.stderr,
        )
        print(
            f"Pulling with workers={args.workers}, threshold={args.score_operator} {args.threshold}, "
            f"score_field={args.score_field}, require_exploit_available={args.require_exploit_available}.",
            file=sys.stderr,
        )

        if args.policy_name or args.policy_rule_id:
            print("Policy filter enabled; policy-rule links will be followed as needed.", file=sys.stderr)
        elif args.include_policy_rule_details:
            print("Policy rule detail collection enabled; this can be slower.", file=sys.stderr)
        else:
            print("Policy rule detail traversal disabled unless policy filters are supplied.", file=sys.stderr)

        findings: list[dict[str, str]] = []
        failures: list[dict[str, str]] = []
        seen_finding_ids: set[str] = set()
        completed_count = 0
        runtime_limited = False
        finding_limit_reached = False
        interrupted = False

        def apply_result(result: CandidatePullResult) -> None:
            nonlocal finding_limit_reached

            failures.extend(result.failures)

            if result.status == "failed":
                print(
                    f"Warning: failed pulling {result.candidate.get('project', '')} / "
                    f"{result.candidate.get('project_version', '')}: {result.error}",
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
                            f"[{target.index}/{len(targets)}] Pulling "
                            f"{target.candidate.get('project')} / {target.candidate.get('project_version')}",
                            file=sys.stderr,
                        )

                    result = pull_one_candidate(settings, api_cache, target)
                    apply_result(result)
                    completed_count += 1

                    print_progress(
                        completed=completed_count,
                        total=len(targets),
                        finding_count=len(findings),
                        failure_count=len(failures),
                        start_seconds=run_start_seconds,
                        progress_every=args.progress_every,
                    )

                    if completed_count % args.cache_save_every == 0:
                        persist_checkpoint(api_cache, findings, failures, args, partial_out)

            elif targets:
                executor: ThreadPoolExecutor | None = ThreadPoolExecutor(max_workers=args.workers)
                pending: dict[Future[CandidatePullResult], PullTarget] = {}
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
                                f"[schedule {next_index}/{len(targets)}] Pulling "
                                f"{target.candidate.get('project')} / {target.candidate.get('project_version')}",
                                file=sys.stderr,
                            )

                        future = executor.submit(pull_one_candidate, settings, api_cache, target)
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
                                total=len(targets),
                                finding_count=len(findings),
                                failure_count=len(failures),
                                start_seconds=run_start_seconds,
                                progress_every=args.progress_every,
                            )

                            if completed_count % args.cache_save_every == 0:
                                persist_checkpoint(api_cache, findings, failures, args, partial_out)

                        if runtime_limit_reached(args, run_start_seconds):
                            runtime_limited = True

                        if not runtime_limited and not finding_limit_reached:
                            submit_more()

                finally:
                    if executor is not None:
                        executor.shutdown(wait=True, cancel_futures=False)

        except KeyboardInterrupt:
            interrupted = True
            print("Interrupted; saving API cache and partial output...", file=sys.stderr)

        if interrupted:
            persist_checkpoint(api_cache, findings, failures, args, partial_out)
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
            total=len(targets),
            finding_count=len(findings),
            failure_count=len(failures),
            start_seconds=run_start_seconds,
            progress_every=args.progress_every,
            force=True,
        )

        findings = sort_findings(findings)

        write_findings(args.out, findings, args.json)
        write_failures(args.failures_out or "", failures)

        remove_partial_output(partial_out)

        if args.failures_out:
            remove_partial_output(f"{args.failures_out}.partial")

        elapsed_seconds = time.monotonic() - run_start_seconds
        remaining_count = max(0, len(targets) - completed_count)

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
    parser.add_argument("--limit-candidates", type=int)
    parser.add_argument("--limit-findings", type=int)
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Concurrent candidate detail pulls. Values above 8 are clamped to 8. Default: 4.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=10,
        help="Print progress after every N completed candidate pulls. Default: 10.",
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
