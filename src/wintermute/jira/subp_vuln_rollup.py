#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shlex
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from wintermute.blackduck.client import BlackDuckClient as SharedBlackDuckClient
from wintermute.blackduck.request_control import (
    BlackDuckCircuitOpenError,
)
from wintermute.blackduck.criteria import (
    jira_parent_rollup_criteria,
)
from wintermute.jira.collection import (
    collect_parent_rollup,
)
from wintermute.blackduck.cache import ApiResponseCache as SharedApiResponseCache
from wintermute.blackduck.resources import (
    canonical_href as shared_canonical_href,
    first_value_by_key as shared_first_value_by_key,
    get_link as shared_get_link,
    get_self_href as shared_get_self_href,
    iter_hrefs as shared_iter_hrefs,
    looks_like_resource_url as shared_looks_like_resource_url,
)
from wintermute.blackduck.vulnerabilities import (
    extract_vulnerability_candidates as shared_extract_vulnerability_candidates,
    looks_like_vulnerability as shared_looks_like_vulnerability,
    vulnerability_identifier as shared_vulnerability_identifier,
    vulnerability_severity as shared_vulnerability_severity,
)
from wintermute.concurrency import (
    DEFAULT_IO_WORKERS,
    MAX_IO_WORKERS,
    bounded_worker_count,
    ordered_parallel_map,
)
from wintermute.paths import ensure_parent_dir, jira_output_path


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




class ApiResponseCache(SharedApiResponseCache):
    pass


class BlackDuckClient(SharedBlackDuckClient):
    pass


def canonical_href(href: str) -> str:
    return shared_canonical_href(href)


def get_self_href(resource: dict[str, Any]) -> str | None:
    return shared_get_self_href(resource) or None


def get_link(
        resource: dict[str, Any],
        rel_names: tuple[str, ...],
) -> str | None:
    return shared_get_link(resource, rel_names) or None


def iter_hrefs(value: Any) -> list[str]:
    return shared_iter_hrefs(value)


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
            except BlackDuckCircuitOpenError:
                raise
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
            except BlackDuckCircuitOpenError:
                raise
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




def first_value_by_key(
        value: Any,
        keys: list[str],
) -> Any:
    return shared_first_value_by_key(value, keys)


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
    except BlackDuckCircuitOpenError:
        raise
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
        except BlackDuckCircuitOpenError:
            raise
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



def looks_like_vulnerability(
        value: dict[str, Any],
        score_field: str,
) -> bool:
    return shared_looks_like_vulnerability(
        value,
        score_fields=(score_field,),
        id_fields=(
            "vulnerabilityName",
            "vulnerabilityId",
            "vulnerabilityExternalId",
            "externalId",
            "cveId",
            "cve",
            "bdsaId",
        ),
    )


def extract_vulnerability_candidates(
        value: Any,
        score_field: str,
) -> list[dict[str, Any]]:
    return shared_extract_vulnerability_candidates(
        value,
        score_fields=(score_field,),
        id_fields=(
            "vulnerabilityName",
            "vulnerabilityId",
            "vulnerabilityExternalId",
            "externalId",
            "cveId",
            "cve",
            "bdsaId",
        ),
        dedupe_score_fields=(score_field,),
        dedupe_payload_limit=500,
    )


def vulnerability_identifier(
        vulnerability: dict[str, Any],
) -> str:
    return shared_vulnerability_identifier(vulnerability)


def vulnerability_severity(
        vulnerability: dict[str, Any],
) -> str:
    return shared_vulnerability_severity(
        vulnerability,
        uppercase=False,
    )



def looks_like_resource_url(value: Any) -> bool:
    return shared_looks_like_resource_url(value)






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
        workers: int = 1,
        excluded_parent_projects: set[str] | None = None,
        excluded_child_projects: set[str] | None = None,
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

    excluded_parent_projects = {
        str(value).strip()
        for value in (excluded_parent_projects or set())
        if str(value).strip()
    }
    excluded_child_projects = {
        str(value).strip()
        for value in (excluded_child_projects or set())
        if str(value).strip()
    }
    rows = [
        row
        for row in rows
        if str(row.get("parent_project") or "")
        not in excluded_parent_projects
        and str(row.get("child_project") or "")
        not in excluded_child_projects
    ]

    stubs: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for row in rows:
        parent_project = str(row.get("parent_project") or "")
        parent_version = str(row.get("parent_version") or "")

        if (
            parent_project_filter
            and parent_project != parent_project_filter
        ):
            continue

        if (
            parent_version_filter
            and parent_version != parent_version_filter
        ):
            continue

        child_version_href = canonical_href(
            str(row.get("child_version_href") or "")
        )

        if not child_version_href:
            continue

        key = relationship_key(row)

        if key in seen:
            continue

        seen.add(key)
        child_project = str(row.get("child_project") or "")
        child_version_name = str(row.get("child_version") or "")

        stubs.append(
            {
                "parent_project": parent_project,
                "parent_version": parent_version,
                "parent_version_href": canonical_href(
                    str(row.get("parent_version_href") or "")
                ),
                "project_name": child_project,
                "version_name": child_version_name,
                "version_href": child_version_href,
                "source": str(
                    row.get("detection_method") or "parent-csv"
                ),
                "path": f"{child_project}/{child_version_name}",
            }
        )

    unique_hrefs = list(
        dict.fromkeys(
            str(stub["version_href"])
            for stub in stubs
        )
    )

    if not unique_hrefs:
        return []

    worker_count = min(
        bounded_worker_count(
            workers,
            maximum=MAX_IO_WORKERS,
        ),
        len(unique_hrefs),
    )
    worker_local = threading.local()

    def worker_client() -> BlackDuckClient:
        if worker_count == 1:
            return client

        local_client = getattr(
            worker_local,
            "blackduck_client",
            None,
        )

        if local_client is None:
            local_client = client.clone_for_worker()
            worker_local.blackduck_client = local_client

        return local_client

    def load_version(
            href: str,
    ) -> tuple[str, dict[str, Any] | None, str, float]:
        started = time.monotonic()

        try:
            return (
                href,
                worker_client().get(href),
                "",
                time.monotonic() - started,
            )
        except BlackDuckCircuitOpenError:
            raise
        except RuntimeError as error:
            return (
                href,
                None,
                str(error),
                time.monotonic() - started,
            )

    loaded = ordered_parallel_map(
        unique_hrefs,
        load_version,
        workers=worker_count,
        maximum=MAX_IO_WORKERS,
    )
    versions_by_href = {
        href: version
        for href, version, error, _ in loaded
        if version is not None and not error
    }
    errors_by_href = {
        href: (error, elapsed)
        for href, _, error, elapsed in loaded
        if error
    }

    subproject_refs: list[dict[str, Any]] = []

    for stub in stubs:
        href = str(stub["version_href"])
        child_version = versions_by_href.get(href)

        if child_version is None:
            error, elapsed = errors_by_href.get(
                href,
                ("Child version was not loaded", 0.0),
            )
            print(
                f"Warning: failed to read child version {href} "
                f"for {stub['parent_project']} / "
                f"{stub['parent_version']} after "
                f"{format_duration(elapsed)}: {error}",
                file=sys.stderr,
            )

            if failures is not None:
                failures.append(
                    failed_relationship_from_subproject(
                        stub,
                        stage="load-child-version",
                        elapsed_seconds=elapsed,
                        client=client,
                        error=error,
                    )
                )

            continue

        if debug:
            print(
                f"Loaded relationship from CSV: "
                f"{stub['parent_project']} / "
                f"{stub['parent_version']} -> "
                f"{stub['project_name']} / "
                f"{stub['version_name']}",
                file=sys.stderr,
            )

        ref = dict(stub)
        ref["version"] = child_version
        subproject_refs.append(ref)

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




def collect_parent_rollup_findings(
        client: BlackDuckClient,
        subprojects: list[dict[str, Any]],
        args: argparse.Namespace,
        default_parent_project: str = "",
        default_parent_version: str = "",
) -> tuple[
    list[dict[str, Any]],
    list[FailedRelationship],
]:
    relationship_rows: list[
        dict[str, Any]
    ] = []
    version_resources: dict[
        str,
        dict[str, Any],
    ] = {}

    for subproject in subprojects:
        parent_project = str(
            subproject.get("parent_project")
            or default_parent_project
        )
        parent_version = str(
            subproject.get("parent_version")
            or default_parent_version
        )
        child_href = canonical_href(
            str(
                subproject.get("version_href")
                or ""
            )
        )

        relationship_rows.append(
            {
                "parent_project": (
                    parent_project
                ),
                "parent_version": (
                    parent_version
                ),
                "parent_version_href": (
                    subproject.get(
                        "parent_version_href",
                        "",
                    )
                ),
                "child_project": (
                    subproject.get(
                        "project_name",
                        "",
                    )
                ),
                "child_version": (
                    subproject.get(
                        "version_name",
                        "",
                    )
                ),
                "child_version_href": (
                    child_href
                ),
                "detection_method": (
                    subproject.get(
                        "source",
                        "",
                    )
                ),
                "subproject_path": (
                    subproject.get(
                        "path",
                        "",
                    )
                ),
            }
        )

        version_resource = subproject.get(
            "version"
        )

        if (
            child_href
            and isinstance(
                version_resource,
                dict,
            )
        ):
            version_resources[
                child_href
            ] = version_resource

    criteria = jira_parent_rollup_criteria(
        threshold=args.threshold,
        score_field=args.score_field,
        entity_custom_field=(
            args.entity_custom_field
        ),
        require_entity=args.require_entity,
    )

    entity_resolver = None

    if args.entity_custom_field:
        def resolve_entity(
            current_client: BlackDuckClient,
            target: Any,
        ) -> str:
            version_href = canonical_href(
                target.project_version.version_href
            )
            version_resource = (
                version_resources.get(
                    version_href,
                    {},
                )
            )

            return read_project_custom_field(
                client=current_client,
                version_href=version_href,
                version=version_resource,
                field_name=(
                    args.entity_custom_field
                ),
            )

        entity_resolver = resolve_entity

    result = collect_parent_rollup(
        client,
        relationship_rows,
        criteria,
        workers=args.workers,
        component_workers=1,
        entity_resolver=entity_resolver,
    )
    failures = [
        FailedRelationship(
            parent_project=(
                failure.parent_project
            ),
            parent_version=(
                failure.parent_version
            ),
            child_project=(
                failure.child_project
            ),
            child_version=(
                failure.child_version
            ),
            child_version_href=(
                failure.child_version_href
            ),
            source=failure.source,
            stage=failure.stage,
            elapsed_seconds=(
                failure.elapsed_seconds
            ),
            timeout_seconds=client.timeout,
            retries=client.retries,
            attempts_per_request=(
                client.retries + 1
            ),
            error=failure.error,
        )
        for failure in result.failures
    ]

    print(
        f"Collected {result.finding_count} direct finding(s) "
        f"from {result.target_count} unique child "
        f"project version(s), expanded across "
        f"{len(relationship_rows)} relationship(s).",
        file=sys.stderr,
    )

    return list(result.rows), failures



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
        "wintermute.jira.subp_vuln_rollup",
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
            "--workers",
            str(getattr(args, "workers", DEFAULT_IO_WORKERS)),
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
        "--exclude-parent-project",
        action="append",
        default=[],
        help=(
            "Exclude an exact parent project name. "
            "Repeat for multiple projects."
        ),
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
        default="",
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
        "--exclude-child-project",
        action="append",
        default=[],
        help=(
            "Exclude an exact child project name. "
            "Repeat for multiple projects."
        ),
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
        "--workers",
        type=int,
        default=DEFAULT_IO_WORKERS,
        help=(
            "Concurrent child project-version vulnerability pulls. "
            f"Values above {MAX_IO_WORKERS} are clamped."
        ),
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
    args.exclude_parent_project = {
        str(value).strip()
        for value in getattr(
            args,
            "exclude_parent_project",
            [],
        )
        if str(value).strip()
    }
    args.exclude_child_project = {
        str(value).strip()
        for value in getattr(
            args,
            "exclude_child_project",
            [],
        )
        if str(value).strip()
    }

    if args.timeout <= 0:
        raise RuntimeError("--timeout must be greater than 0")

    if args.retries < 0:
        raise RuntimeError("--retries must be 0 or greater")

    if args.retry_delay < 0:
        raise RuntimeError("--retry-delay must be 0 or greater")

    if args.page_limit <= 0:
        raise RuntimeError("--page-limit must be greater than 0")

    requested_workers = int(
        getattr(args, "workers", DEFAULT_IO_WORKERS)
    )

    if requested_workers <= 0:
        raise RuntimeError("--workers must be greater than 0")

    if requested_workers > MAX_IO_WORKERS:
        print(
            f"Warning: --workers {requested_workers} exceeds "
            f"maximum {MAX_IO_WORKERS}; clamping.",
            file=sys.stderr,
        )

    args.workers = bounded_worker_count(
        requested_workers,
        maximum=MAX_IO_WORKERS,
    )

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
                workers=args.workers,
                excluded_parent_projects=args.exclude_parent_project,
                excluded_child_projects=args.exclude_child_project,
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

            child_findings, child_failures = collect_parent_rollup_findings(
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

            child_findings, child_failures = collect_parent_rollup_findings(
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
