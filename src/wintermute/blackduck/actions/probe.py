from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from wintermute.blackduck.client import (
    BlackDuckClient,
)
from wintermute.blackduck.collector import (
    component_version_href,
)
from wintermute.blackduck.jobs.cip.config import (
    CipTarget,
    load_cip_configuration,
)
from wintermute.blackduck.resources import (
    canonical_href,
    get_link,
    get_self_href,
)
from wintermute.paths import (
    ensure_parent_dir,
    output_root,
)


_UUID_PATTERN = (
    r"[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}"
)
_UUID_RE = re.compile(
    rf"^{_UUID_PATTERN}$"
)
_UUID_ANY_RE = re.compile(
    _UUID_PATTERN
)
_CVE_RE = re.compile(
    r"\bCVE-[0-9]{4}-[0-9]{4,}\b",
    re.IGNORECASE,
)
_RESOURCE_LABELS = {
    "projects": "project",
    "versions": "version",
    "components": "component",
    "vulnerabilities": "vulnerability",
}


def default_output_path() -> str:
    return str(
        output_root()
        / "blackduck"
        / "actions"
        / "remediation-probe.json"
    )


def redact_href(value: str) -> str:
    parsed = urlsplit(
        str(value or "").strip()
    )
    parts = [
        part
        for part in parsed.path.split("/")
        if part
    ]
    rendered: list[str] = []
    pending_label = ""

    for part in parts:
        if pending_label:
            rendered.append(
                f"{{{pending_label}}}"
            )
            pending_label = ""
            continue

        rendered.append(part)
        pending_label = (
            _RESOURCE_LABELS.get(
                part.casefold(),
                "",
            )
        )

        if (
            not pending_label
            and _UUID_RE.fullmatch(part)
        ):
            rendered[-1] = "{id}"

    path = "/" + "/".join(rendered)

    if parsed.scheme and parsed.netloc:
        return f"<blackduck>{path}"

    return path


def redact_error(
    value: Any,
    base_url: str,
) -> str:
    rendered = str(value).replace(
        base_url.rstrip("/"),
        "<blackduck>",
    )

    return _UUID_ANY_RE.sub(
        "{id}",
        rendered,
    )


def raw_links(
    value: Any,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            meta = item.get("_meta")
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
                ).strip()

                if href:
                    rows.append(
                        {
                            "rel": str(
                                link.get("rel")
                                or ""
                            ),
                            "type": str(
                                link.get("type")
                                or link.get(
                                    "mediaType"
                                )
                                or ""
                            ),
                            "href": href,
                        }
                    )

            for nested in item.values():
                if isinstance(
                    nested,
                    (dict, list),
                ):
                    walk(nested)

        elif isinstance(item, list):
            for nested in item:
                walk(nested)

    walk(value)
    return rows


def link_rows(
    value: Any,
) -> list[dict[str, str]]:
    unique: dict[
        tuple[str, str, str],
        dict[str, str],
    ] = {}

    for row in raw_links(value):
        selected = {
            "rel": row["rel"],
            "type": row["type"],
            "href": redact_href(
                row["href"]
            ),
        }
        key = (
            selected["rel"],
            selected["type"],
            selected["href"],
        )
        unique.setdefault(
            key,
            selected,
        )

    return [
        unique[key]
        for key in sorted(unique)
    ]


def cve_values(value: Any) -> list[str]:
    matches: set[str] = set()

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            for nested in item.values():
                if isinstance(
                    nested,
                    (dict, list),
                ):
                    walk(nested)
                elif isinstance(
                    nested,
                    (str, int),
                ):
                    matches.update(
                        match.upper()
                        for match
                        in _CVE_RE.findall(
                            str(nested)
                        )
                    )

        elif isinstance(item, list):
            for nested in item:
                walk(nested)

    walk(value)
    return sorted(matches)


def project_remediation_href(
    value: Any,
    project_version_href: str,
) -> tuple[str, str]:
    project = urlsplit(
        project_version_href
    )
    expected_prefix = (
        project.path.rstrip("/")
        + "/components/"
    )

    def valid(href: str) -> bool:
        parsed = urlsplit(href)

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

    self_href = get_self_href(value)

    if self_href and valid(self_href):
        return self_href, ""

    links = raw_links(value)

    for row in links:
        if (
            row["rel"].casefold()
            in {
                "remediation",
                "vulnerability-remediation",
                "self",
            }
            and valid(row["href"])
        ):
            return row["href"], row["type"]

    for row in links:
        if (
            "remediation"
            in row["rel"].casefold()
            and valid(row["href"])
        ):
            return row["href"], row["type"]

    return "", ""


def collection_page(
    client: Any,
    url: str,
    *,
    offset: int,
    limit: int,
) -> tuple[
    list[dict[str, Any]],
    int | None,
]:
    try:
        payload = client.get(
            url,
            {
                "offset": offset,
                "limit": limit,
            },
        )
    except RuntimeError as direct_error:
        paged_get = getattr(
            client,
            "paged_get",
            None,
        )

        if not callable(paged_get):
            raise

        try:
            values = paged_get(url)
        except Exception:
            raise direct_error

        rows = [
            dict(value)
            for value in values
            if isinstance(value, dict)
        ]

        return (
            rows[offset:offset + limit],
            len(rows),
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


def remediation_shape(
    payload: dict[str, Any],
) -> dict[str, Any]:
    status = ""

    for key in (
        "remediationStatus",
        "remediation_status",
        "status",
    ):
        value = payload.get(key)

        if value not in (None, ""):
            status = str(value)
            break

    comment = ""

    for key in (
        "comment",
        "remediationComment",
        "remediation_comment",
    ):
        value = payload.get(key)

        if isinstance(value, str):
            comment = value
            break

    meta = payload.get("_meta")

    return {
        "keys": sorted(
            str(key)
            for key in payload
        ),
        "status": status,
        "comment_present": bool(comment),
        "comment_length": len(comment),
        "href": redact_href(
            str(
                meta.get("href") or ""
            )
            if isinstance(meta, dict)
            else ""
        ),
        "links": link_rows(payload),
    }


def inspect_fallback_vulnerabilities(
    client: Any,
    component: dict[str, Any],
    project_version_href: str,
    *,
    max_vulnerabilities: int,
    max_remediations: int,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    items: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    vulnerabilities_url = get_link(
        component,
        (
            "vulnerabilities",
            "vulnerability",
        ),
    )

    if not vulnerabilities_url:
        return items, failures

    try:
        vulnerabilities, _ = (
            collection_page(
                client,
                vulnerabilities_url,
                offset=0,
                limit=max_vulnerabilities,
            )
        )
    except Exception as error:
        return (
            items,
            [
                {
                    "stage": (
                        "load-vulnerabilities"
                    ),
                    "error": redact_error(
                        error,
                        client.base_url,
                    ),
                }
            ],
        )

    remediation_reads = 0

    for vulnerability in vulnerabilities:
        href, media_type = (
            project_remediation_href(
                vulnerability,
                project_version_href,
            )
        )
        item = {
            "source": (
                "vulnerability-resource"
            ),
            "cves": cve_values(
                vulnerability
            ),
            "href": redact_href(
                get_self_href(vulnerability)
            ),
            "links": link_rows(
                vulnerability
            ),
            "remediation_href": (
                redact_href(href)
            ),
            "remediation_media_type": (
                media_type
            ),
            "remediation": None,
        }

        if (
            href
            and remediation_reads
            < max_remediations
        ):
            remediation_reads += 1

            try:
                item["remediation"] = (
                    remediation_shape(
                        client.get(href)
                    )
                )
            except Exception as error:
                failures.append(
                    {
                        "stage": (
                            "load-remediation"
                        ),
                        "cves": item["cves"],
                        "error": redact_error(
                            error,
                            client.base_url,
                        ),
                    }
                )

        items.append(item)

        if item["remediation"] is not None:
            break

    return items, failures


def inspect_target(
    client: Any,
    target: CipTarget,
    *,
    component_page_size: int = 100,
    max_component_pages: int = 50,
    max_vulnerabilities: int = 20,
    max_remediations: int = 1,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "project_version_href": redact_href(
            target.project_version_href
        ),
        "component_version_href": redact_href(
            target.component_version_href
        ),
        "cip_tag": target.cip_tag,
        "status": "failed",
        "matching_occurrence_rows": 0,
        "component_search": {},
        "occurrences": [],
        "failures": [],
    }

    try:
        project_version = client.get(
            target.project_version_href
        )
    except Exception as error:
        result["failures"].append(
            {
                "stage": (
                    "load-project-version"
                ),
                "error": redact_error(
                    error,
                    client.base_url,
                ),
            }
        )
        return result

    collection_url = (
        vulnerable_components_url(
            project_version,
            target.project_version_href,
        )
    )
    wanted_component = canonical_href(
        target.component_version_href
    )
    offset = 0
    pages_read = 0
    rows_read = 0
    total_count: int | None = None
    remediation_reads = 0
    remediation_found = False

    for page_number in range(
        1,
        max_component_pages + 1,
    ):
        try:
            rows, total_count = (
                collection_page(
                    client,
                    collection_url,
                    offset=offset,
                    limit=(
                        component_page_size
                    ),
                )
            )
        except Exception as error:
            result["failures"].append(
                {
                    "stage": (
                        "load-vulnerable-components"
                    ),
                    "error": redact_error(
                        error,
                        client.base_url,
                    ),
                }
            )
            break

        pages_read += 1
        rows_read += len(rows)

        for component in rows:
            if canonical_href(
                component_version_href(
                    component
                )
            ) != wanted_component:
                continue

            result[
                "matching_occurrence_rows"
            ] += 1
            href, media_type = (
                project_remediation_href(
                    component,
                    target.project_version_href,
                )
            )
            occurrence: dict[str, Any] = {
                "source": (
                    "vulnerable-bom-component"
                ),
                "cves": cve_values(component),
                "keys": sorted(
                    str(key)
                    for key in component
                ),
                "href": redact_href(
                    get_self_href(component)
                ),
                "links": link_rows(component),
                "remediation_href": (
                    redact_href(href)
                ),
                "remediation_media_type": (
                    media_type
                ),
                "remediation": None,
            }

            if (
                href
                and remediation_reads
                < max_remediations
            ):
                remediation_reads += 1

                try:
                    occurrence[
                        "remediation"
                    ] = remediation_shape(
                        client.get(href)
                    )
                    remediation_found = True
                except Exception as error:
                    result["failures"].append(
                        {
                            "stage": (
                                "load-remediation"
                            ),
                            "cves": (
                                occurrence["cves"]
                            ),
                            "error": redact_error(
                                error,
                                client.base_url,
                            ),
                        }
                    )

            result["occurrences"].append(
                occurrence
            )

            if remediation_found:
                break

            if (
                not href
                and len(result["occurrences"])
                == 1
            ):
                fallback, failures = (
                    inspect_fallback_vulnerabilities(
                        client,
                        component,
                        target.project_version_href,
                        max_vulnerabilities=(
                            max_vulnerabilities
                        ),
                        max_remediations=(
                            max_remediations
                            - remediation_reads
                        ),
                    )
                )
                result["occurrences"].extend(
                    fallback
                )
                result["failures"].extend(
                    failures
                )

                if any(
                    item.get("remediation")
                    is not None
                    for item in fallback
                ):
                    remediation_found = True
                    remediation_reads += 1
                    break

        if remediation_found:
            break

        if not rows:
            break

        offset += len(rows)

        if (
            total_count is not None
            and offset >= total_count
        ):
            break

        if len(rows) < component_page_size:
            break

        if (
            remediation_reads
            >= max_remediations
        ):
            break

        if page_number == max_component_pages:
            result["failures"].append(
                {
                    "stage": (
                        "component-search-limit"
                    ),
                    "error": (
                        "Maximum component pages "
                        "were reached"
                    ),
                }
            )

    result["component_search"] = {
        "collection": redact_href(
            collection_url
        ),
        "pages_read": pages_read,
        "rows_read": rows_read,
        "total_count": total_count,
    }
    result["remediation_reads"] = (
        remediation_reads
    )

    if not remediation_found:
        result["failures"].append(
            {
                "stage": (
                    "find-remediation-resource"
                ),
                "error": (
                    "No readable project-scoped "
                    "remediation resource was found"
                ),
            }
        )

    result["status"] = (
        "partial"
        if result["failures"]
        else "succeeded"
    )

    return result


def atomic_write_json(
    path: str,
    payload: dict[str, Any],
) -> None:
    ensure_parent_dir(path)
    destination = Path(path)
    temporary = destination.with_name(
        f"{destination.name}."
        f"{uuid.uuid4().hex}.tmp"
    )

    try:
        temporary.write_text(
            json.dumps(
                payload,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        os.replace(
            temporary,
            destination,
        )
    finally:
        temporary.unlink(missing_ok=True)


def validate_args(
    args: argparse.Namespace,
) -> None:
    for name in (
        "component_page_size",
        "max_component_pages",
        "max_vulnerabilities",
        "max_remediations",
        "timeout",
        "page_limit",
    ):
        if int(getattr(args, name)) < 1:
            raise RuntimeError(
                f"--{name.replace('_', '-')} "
                "must be greater than zero"
            )

    if args.component_page_size > 500:
        raise RuntimeError(
            "--component-page-size cannot "
            "exceed 500"
        )

    if args.max_vulnerabilities > 500:
        raise RuntimeError(
            "--max-vulnerabilities cannot "
            "exceed 500"
        )

    if args.retries < 0:
        raise RuntimeError(
            "--retries cannot be negative"
        )

    if args.retry_delay < 0:
        raise RuntimeError(
            "--retry-delay cannot be negative"
        )


def run(args: argparse.Namespace) -> int:
    validate_args(args)
    configuration = load_cip_configuration(
        args.config
    )
    client = BlackDuckClient(
        base_url=(
            configuration.blackduck_base_url
        ),
        api_token=args.api_token,
        insecure=args.insecure,
        ca_bundle=args.ca_bundle,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        page_limit=args.page_limit,
        debug=args.debug,
        api_cache=None,
        request_interval_seconds=(
            args.request_interval_seconds
        ),
    )
    client.cache_raw_gets = False
    client.cache_paged_results = False
    client.authenticate()
    targets: list[dict[str, Any]] = []

    for index, target in enumerate(
        configuration.targets,
        start=1,
    ):
        print(
            f"Inspecting CIP target "
            f"{index}/{len(configuration.targets)}",
            file=sys.stderr,
        )
        targets.append(
            inspect_target(
                client,
                target,
                component_page_size=(
                    args.component_page_size
                ),
                max_component_pages=(
                    args.max_component_pages
                ),
                max_vulnerabilities=(
                    args.max_vulnerabilities
                ),
                max_remediations=(
                    args.max_remediations
                ),
            )
        )

    failure_count = sum(
        len(target["failures"])
        for target in targets
    )
    payload = {
        "schema_version": 1,
        "blackduck_base_url": (
            "<blackduck>"
        ),
        "target_count": len(targets),
        "failure_count": failure_count,
        "targets": targets,
    }
    atomic_write_json(
        args.output,
        payload,
    )
    print(
        json.dumps(
            {
                "output": args.output,
                "target_count": len(targets),
                "failure_count": failure_count,
            },
            indent=2,
            sort_keys=True,
        )
    )

    return 1 if failure_count else 0


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect a project-scoped Black Duck "
            "remediation resource."
        )
    )
    parser.add_argument(
        "--config",
        default=os.getenv(
            "CIP_REMEDIATION_CONFIG"
        ),
    )
    parser.add_argument(
        "--output",
        default=default_output_path(),
    )
    parser.add_argument(
        "--component-page-size",
        type=int,
        default=100,
    )
    parser.add_argument(
        "--max-component-pages",
        type=int,
        default=50,
    )
    parser.add_argument(
        "--max-vulnerabilities",
        type=int,
        default=20,
    )
    parser.add_argument(
        "--max-remediations",
        type=int,
        default=1,
    )
    parser.add_argument(
        "--api-token",
        default=os.getenv(
            "BLACKDUCK_API_TOKEN"
        ),
        required=(
            os.getenv(
                "BLACKDUCK_API_TOKEN"
            )
            is None
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=1,
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=2,
    )
    parser.add_argument(
        "--page-limit",
        type=int,
        default=500,
    )
    parser.add_argument(
        "--request-interval-seconds",
        type=float,
        default=0.5,
    )
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument(
        "--insecure",
        action="store_true",
    )
    tls.add_argument("--ca-bundle")
    parser.add_argument(
        "--debug",
        action="store_true",
    )

    return parser.parse_args(argv)


def main() -> int:
    try:
        return run(parse_args())
    except KeyboardInterrupt:
        return 130
    except (
        OSError,
        RuntimeError,
        ValueError,
    ) as error:
        print(
            f"ERROR: {error}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
