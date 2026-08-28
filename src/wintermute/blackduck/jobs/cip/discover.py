from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wintermute.blackduck.actions.lock import (
    FileLock,
    LockUnavailableError,
)
from wintermute.blackduck.client import (
    BlackDuckClient,
)
from wintermute.blackduck.collector import (
    component_version_href,
    get_vulnerable_components,
)
from wintermute.blackduck.inventory import (
    version_name,
)
from wintermute.blackduck.request_control import (
    blackduck_request_context,
)
from wintermute.blackduck.resources import (
    canonical_href,
    first_value_by_key,
    get_link,
    get_self_href,
    looks_like_resource_url,
)
from wintermute.concurrency import (
    bounded_worker_count,
    ordered_parallel_map,
)
from wintermute.paths import (
    ensure_parent_dir,
    output_root,
)


_CIP_TAG_RE = re.compile(
    r"^v?(?P<base>[0-9]+\.[0-9]+\.[0-9]+)"
    r"(?:[-+]cip(?P<cip>[0-9]+))?$",
    re.IGNORECASE,
)
_SERIES_RE = re.compile(
    r"(?<![0-9])(?P<series>[0-9]+\.[0-9]+)"
    r"(?![0-9])"
)


@dataclass(frozen=True)
class ProjectVersion:
    project: str
    project_version: str
    project_version_href: str
    project_href: str

    def as_dict(self) -> dict[str, str]:
        return {
            "project": self.project,
            "project_version": (
                self.project_version
            ),
            "project_version_href": (
                self.project_version_href
            ),
            "project_href": self.project_href,
        }


@dataclass(frozen=True)
class DiscoveryCandidate:
    project: str
    project_version: str
    project_version_href: str
    component: str
    component_version: str
    component_version_href: str
    bom_component_href: str
    cip_tag: str
    cip_branch: str
    score: int

    @property
    def complete(self) -> bool:
        return bool(
            self.project_version_href
            and self.component_version_href
            and self.cip_tag
            and self.cip_branch
        )

    @property
    def environment(self) -> dict[str, str]:
        return {
            "WINTERMUTE_CIP_PROJECT_VERSION_HREF": (
                self.project_version_href
            ),
            "WINTERMUTE_CIP_COMPONENT_VERSION_HREF": (
                self.component_version_href
            ),
            "WINTERMUTE_CIP_TAG": self.cip_tag,
            "WINTERMUTE_CIP_BRANCH": (
                self.cip_branch
            ),
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "project_version": (
                self.project_version
            ),
            "project_version_href": (
                self.project_version_href
            ),
            "component": self.component,
            "component_version": (
                self.component_version
            ),
            "component_version_href": (
                self.component_version_href
            ),
            "bom_component_href": (
                self.bom_component_href
            ),
            "cip_tag": self.cip_tag,
            "cip_branch": self.cip_branch,
            "score": self.score,
            "complete": self.complete,
            "environment": self.environment,
        }


@dataclass(frozen=True)
class DiscoveryFailure:
    project: str
    project_version: str
    project_version_href: str
    stage: str
    error: str

    def as_dict(self) -> dict[str, str]:
        return {
            "project": self.project,
            "project_version": (
                self.project_version
            ),
            "project_version_href": (
                self.project_version_href
            ),
            "stage": self.stage,
            "error": self.error,
        }


@dataclass(frozen=True)
class VersionDiscoveryResult:
    candidates: tuple[
        DiscoveryCandidate,
        ...
    ]
    failures: tuple[
        DiscoveryFailure,
        ...
    ]


def default_output_path() -> str:
    return str(
        output_root()
        / "blackduck"
        / "jobs"
        / "cip"
        / "discovery.json"
    )


def default_environment_path() -> str:
    return str(
        output_root()
        / "blackduck"
        / "jobs"
        / "cip"
        / "selected-target.env"
    )


def default_lock_path() -> str:
    return str(
        output_root()
        / "blackduck"
        / "jobs"
        / "cip"
        / "discovery.lock"
    )


def normalized_version(
    value: str,
) -> str:
    return (
        str(value or "")
        .strip()
        .casefold()
        .removeprefix("v")
        .replace("+cip", "-cip")
    )


def tag_parts(
    value: str,
) -> tuple[str, str, str]:
    selected = str(value or "").strip()
    match = _CIP_TAG_RE.fullmatch(selected)

    if match is None:
        return "", "", ""

    base = match.group("base")
    series_match = _SERIES_RE.search(base)
    series = (
        series_match.group("series")
        if series_match is not None
        else ""
    )

    if match.group("cip"):
        tag = (
            f"v{base}-cip"
            f"{match.group('cip')}"
        )
    else:
        tag = ""

    return tag, base, series


def branch_from_value(
    value: str,
) -> str:
    match = _SERIES_RE.search(
        str(value or "")
    )

    if match is None:
        return ""

    return (
        f"linux-{match.group('series')}"
        ".y-cip"
    )


def suggested_tag(
    *values: str,
) -> str:
    for value in values:
        tag, _, _ = tag_parts(value)

        if tag:
            return tag

    return ""


def component_name(
    component: dict[str, Any],
) -> str:
    return str(
        first_value_by_key(
            component,
            (
                "componentName",
                "component_name",
                "projectName",
            ),
        )
        or ""
    ).strip()


def component_version_name(
    component: dict[str, Any],
) -> str:
    value = first_value_by_key(
        component,
        (
            "componentVersionName",
            "versionName",
        ),
    )
    rendered = str(value or "").strip()

    if looks_like_resource_url(rendered):
        return ""

    return rendered


def is_linux_component(
    name: str,
    *,
    name_filter: str,
) -> bool:
    selected = str(name or "").casefold()
    required = str(
        name_filter or ""
    ).strip().casefold()

    if required and required not in selected:
        return False

    return (
        "linux" in selected
        or "kernel" in selected
    )


def candidate_score(
    *,
    component: str,
    component_version: str,
    project: str,
    project_version: str,
    requested_tag: str,
    selected_tag: str,
    component_version_href: str,
) -> int:
    score = 0
    component_text = component.casefold()

    if "linux" in component_text:
        score += 20

    if "kernel" in component_text:
        score += 20

    if component_version_href:
        score += 10

    requested_normalized = normalized_version(
        requested_tag
    )
    component_normalized = normalized_version(
        component_version
    )
    project_normalized = normalized_version(
        project_version
    )
    _, requested_base, _ = tag_parts(
        requested_tag
    )

    if requested_normalized:
        if (
            component_normalized
            == requested_normalized
        ):
            score += 100
        elif (
            requested_base
            and component_normalized
            == normalized_version(
                requested_base
            )
        ):
            score += 80

        if requested_normalized in (
            project_normalized
        ):
            score += 30

        if requested_normalized in (
            normalized_version(project)
        ):
            score += 20

    if selected_tag:
        score += 30

    if "cip" in component_normalized:
        score += 20

    return score


def collection_items(
    client: Any,
    url: str,
    *,
    limit: int,
    sort: str = "",
) -> list[dict[str, Any]]:
    parameters: dict[str, Any] = {
        "limit": limit,
        "offset": 0,
    }

    if sort:
        parameters["sort"] = sort

    try:
        payload = client.get(
            url,
            parameters,
        )
    except RuntimeError:
        if not sort:
            raise

        parameters.pop("sort", None)
        payload = client.get(
            url,
            parameters,
        )

    if not isinstance(payload, dict):
        raise RuntimeError(
            f"Collection response is not an "
            f"object: {url}"
        )

    items = payload.get("items")

    if not isinstance(items, list):
        if payload:
            return [payload]

        return []

    return [
        dict(item)
        for item in items
        if isinstance(item, dict)
    ]


def recent_project_versions(
    client: Any,
    *,
    max_projects: int,
    max_versions_per_project: int,
    max_project_versions: int,
    project_name_contains: str,
) -> tuple[
    list[ProjectVersion],
    list[DiscoveryFailure],
]:
    projects = collection_items(
        client,
        "/api/projects",
        limit=max_projects,
        sort="updatedAt DESC",
    )
    selected_projects = [
        project
        for project in projects
        if (
            not project_name_contains
            or project_name_contains.casefold()
            in str(
                project.get("name") or ""
            ).casefold()
        )
    ]
    versions: list[ProjectVersion] = []
    failures: list[DiscoveryFailure] = []

    for project in selected_projects:
        project_name = str(
            project.get("name") or ""
        )
        project_href = canonical_href(
            get_self_href(project)
        )
        versions_url = get_link(
            project,
            ("versions",),
        )

        if not versions_url and project_href:
            versions_url = (
                f"{project_href}/versions"
            )

        if not versions_url:
            failures.append(
                DiscoveryFailure(
                    project=project_name,
                    project_version="",
                    project_version_href="",
                    stage="find-project-versions-link",
                    error=(
                        "Project has no versions link"
                    ),
                )
            )
            continue

        try:
            resources = collection_items(
                client,
                versions_url,
                limit=(
                    max_versions_per_project
                ),
                sort="updatedAt DESC",
            )
        except Exception as error:
            failures.append(
                DiscoveryFailure(
                    project=project_name,
                    project_version="",
                    project_version_href="",
                    stage="load-project-versions",
                    error=str(error),
                )
            )
            continue

        for resource in resources:
            version_href = canonical_href(
                get_self_href(resource)
            )

            if not version_href:
                continue

            versions.append(
                ProjectVersion(
                    project=project_name,
                    project_version=(
                        version_name(resource)
                    ),
                    project_version_href=(
                        version_href
                    ),
                    project_href=project_href,
                )
            )

            if (
                len(versions)
                >= max_project_versions
            ):
                return versions, failures

    return versions, failures


def inspect_version(
    client: Any,
    project_version: ProjectVersion,
    *,
    component_name_contains: str,
    requested_tag: str,
    requested_branch: str,
) -> VersionDiscoveryResult:
    with blackduck_request_context(
        project=project_version.project,
        project_version=(
            project_version.project_version
        ),
        project_version_href=(
            project_version
            .project_version_href
        ),
        stage="cip-target-discovery",
    ):
        try:
            components = get_vulnerable_components(
                client,
                project_version
                .project_version_href,
            )
        except Exception as error:
            return VersionDiscoveryResult(
                candidates=(),
                failures=(
                    DiscoveryFailure(
                        project=(
                            project_version.project
                        ),
                        project_version=(
                            project_version
                            .project_version
                        ),
                        project_version_href=(
                            project_version
                            .project_version_href
                        ),
                        stage=(
                            "load-vulnerable-components"
                        ),
                        error=str(error),
                    ),
                ),
            )

    candidates: list[
        DiscoveryCandidate
    ] = []
    requested_canonical_tag, _, _ = (
        tag_parts(requested_tag)
    )

    for component in components:
        name = component_name(component)

        if not is_linux_component(
            name,
            name_filter=(
                component_name_contains
            ),
        ):
            continue

        version = component_version_name(
            component
        )
        version_href = canonical_href(
            component_version_href(
                component
            )
        )

        if not version_href:
            continue

        inferred_tag = suggested_tag(
            version,
            project_version.project_version,
            project_version.project,
        )
        selected_tag = (
            requested_canonical_tag
            or requested_tag
            or inferred_tag
        )
        selected_branch = (
            requested_branch
            or branch_from_value(
                selected_tag
                or version
            )
        )
        score = candidate_score(
            component=name,
            component_version=version,
            project=project_version.project,
            project_version=(
                project_version.project_version
            ),
            requested_tag=requested_tag,
            selected_tag=selected_tag,
            component_version_href=(
                version_href
            ),
        )

        candidates.append(
            DiscoveryCandidate(
                project=project_version.project,
                project_version=(
                    project_version.project_version
                ),
                project_version_href=(
                    project_version
                    .project_version_href
                ),
                component=name,
                component_version=version,
                component_version_href=(
                    version_href
                ),
                bom_component_href=(
                    canonical_href(
                        get_self_href(component)
                    )
                ),
                cip_tag=selected_tag,
                cip_branch=selected_branch,
                score=score,
            )
        )

    return VersionDiscoveryResult(
        candidates=tuple(candidates),
        failures=(),
    )


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


def write_environment(
    path: str,
    environment: dict[str, str],
) -> None:
    for key, value in environment.items():
        if (
            not key
            or not value
            or "\n" in value
            or "\r" in value
        ):
            raise ValueError(
                "Selected target environment is "
                "incomplete or invalid"
            )

    ensure_parent_dir(path)
    destination = Path(path)
    temporary = destination.with_name(
        f"{destination.name}."
        f"{uuid.uuid4().hex}.tmp"
    )
    content = "\n".join(
        f"{key}={value}"
        for key, value
        in sorted(environment.items())
    ) + "\n"

    try:
        temporary.write_text(
            content,
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
        "max_projects",
        "max_versions_per_project",
        "max_project_versions",
        "workers",
        "timeout",
        "page_limit",
    ):
        if int(getattr(args, name)) < 1:
            raise RuntimeError(
                f"--{name.replace('_', '-')} "
                "must be greater than zero"
            )

    if args.retries < 0:
        raise RuntimeError(
            "--retries cannot be negative"
        )

    if args.retry_delay < 0:
        raise RuntimeError(
            "--retry-delay cannot be negative"
        )

    if args.request_interval_seconds < 0:
        raise RuntimeError(
            "--request-interval-seconds cannot "
            "be negative"
        )

    if args.cip_tag:
        tag, _, _ = tag_parts(
            args.cip_tag
        )

        if not tag:
            raise RuntimeError(
                "--cip-tag must use a form like "
                "v6.1.173-cip56"
            )


def run(
    args: argparse.Namespace,
) -> int:
    validate_args(args)
    client = BlackDuckClient(
        base_url=args.bd_url,
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

    with FileLock(
        args.lock,
        stale_seconds=(
            args.lock_stale_seconds
        ),
        wait_seconds=0,
    ):
        versions, failures = (
            recent_project_versions(
                client,
                max_projects=(
                    args.max_projects
                ),
                max_versions_per_project=(
                    args
                    .max_versions_per_project
                ),
                max_project_versions=(
                    args.max_project_versions
                ),
                project_name_contains=(
                    args.project_name_contains
                ),
            )
        )
        worker_count = min(
            bounded_worker_count(
                args.workers,
                maximum=8,
            ),
            len(versions),
        )

        if versions:
            worker_local = threading.local()

            def worker_client() -> Any:
                selected = getattr(
                    worker_local,
                    "client",
                    None,
                )

                if selected is None:
                    selected = (
                        client.clone_for_uncached_reads()
                    )
                    worker_local.client = selected

                return selected

            def inspect(
                project_version: ProjectVersion,
            ) -> VersionDiscoveryResult:
                return inspect_version(
                    worker_client(),
                    project_version,
                    component_name_contains=(
                        args
                        .component_name_contains
                    ),
                    requested_tag=(
                        args.cip_tag
                    ),
                    requested_branch=(
                        args.cip_branch
                    ),
                )

            results = ordered_parallel_map(
                versions,
                inspect,
                workers=max(1, worker_count),
                maximum=8,
            )
        else:
            results = []

        candidates = [
            candidate
            for result in results
            for candidate in result.candidates
        ]
        failures.extend(
            failure
            for result in results
            for failure in result.failures
        )
        candidates.sort(
            key=lambda candidate: (
                -candidate.score,
                candidate.project.casefold(),
                candidate
                .project_version
                .casefold(),
                candidate
                .component
                .casefold(),
                candidate
                .component_version
                .casefold(),
                candidate
                .component_version_href,
            )
        )
        selected = next(
            (
                candidate
                for candidate in candidates
                if candidate.complete
            ),
            None,
        )

        if selected is not None:
            write_environment(
                args.environment_out,
                selected.environment,
            )
        else:
            Path(
                args.environment_out
            ).unlink(missing_ok=True)

        payload = {
            "schema_version": 1,
            "search": {
                "cip_tag": args.cip_tag,
                "cip_branch": args.cip_branch,
                "component_name_contains": (
                    args.component_name_contains
                ),
                "project_name_contains": (
                    args.project_name_contains
                ),
                "max_projects": (
                    args.max_projects
                ),
                "max_versions_per_project": (
                    args
                    .max_versions_per_project
                ),
                "max_project_versions": (
                    args.max_project_versions
                ),
            },
            "project_version_count": (
                len(versions)
            ),
            "candidate_count": (
                len(candidates)
            ),
            "failure_count": len(failures),
            "selected": (
                selected.as_dict()
                if selected is not None
                else None
            ),
            "candidates": [
                candidate.as_dict()
                for candidate
                in candidates[
                    :args.max_candidates
                ]
            ],
            "failures": [
                failure.as_dict()
                for failure in failures
            ],
            "environment_file": (
                args.environment_out
                if selected is not None
                else ""
            ),
        }
        atomic_write_json(
            args.output,
            payload,
        )

    summary = {
        "output": args.output,
        "environment_file": (
            args.environment_out
            if selected is not None
            else ""
        ),
        "project_versions_scanned": (
            len(versions)
        ),
        "candidate_count": len(candidates),
        "selected": (
            selected.as_dict()
            if selected is not None
            else None
        ),
    }
    print(
        json.dumps(
            summary,
            indent=2,
            sort_keys=True,
        )
    )

    if selected is None:
        print(
            "No complete CIP target was selected. "
            "Set WINTERMUTE_CIP_TAG when the "
            "Black Duck component only exposes the "
            "upstream kernel version, or increase "
            "--max-projects and "
            "--max-project-versions.",
            file=sys.stderr,
        )
        return 1

    return 0


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Find a recent Black Duck project version "
            "containing a vulnerable Linux component."
        )
    )
    parser.add_argument(
        "--output",
        default=default_output_path(),
    )
    parser.add_argument(
        "--environment-out",
        default=default_environment_path(),
    )
    parser.add_argument(
        "--cip-tag",
        default=os.getenv(
            "WINTERMUTE_CIP_TAG",
            "",
        ),
    )
    parser.add_argument(
        "--cip-branch",
        default=os.getenv(
            "WINTERMUTE_CIP_BRANCH",
            "",
        ),
    )
    parser.add_argument(
        "--component-name-contains",
        default=os.getenv(
            "WINTERMUTE_CIP_COMPONENT_NAME",
            "linux",
        ),
    )
    parser.add_argument(
        "--project-name-contains",
        default="",
    )
    parser.add_argument(
        "--max-projects",
        type=int,
        default=50,
    )
    parser.add_argument(
        "--max-versions-per-project",
        type=int,
        default=5,
    )
    parser.add_argument(
        "--max-project-versions",
        type=int,
        default=100,
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        default=100,
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=2,
    )
    parser.add_argument(
        "--lock",
        default=default_lock_path(),
    )
    parser.add_argument(
        "--lock-stale-seconds",
        type=float,
        default=7200,
    )
    parser.add_argument(
        "--bd-url",
        default=os.getenv("BLACKDUCK_URL"),
        required=(
            os.getenv("BLACKDUCK_URL")
            is None
        ),
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
        LockUnavailableError,
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
