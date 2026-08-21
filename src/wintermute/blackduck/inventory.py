from __future__ import annotations

import sys
import threading
from dataclasses import dataclass
from typing import Any

from wintermute.blackduck.models import ProjectVersionRef
from wintermute.blackduck.request_control import (
    BlackDuckCircuitOpenError,
)
from wintermute.blackduck.resources import (
    canonical_href,
    first_value_by_key,
    get_link,
    get_self_href,
)
from wintermute.concurrency import (
    DEFAULT_IO_WORKERS,
    MAX_IO_WORKERS,
    bounded_worker_count,
    ordered_parallel_map,
)


@dataclass(frozen=True)
class InventoryFilter:
    project_name: str = ""
    project_name_contains: str = ""
    version_name: str = ""
    phase: str = ""
    max_projects: int | None = None
    max_versions: int | None = None


@dataclass(frozen=True)
class InventoryFailure:
    project: str
    project_href: str
    stage: str
    error: str


@dataclass(frozen=True)
class InventoryItem:
    project_resource: dict[str, Any]
    version_resource: dict[str, Any]
    project_version: ProjectVersionRef
    created: str = ""


@dataclass(frozen=True)
class InventoryResult:
    items: tuple[InventoryItem, ...]
    failures: tuple[InventoryFailure, ...]
    selected_project_count: int

    @property
    def project_version_count(self) -> int:
        return len(self.items)


def version_name(version: dict[str, Any]) -> str:
    return str(
        version.get("versionName")
        or version.get("name")
        or ""
    )


def version_updated(version: dict[str, Any]) -> str:
    return str(
        first_value_by_key(
            version,
            (
                "updatedAt",
                "updatedDate",
                "lastUpdated",
                "lastUpdatedDate",
                "modifiedAt",
                "modifiedDate",
                "updated",
            ),
        )
        or ""
    )


def version_created(version: dict[str, Any]) -> str:
    return str(
        first_value_by_key(
            version,
            (
                "createdAt",
                "createdDate",
                "created",
            ),
        )
        or ""
    )


def get_project_versions(
    client: Any,
    project: dict[str, Any],
) -> list[dict[str, Any]]:
    versions_url = get_link(project, ("versions",))

    if not versions_url:
        project_href = get_self_href(project)

        if not project_href:
            return []

        versions_url = f"{project_href}/versions"

    return client.paged_get(versions_url)


def build_project_version_inventory(
    client: Any,
    *,
    filters: InventoryFilter | None = None,
    workers: int = DEFAULT_IO_WORKERS,
    debug: bool = False,
) -> InventoryResult:
    filters = filters or InventoryFilter()
    projects = client.paged_get("/api/projects")
    selected_projects: list[dict[str, Any]] = []

    for project in projects:
        project_name = str(project.get("name") or "")

        if (
            filters.project_name
            and project_name != filters.project_name
        ):
            continue

        if (
            filters.project_name_contains
            and filters.project_name_contains.lower()
            not in project_name.lower()
        ):
            continue

        selected_projects.append(project)

        if (
            filters.max_projects is not None
            and len(selected_projects) >= filters.max_projects
        ):
            break

    if not selected_projects:
        return InventoryResult(
            items=(),
            failures=(),
            selected_project_count=0,
        )

    worker_count = min(
        bounded_worker_count(
            workers,
            maximum=MAX_IO_WORKERS,
        ),
        len(selected_projects),
    )
    worker_local = threading.local()

    def worker_client() -> Any:
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

    def load_project(
        project: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], str]:
        project_name = str(project.get("name") or "")

        if debug:
            print(
                f"Indexing project: {project_name}",
                file=sys.stderr,
            )

        try:
            return (
                get_project_versions(
                    worker_client(),
                    project,
                ),
                "",
            )
        except BlackDuckCircuitOpenError:
            raise
        except RuntimeError as error:
            return [], str(error)

    loaded_projects = ordered_parallel_map(
        selected_projects,
        load_project,
        workers=worker_count,
        maximum=MAX_IO_WORKERS,
    )
    items: list[InventoryItem] = []
    failures: list[InventoryFailure] = []

    for project, (versions, error) in zip(
        selected_projects,
        loaded_projects,
        strict=True,
    ):
        project_name = str(project.get("name") or "")
        project_href = canonical_href(
            get_self_href(project)
        )

        if error:
            failures.append(
                InventoryFailure(
                    project=project_name,
                    project_href=project_href,
                    stage="load-project-versions",
                    error=error,
                )
            )
            continue

        for version in versions:
            current_version_name = version_name(version)

            if (
                filters.version_name
                and current_version_name
                != filters.version_name
            ):
                continue

            phase = str(version.get("phase") or "")

            if filters.phase and phase != filters.phase:
                continue

            version_href = canonical_href(
                get_self_href(version)
            )

            if not version_href:
                failures.append(
                    InventoryFailure(
                        project=project_name,
                        project_href=project_href,
                        stage="missing-version-href",
                        error=(
                            f"Project version "
                            f"{current_version_name!r} has no self href"
                        ),
                    )
                )
                continue

            items.append(
                InventoryItem(
                    project_resource=project,
                    version_resource=version,
                    project_version=ProjectVersionRef(
                        instance_url=str(
                            getattr(client, "base_url", "")
                        ),
                        project=project_name,
                        version=current_version_name,
                        project_href=project_href,
                        version_href=version_href,
                        phase=phase,
                        updated=version_updated(version),
                    ),
                    created=version_created(version),
                )
            )

            if (
                filters.max_versions is not None
                and len(items) >= filters.max_versions
            ):
                return InventoryResult(
                    items=tuple(items),
                    failures=tuple(failures),
                    selected_project_count=len(
                        selected_projects
                    ),
                )

    return InventoryResult(
        items=tuple(items),
        failures=tuple(failures),
        selected_project_count=len(selected_projects),
    )
