from __future__ import annotations

import re
import sys
from collections.abc import Callable, Mapping
from typing import Any

from wintermute.blackduck.models import (
    LineageContext,
    ProjectVersionRef,
)
from wintermute.blackduck.resources import (
    canonical_href,
    first_value_by_key,
    get_link,
    get_self_href,
    iter_hrefs,
)


PROJECT_VERSION_RE = re.compile(
    r"/api/projects/[0-9a-fA-F-]+/versions/[0-9a-fA-F-]+"
)


def version_name(version: dict[str, Any]) -> str:
    return str(
        version.get("versionName")
        or version.get("name")
        or ""
    )


def extract_project_version_hrefs(
    raw_href: str,
    base_url: str,
) -> list[str]:
    hrefs: list[str] = []

    for match in PROJECT_VERSION_RE.finditer(
        str(raw_href or "")
    ):
        path = match.group(0)

        if raw_href.startswith(
            ("http://", "https://")
        ):
            from urllib.parse import urlparse

            parsed = urlparse(raw_href)
            href = (
                f"{parsed.scheme}://{parsed.netloc}{path}"
            )
        else:
            href = f"{base_url.rstrip('/')}{path}"

        hrefs.append(canonical_href(href))

    return hrefs


def project_href_from_version_href(
    version_href: str,
) -> str:
    match = re.search(
        r"(.*/api/projects/[0-9a-fA-F-]+)"
        r"/versions/[0-9a-fA-F-]+",
        str(version_href or ""),
    )

    if not match:
        return ""

    return canonical_href(match.group(1))


def build_project_version_indexes(
    project_versions: list[ProjectVersionRef],
) -> tuple[
    dict[str, ProjectVersionRef],
    dict[tuple[str, str], list[ProjectVersionRef]],
]:
    by_href: dict[str, ProjectVersionRef] = {}
    by_name: dict[
        tuple[str, str],
        list[ProjectVersionRef],
    ] = {}

    for project_version in project_versions:
        if project_version.version_href:
            by_href[
                project_version.version_href
            ] = project_version

        by_name.setdefault(
            (
                project_version.project,
                project_version.version,
            ),
            [],
        ).append(project_version)

    return by_href, by_name


def resolve_project_version(
    client: Any,
    version_href: str,
    versions_by_href: Mapping[
        str,
        ProjectVersionRef,
    ],
) -> ProjectVersionRef | None:
    version_href = canonical_href(version_href)
    existing = versions_by_href.get(version_href)

    if existing is not None:
        return existing

    project_href = project_href_from_version_href(
        version_href
    )

    if not project_href:
        return None

    try:
        project = client.get(project_href)
        version = client.get(version_href)
    except RuntimeError:
        return None

    project_name = str(project.get("name") or "")
    current_version_name = version_name(version)

    if not project_name or not current_version_name:
        return None

    updated = str(
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

    return ProjectVersionRef(
        instance_url=str(
            getattr(client, "base_url", "")
        ),
        project=project_name,
        version=current_version_name,
        project_href=project_href,
        version_href=version_href,
        phase=str(version.get("phase") or ""),
        updated=updated,
    )


def get_bom_components(
    client: Any,
    project_version: ProjectVersionRef,
) -> list[dict[str, Any]]:
    components_url = (
        f"{project_version.version_href}/components"
    )

    try:
        return client.paged_get(components_url)
    except RuntimeError as direct_error:
        try:
            version = client.get(
                project_version.version_href
            )
            linked_url = get_link(
                version,
                (
                    "components",
                    "bom-components",
                    "bomComponents",
                ),
            )

            if linked_url:
                return client.paged_get(linked_url)

        except RuntimeError:
            pass

        raise direct_error


def discover_lineage_contexts(
    client: Any,
    parent: ProjectVersionRef,
    versions_by_href: Mapping[
        str,
        ProjectVersionRef,
    ],
    versions_by_name: Mapping[
        tuple[str, str],
        list[ProjectVersionRef],
    ],
    *,
    resolve_bom_names: bool,
    debug: bool = False,
    bom_loader: Callable[
        [Any, ProjectVersionRef],
        list[dict[str, Any]],
    ]
    | None = None,
) -> list[LineageContext]:
    loader = bom_loader or get_bom_components
    bom_components = loader(client, parent)
    contexts: list[LineageContext] = []
    seen_child_hrefs: set[str] = set()

    for bom_item in bom_components:
        component_name = str(
            first_value_by_key(
                bom_item,
                ("componentName", "name"),
            )
            or ""
        )
        component_version = str(
            first_value_by_key(
                bom_item,
                (
                    "componentVersionName",
                    "componentVersion",
                    "versionName",
                ),
            )
            or ""
        )
        detected_hrefs: list[str] = []

        for raw_href in iter_hrefs(bom_item):
            detected_hrefs.extend(
                extract_project_version_hrefs(
                    raw_href,
                    str(
                        getattr(
                            client,
                            "base_url",
                            parent.instance_url,
                        )
                    ),
                )
            )

        for detected_href in detected_hrefs:
            detected_href = canonical_href(
                detected_href
            )

            if detected_href == parent.version_href:
                continue

            if detected_href in seen_child_hrefs:
                continue

            child = resolve_project_version(
                client,
                detected_href,
                versions_by_href,
            )

            if child is None:
                continue

            seen_child_hrefs.add(child.version_href)
            contexts.append(
                LineageContext(
                    parent=parent,
                    child=child,
                    detection_method="api-href",
                    bom_component_name=component_name,
                    bom_component_version=(
                        component_version
                    ),
                )
            )

        if (
            resolve_bom_names
            and component_name
            and component_version
        ):
            matches = versions_by_name.get(
                (
                    component_name,
                    component_version,
                ),
                [],
            )

            if len(matches) > 1 and debug:
                print(
                    f"Ambiguous BOM name match for "
                    f"{component_name} / "
                    f"{component_version}: "
                    f"{len(matches)} project versions",
                    file=sys.stderr,
                )

            for child in matches:
                if (
                    child.version_href
                    == parent.version_href
                ):
                    continue

                if child.version_href in seen_child_hrefs:
                    continue

                seen_child_hrefs.add(child.version_href)
                contexts.append(
                    LineageContext(
                        parent=parent,
                        child=child,
                        detection_method=(
                            "bom-component-name-version"
                        ),
                        bom_component_name=(
                            component_name
                        ),
                        bom_component_version=(
                            component_version
                        ),
                    )
                )

    return contexts


def lineage_context_to_row(
    context: LineageContext,
) -> dict[str, str]:
    return {
        "parent_project": context.parent.project,
        "parent_version": context.parent.version,
        "parent_phase": context.parent.phase,
        "parent_updated": context.parent.updated,
        "child_project": context.child.project,
        "child_version": context.child.version,
        "child_phase": context.child.phase,
        "detection_method": (
            context.detection_method
        ),
        "bom_component_name": (
            context.bom_component_name
        ),
        "bom_component_version": (
            context.bom_component_version
        ),
        "parent_version_href": (
            context.parent.version_href
        ),
        "child_version_href": (
            context.child.version_href
        ),
    }
