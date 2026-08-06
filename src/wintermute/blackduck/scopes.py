from __future__ import annotations

from enum import Enum
from typing import Any, Iterable, Mapping

from wintermute.blackduck.models import (
    CollectionTarget,
    LineageContext,
    ProjectVersionRef,
)


class CollectionScope(str, Enum):
    PARENT_ROLLUP = "parent-rollup"
    CANDIDATE_PROJECTS = "candidate-projects"
    ALL_PROJECT_VERSIONS = "all-project-versions"
    EXPLICIT_PROJECT_VERSIONS = "explicit-project-versions"


_SCOPE_ALIASES = {
    "parent": CollectionScope.PARENT_ROLLUP,
    "parents": CollectionScope.PARENT_ROLLUP,
    "parent-rollup": CollectionScope.PARENT_ROLLUP,
    "candidate": CollectionScope.CANDIDATE_PROJECTS,
    "candidates": CollectionScope.CANDIDATE_PROJECTS,
    "candidate-projects": CollectionScope.CANDIDATE_PROJECTS,
    "all": CollectionScope.ALL_PROJECT_VERSIONS,
    "all-project-versions": CollectionScope.ALL_PROJECT_VERSIONS,
    "explicit": CollectionScope.EXPLICIT_PROJECT_VERSIONS,
    "explicit-project-versions": (
        CollectionScope.EXPLICIT_PROJECT_VERSIONS
    ),
}


def normalize_scope(value: str | CollectionScope) -> CollectionScope:
    if isinstance(value, CollectionScope):
        return value

    normalized = str(value or "").strip().lower()

    try:
        return _SCOPE_ALIASES[normalized]
    except KeyError as error:
        supported = ", ".join(
            scope.value for scope in CollectionScope
        )
        raise ValueError(
            f"Unsupported collection scope {value!r}; "
            f"expected one of: {supported}"
        ) from error


def _value(
    row: Mapping[str, Any],
    *names: str,
) -> str:
    for name in names:
        value = str(row.get(name) or "").strip()

        if value:
            return value

    return ""


def targets_from_parent_relationships(
    rows: Iterable[Mapping[str, Any]],
    *,
    instance_url: str = "",
) -> list[CollectionTarget]:
    targets: dict[str, CollectionTarget] = {}

    for row in rows:
        child = ProjectVersionRef(
            instance_url=instance_url,
            project=_value(
                row,
                "child_project",
                "subproject",
                "project",
            ),
            version=_value(
                row,
                "child_version",
                "subproject_version",
                "project_version",
            ),
            project_href=_value(
                row,
                "child_project_href",
                "subproject_href",
                "project_href",
            ),
            version_href=_value(
                row,
                "child_version_href",
                "subproject_version_href",
                "project_version_href",
            ),
            phase=_value(
                row,
                "child_phase",
                "project_phase",
            ),
            updated=_value(
                row,
                "child_updated",
                "project_updated",
            ),
        )
        parent = ProjectVersionRef(
            instance_url=instance_url,
            project=_value(row, "parent_project"),
            version=_value(row, "parent_version"),
            project_href=_value(row, "parent_project_href"),
            version_href=_value(row, "parent_version_href"),
            phase=_value(row, "parent_phase"),
            updated=_value(row, "parent_updated"),
        )

        context = LineageContext(
            parent=parent,
            child=child,
            detection_method=_value(
                row,
                "detection_method",
                "relationship_detection_method",
                "source",
            ),
            bom_component_name=_value(
                row,
                "bom_component_name",
            ),
            bom_component_version=_value(
                row,
                "bom_component_version",
            ),
        )
        existing = targets.get(child.identity_key)

        if existing is None:
            existing = CollectionTarget(
                project_version=child,
            )

        targets[child.identity_key] = existing.with_contexts(
            [context]
        )

    return [
        targets[key]
        for key in sorted(targets)
    ]


def targets_from_candidates(
    rows: Iterable[Mapping[str, Any]],
    *,
    instance_url: str = "",
) -> list[CollectionTarget]:
    targets: dict[str, CollectionTarget] = {}

    for row in rows:
        project_version = ProjectVersionRef(
            instance_url=instance_url,
            project=_value(row, "project"),
            version=_value(row, "project_version"),
            project_href=_value(row, "project_href"),
            version_href=_value(
                row,
                "project_version_href",
            ),
            phase=_value(row, "project_phase"),
            updated=_value(row, "project_updated"),
        )
        targets.setdefault(
            project_version.identity_key,
            CollectionTarget(
                project_version=project_version,
            ),
        )

    return [
        targets[key]
        for key in sorted(targets)
    ]


def resolve_targets(
    scope: str | CollectionScope,
    rows: Iterable[Mapping[str, Any]],
    *,
    instance_url: str = "",
) -> list[CollectionTarget]:
    normalized = normalize_scope(scope)

    if normalized == CollectionScope.PARENT_ROLLUP:
        return targets_from_parent_relationships(
            rows,
            instance_url=instance_url,
        )

    return targets_from_candidates(
        rows,
        instance_url=instance_url,
    )
