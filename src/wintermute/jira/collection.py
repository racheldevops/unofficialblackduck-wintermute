from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from wintermute.blackduck.criteria import (
    CollectionCriteria,
)
from wintermute.blackduck.models import (
    CollectionTarget,
    LineageContext,
)
from wintermute.blackduck.pull import (
    PullRequest,
    pull_rows,
)
from wintermute.blackduck.scopes import CollectionScope
from wintermute.blackduck.projections import (
    jira_parent_rollup_rows,
)
from wintermute.blackduck.resources import (
    canonical_href,
)


EntityResolver = Callable[
    [Any, CollectionTarget],
    str,
]


@dataclass(frozen=True)
class JiraParentRollupFailure:
    parent_project: str
    parent_version: str
    child_project: str
    child_version: str
    child_version_href: str
    source: str
    stage: str
    error: str
    elapsed_seconds: float


@dataclass(frozen=True)
class JiraParentRollupResult:
    rows: tuple[dict[str, Any], ...]
    failures: tuple[JiraParentRollupFailure, ...]
    target_count: int
    finding_count: int


def relationship_identity(
    *,
    parent_project: str,
    parent_version: str,
    parent_version_href: str,
    child_project: str,
    child_version: str,
    child_version_href: str,
) -> tuple[str, str]:
    parent_identity = (
        canonical_href(parent_version_href)
        or "|".join(
            [
                parent_project,
                parent_version,
            ]
        )
    )
    child_identity = (
        canonical_href(child_version_href)
        or "|".join(
            [
                child_project,
                child_version,
            ]
        )
    )

    return parent_identity, child_identity


def relationship_identity_from_row(
    row: Mapping[str, Any],
) -> tuple[str, str]:
    return relationship_identity(
        parent_project=str(
            row.get("parent_project") or ""
        ),
        parent_version=str(
            row.get("parent_version") or ""
        ),
        parent_version_href=str(
            row.get("parent_version_href") or ""
        ),
        child_project=str(
            row.get("child_project")
            or row.get("subproject")
            or ""
        ),
        child_version=str(
            row.get("child_version")
            or row.get("subproject_version")
            or ""
        ),
        child_version_href=str(
            row.get("child_version_href")
            or row.get("subproject_version_href")
            or ""
        ),
    )


def relationship_identity_from_context(
    context: LineageContext,
) -> tuple[str, str]:
    return relationship_identity(
        parent_project=context.parent.project,
        parent_version=context.parent.version,
        parent_version_href=(
            context.parent.version_href
        ),
        child_project=context.child.project,
        child_version=context.child.version,
        child_version_href=(
            context.child.version_href
        ),
    )


def collect_parent_rollup(
    client: Any,
    relationships: Iterable[Mapping[str, Any]],
    criteria: CollectionCriteria,
    *,
    workers: int,
    component_workers: int = 1,
    entity_resolver: EntityResolver | None = None,
) -> JiraParentRollupResult:
    relationship_rows = [
        dict(row)
        for row in relationships
    ]
    paths_by_relationship = {
        relationship_identity_from_row(row): str(
            row.get("subproject_path")
            or row.get("path")
            or ""
        )
        for row in relationship_rows
    }
    execution = pull_rows(
        client,
        relationship_rows,
        PullRequest(
            scope=CollectionScope.PARENT_ROLLUP,
            criteria=criteria,
            workers=workers,
            component_workers=component_workers,
        ),
        entity_resolver=entity_resolver,
    )
    run_result = execution.collection
    projected_rows = jira_parent_rollup_rows(
        run_result.findings
    )

    for row in projected_rows:
        key = relationship_identity_from_row(row)
        configured_path = paths_by_relationship.get(
            key,
            "",
        )

        if configured_path:
            row["subproject_path"] = (
                configured_path
            )

    failures: list[JiraParentRollupFailure] = []

    for target_result in run_result.target_results:
        contexts = (
            target_result.target.lineage_contexts
        )

        for failure in target_result.failures:
            if contexts:
                for context in contexts:
                    failures.append(
                        JiraParentRollupFailure(
                            parent_project=(
                                context.parent.project
                            ),
                            parent_version=(
                                context.parent.version
                            ),
                            child_project=(
                                context.child.project
                            ),
                            child_version=(
                                context.child.version
                            ),
                            child_version_href=(
                                context.child.version_href
                            ),
                            source=(
                                context.detection_method
                            ),
                            stage=failure.stage,
                            error=failure.error,
                            elapsed_seconds=(
                                target_result.elapsed_seconds
                            ),
                        )
                    )
            else:
                project_version = (
                    target_result.target.project_version
                )
                failures.append(
                    JiraParentRollupFailure(
                        parent_project="",
                        parent_version="",
                        child_project=(
                            project_version.project
                        ),
                        child_version=(
                            project_version.version
                        ),
                        child_version_href=(
                            project_version.version_href
                        ),
                        source="",
                        stage=failure.stage,
                        error=failure.error,
                        elapsed_seconds=(
                            target_result.elapsed_seconds
                        ),
                    )
                )

    return JiraParentRollupResult(
        rows=tuple(projected_rows),
        failures=tuple(failures),
        target_count=execution.target_count,
        finding_count=execution.finding_count,
    )
