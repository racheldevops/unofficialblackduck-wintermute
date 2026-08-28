from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

from wintermute.concurrency import (
    bounded_worker_count,
    ordered_parallel_map,
)
from wintermute.scm.models import (
    InventoryFailure,
    Repository,
    RepositoryExclusion,
    RepositoryInventory,
    ScmTenant,
    normalize_language,
)
from wintermute.scm.providers.gitlab.client import (
    GitLabRestClient,
    GitLabRestError,
)
from wintermute.scm.providers.gitlab.graphql import (
    GitLabGraphQLClient,
    GitLabGraphQLError,
    GitLabGraphQLStats,
    normalize_graphql_url,
)
from wintermute.scm.providers.gitlab.repository import (
    validate_revision,
)


_ENCODED = r"[A-Za-z0-9._~%+-]+"
_ALLOWED_PATHS = (
    re.compile(
        rf"^/groups/{_ENCODED}$"
    ),
    re.compile(
        rf"^/groups/{_ENCODED}/projects$"
    ),
    re.compile(
        rf"^/projects/{_ENCODED}/languages$"
    ),
    re.compile(
        rf"^/projects/{_ENCODED}/pipelines$"
    ),
    re.compile(
        rf"^/projects/{_ENCODED}/"
        rf"protected_branches/{_ENCODED}$"
    ),
)


def required_string(
    value: Any,
    field: str,
) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
    ):
        raise ValueError(
            f"GitLab field {field!r} must be "
            "a nonempty string"
        )

    return value.strip()


def required_identifier(
    value: Any,
    field: str,
) -> str:
    if isinstance(value, int):
        if value < 1:
            raise ValueError(
                f"GitLab field {field!r} is invalid"
            )

        return str(value)

    return required_string(value, field)


def boolean_value(
    value: Any,
    field: str,
) -> bool:
    if type(value) is not bool:
        raise ValueError(
            f"GitLab field {field!r} must be boolean"
        )

    return value


def parse_timestamp(
    value: Any,
) -> datetime | None:
    selected = str(value or "").strip()

    if not selected:
        return None

    normalized = (
        selected[:-1] + "+00:00"
        if selected.endswith("Z")
        else selected
    )

    try:
        parsed = datetime.fromisoformat(
            normalized
        )
    except ValueError:
        return None

    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
    ):
        return None

    return parsed.astimezone(timezone.utc)


def activity_status(
    value: Any,
    cutoff: datetime,
) -> str:
    parsed = parse_timestamp(value)

    if parsed is None:
        return "unknown"

    return (
        "active"
        if parsed >= cutoff
        else "inactive"
    )


def primary_language(
    values: dict[str, Any],
) -> tuple[str, ...]:
    percentages: list[
        tuple[float, str]
    ] = []

    for name, raw_percentage in values.items():
        try:
            percentage = float(
                raw_percentage
            )
        except (
            TypeError,
            ValueError,
        ):
            continue

        if percentage <= 0:
            continue

        percentages.append(
            (
                percentage,
                normalize_language(name),
            )
        )

    if not percentages:
        return ("unknown",)

    selected = min(
        percentages,
        key=lambda item: (
            -item[0],
            item[1],
        ),
    )

    return (selected[1],)


class GitLabClient(GitLabRestClient):
    provider = "gitlab"

    def __init__(
        self,
        group: str,
        token: str,
        *,
        page_size: int = 100,
        activity_days: int = 180,
        workers: int = 4,
        pipeline_limit: int = 3,
        graphql_endpoint: str = "",
        clock: Any = (
            lambda: datetime.now(timezone.utc)
        ),
        **kwargs: Any,
    ) -> None:
        group = str(group or "").strip(
            "/"
        )

        if (
            not group
            or any(
                not part
                or part in {".", ".."}
                for part in group.split("/")
            )
        ):
            raise ValueError(
                "GitLab group is invalid"
            )

        if not 1 <= page_size <= 100:
            raise ValueError(
                "page_size must be between 1 and 100"
            )

        if activity_days < 1:
            raise ValueError(
                "activity_days must be positive"
            )

        if not 1 <= workers <= 8:
            raise ValueError(
                "workers must be between 1 and 8"
            )

        if not 0 <= pipeline_limit <= 100:
            raise ValueError(
                "pipeline_limit must be between 0 and 100"
            )

        self.group = group
        self.page_size = page_size
        self.activity_days = activity_days
        self.workers = workers
        self.pipeline_limit = pipeline_limit
        self._clock = clock
        self._languages_by_project_id: dict[
            str,
            dict[str, Any],
        ] = {}
        self._pipelines_by_project_id: dict[
            str,
            tuple[dict[str, Any], ...],
        ] = {}
        self._complete_pipeline_projects: set[
            str
        ] = set()
        self._ci_path_by_project_id: dict[
            str,
            str,
        ] = {}
        self.graphql_fallback_error = ""

        super().__init__(
            token=token,
            **kwargs,
        )
        self.graphql = GitLabGraphQLClient(
            token,
            endpoint=(
                graphql_endpoint
                or normalize_graphql_url(
                    self.base_url
                )
            ),
            timeout=self.timeout,
            retries=self.retries,
            retry_delay=self.retry_delay,
            request_interval_seconds=(
                self.request_interval_seconds
            ),
            insecure=bool(
                self.ssl_context is not None
                and kwargs.get(
                    "insecure",
                    False,
                )
            ),
            ca_bundle=kwargs.get("ca_bundle"),
            deadline=self.deadline,
            sleeper=self._sleeper,
        )

    def graphql_stats(self) -> GitLabGraphQLStats:
        return self.graphql.stats()

    def group_path(
        self,
        suffix: str = "",
    ) -> str:
        path = (
            f"/groups/"
            f"{quote(self.group, safe='')}"
        )

        if suffix:
            path = (
                f"{path}/{suffix.lstrip('/')}"
            )

        return path

    def project_path(
        self,
        project_id: str,
        suffix: str,
    ) -> str:
        identifier = required_identifier(
            project_id,
            "project.id",
        )

        return (
            f"/projects/"
            f"{quote(identifier, safe='')}/"
            f"{suffix.lstrip('/')}"
        )

    def paged_list(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        values: list[dict[str, Any]] = []

        for page in range(1, 10001):
            payload, headers = (
                self._json_response(
                    path,
                    params={
                        **dict(params or {}),
                        "per_page": self.page_size,
                        "page": page,
                    },
                )
            )

            if (
                not isinstance(payload, list)
                or not all(
                    isinstance(value, dict)
                    for value in payload
                )
            ):
                raise GitLabRestError(
                    "invalid_response",
                    f"GET {path} returned a "
                    "malformed list",
                    attempts=1,
                )

            values.extend(
                dict(value)
                for value in payload
            )
            next_page = self._header(
                headers,
                "X-Next-Page",
            ).strip()

            if next_page:
                try:
                    next_value = int(next_page)
                except ValueError as error:
                    raise GitLabRestError(
                        "pagination_error",
                        "GitLab returned an invalid "
                        "next-page header",
                        attempts=1,
                    ) from error

                if next_value <= page:
                    raise GitLabRestError(
                        "pagination_error",
                        "GitLab pagination did not advance",
                        attempts=1,
                    )

                continue

            total_pages = self._header(
                headers,
                "X-Total-Pages",
            ).strip()

            if total_pages:
                try:
                    if page < int(total_pages):
                        continue
                except ValueError as error:
                    raise GitLabRestError(
                        "pagination_error",
                        "GitLab returned an invalid "
                        "total-pages header",
                        attempts=1,
                    ) from error

            return values

        raise GitLabRestError(
            "pagination_error",
            f"GET {path} exceeded the page limit",
            attempts=1,
        )

    def list_tenants(
        self,
    ) -> tuple[ScmTenant, ...]:
        payload = self.get_json(
            self.group_path()
        )

        if not isinstance(payload, dict):
            raise GitLabRestError(
                "invalid_response",
                "GitLab group response must be "
                "an object",
                attempts=1,
            )

        group_id = required_identifier(
            payload.get("id"),
            "group.id",
        )
        full_path = required_string(
            payload.get("full_path")
            or payload.get("path"),
            "group.full_path",
        )

        if (
            full_path.casefold()
            != self.group.casefold()
        ):
            raise GitLabRestError(
                "invalid_response",
                "GitLab returned a different group",
                attempts=1,
            )

        return (
            ScmTenant(
                provider=self.provider,
                provider_instance=(
                    self.provider_instance
                ),
                tenant_id=group_id,
                namespace=full_path,
            ),
        )

    def group_projects(
        self,
    ) -> list[dict[str, Any]]:
        try:
            projects = (
                self.graphql.group_projects(
                    self.group,
                    page_size=self.page_size,
                    pipeline_limit=(
                        self.pipeline_limit
                    ),
                )
            )
        except (
            GitLabGraphQLError,
            RuntimeError,
            ValueError,
        ) as error:
            self.graphql_fallback_error = str(error)
            projects = self.paged_list(
                self.group_path("projects"),
                params={
                    "include_subgroups": "true",
                    "with_shared": "false",
                    "simple": "false",
                    "order_by": "path",
                    "sort": "asc",
                },
            )

        for project in projects:
            project_id = str(
                project.get("id") or ""
            )

            if not project_id:
                continue

            languages = project.get(
                "_wintermute_languages"
            )

            if isinstance(languages, dict):
                self._languages_by_project_id[
                    project_id
                ] = dict(languages)

            pipelines = project.get(
                "_wintermute_pipelines"
            )

            if isinstance(pipelines, list):
                self._pipelines_by_project_id[
                    project_id
                ] = tuple(
                    dict(value)
                    for value in pipelines
                    if isinstance(value, dict)
                )

            if project.get(
                "_wintermute_pipelines_complete"
            ):
                self._complete_pipeline_projects.add(
                    project_id
                )

            ci_path = str(
                project.get(
                    "_wintermute_ci_config_path"
                )
                or ""
            ).strip()

            if ci_path:
                self._ci_path_by_project_id[
                    project_id
                ] = ci_path

        return projects

    def ci_config_path(
        self,
        project_id: str,
    ) -> str:
        return self._ci_path_by_project_id.get(
            str(project_id),
            ".gitlab-ci.yml",
        )

    def project_languages(
        self,
        project_id: str,
    ) -> dict[str, Any]:
        project_id = str(project_id)
        cached = self._languages_by_project_id.get(
            project_id
        )

        if cached is not None:
            return dict(cached)

        payload = self.get_json(
            self.project_path(
                project_id,
                "languages",
            )
        )

        if not isinstance(payload, dict):
            raise GitLabRestError(
                "invalid_response",
                "GitLab languages response must "
                "be an object",
                attempts=1,
            )

        self._languages_by_project_id[
            project_id
        ] = dict(payload)
        return dict(payload)

    def recent_pipelines(
        self,
        project_id: str,
        *,
        limit: int = 3,
    ) -> tuple[dict[str, Any], ...]:
        project_id = str(project_id)

        if (
            project_id
            in self._complete_pipeline_projects
        ):
            return self._pipelines_by_project_id.get(
                project_id,
                (),
            )[:limit]

        payload, _ = self._json_response(
            self.project_path(
                project_id,
                "pipelines",
            ),
            params={
                "per_page": limit,
                "page": 1,
                "order_by": "id",
                "sort": "desc",
            },
        )

        if (
            not isinstance(payload, list)
            or not all(
                isinstance(value, dict)
                for value in payload
            )
        ):
            raise GitLabRestError(
                "invalid_response",
                "GitLab pipelines response must "
                "be a list of objects",
                attempts=1,
            )

        values = tuple(
            dict(value)
            for value in payload
        )
        self._pipelines_by_project_id[
            project_id
        ] = values
        self._complete_pipeline_projects.add(
            project_id
        )
        return values

    def protected_branch(
        self,
        project_id: str,
        branch: str,
    ) -> dict[str, Any] | None:
        branch = validate_revision(branch)

        try:
            payload = self.get_json(
                self.project_path(
                    project_id,
                    (
                        "protected_branches/"
                        f"{quote(branch, safe='')}"
                    ),
                )
            )
        except GitLabRestError as error:
            if error.category == "not_found":
                return None

            raise

        if not isinstance(payload, dict):
            raise GitLabRestError(
                "invalid_response",
                "GitLab protected branch response "
                "must be an object",
                attempts=1,
            )

        return payload

    def inventory(
        self,
        tenant: ScmTenant,
    ) -> RepositoryInventory:
        self._validate_tenant(tenant)
        projects = self.group_projects()
        now = self._clock()

        if (
            now.tzinfo is None
            or now.utcoffset() is None
        ):
            raise ValueError(
                "GitLab inventory clock must return "
                "a timezone-aware datetime"
            )

        cutoff = (
            now.astimezone(timezone.utc)
            - timedelta(
                days=self.activity_days
            )
        )

        def map_project(
            project: dict[str, Any],
        ) -> tuple[
            Repository | None,
            str,
        ]:
            try:
                return (
                    self._repository(
                        project,
                        tenant,
                        cutoff,
                    ),
                    "",
                )
            except Exception as error:
                return None, str(error)

        worker_count = min(
            bounded_worker_count(
                self.workers,
                maximum=8,
            ),
            max(1, len(projects)),
        )
        mapped = (
            ordered_parallel_map(
                projects,
                map_project,
                workers=worker_count,
                maximum=8,
            )
            if projects
            else []
        )
        repositories: list[Repository] = []
        exclusions: list[
            RepositoryExclusion
        ] = []
        failures: list[InventoryFailure] = []
        identities: set[str] = set()
        names: set[str] = set()

        for project, (
            repository,
            error,
        ) in zip(
            projects,
            mapped,
            strict=True,
        ):
            project_id = str(
                project.get("id") or ""
            )
            name_with_owner = str(
                project.get(
                    "path_with_namespace"
                )
                or ""
            )

            if error or repository is None:
                failures.append(
                    InventoryFailure(
                        provider=self.provider,
                        provider_instance=(
                            self.provider_instance
                        ),
                        tenant_id=(
                            tenant.tenant_id
                        ),
                        repository_id=project_id,
                        name_with_owner=(
                            name_with_owner
                        ),
                        stage="map-repository",
                        error=(
                            error
                            or "Repository mapping failed"
                        ),
                    )
                )
                continue

            normalized_name = (
                repository.name_with_owner
                .casefold()
            )

            if (
                repository.external_id
                in identities
                or normalized_name in names
            ):
                failures.append(
                    InventoryFailure(
                        provider=self.provider,
                        provider_instance=(
                            self.provider_instance
                        ),
                        tenant_id=(
                            tenant.tenant_id
                        ),
                        repository_id=(
                            repository.repository_id
                        ),
                        name_with_owner=(
                            repository.name_with_owner
                        ),
                        stage="deduplicate-repository",
                        error=(
                            "GitLab returned a duplicate "
                            "repository"
                        ),
                    )
                )
                continue

            identities.add(
                repository.external_id
            )
            names.add(normalized_name)

            if repository.archived:
                exclusions.append(
                    RepositoryExclusion(
                        repository=repository,
                        reason="archived",
                    )
                )
            else:
                repositories.append(repository)

        return RepositoryInventory(
            repositories=tuple(
                sorted(
                    repositories,
                    key=lambda value: (
                        value.name_with_owner
                        .casefold(),
                        value.repository_id,
                    ),
                )
            ),
            exclusions=tuple(
                sorted(
                    exclusions,
                    key=lambda value: (
                        value.repository
                        .name_with_owner
                        .casefold(),
                        value.repository
                        .repository_id,
                    ),
                )
            ),
            failures=tuple(failures),
            discovered_count=len(projects),
        )

    def _repository(
        self,
        project: dict[str, Any],
        tenant: ScmTenant,
        cutoff: datetime,
    ) -> Repository:
        project_id = required_identifier(
            project.get("id"),
            "project.id",
        )
        name_with_owner = required_string(
            project.get(
                "path_with_namespace"
            ),
            "project.path_with_namespace",
        )
        namespace, name = (
            name_with_owner.rsplit("/", 1)
        )
        web_url = required_string(
            project.get("web_url"),
            "project.web_url",
        )
        visibility = required_string(
            project.get("visibility"),
            "project.visibility",
        ).casefold()
        archived = boolean_value(
            project.get("archived"),
            "project.archived",
        )
        default_branch = str(
            project.get("default_branch")
            or ""
        ).strip()
        head_sha = str(
            project.get(
                "_wintermute_head_sha"
            )
            or ""
        ).casefold()

        if (
            default_branch
            and not head_sha
            and not project.get(
                "_wintermute_graphql"
            )
        ):
            try:
                reference = (
                    self.resolve_repository_ref(
                        web_url,
                        default_branch,
                    )
                )
                head_sha = reference.commit
            except GitLabRestError as error:
                if error.category != "not_found":
                    raise

        languages_payload = (
            self.project_languages(
                project_id
            )
        )
        languages = primary_language(
            languages_payload
        )
        forked_from = project.get(
            "forked_from_project"
        )
        pushed_at = str(
            project.get("last_activity_at")
            or ""
        ).strip()

        return Repository(
            provider=self.provider,
            provider_instance=(
                self.provider_instance
            ),
            tenant_id=tenant.tenant_id,
            repository_id=project_id,
            namespace=namespace,
            name=name,
            canonical_url=web_url,
            default_branch=default_branch,
            head_sha=head_sha,
            visibility=visibility,
            archived=archived,
            fork=isinstance(
                forked_from,
                dict,
            ),
            template=False,
            pushed_at=pushed_at,
            activity_status=activity_status(
                pushed_at,
                cutoff,
            ),
            languages=languages,
            language_data_complete=False,
        )

    def _validate_tenant(
        self,
        tenant: ScmTenant,
    ) -> None:
        if tenant.provider != self.provider:
            raise ValueError(
                "SCM tenant provider does not match "
                "the GitLab client"
            )

        if (
            tenant.provider_instance
            != self.provider_instance
        ):
            raise ValueError(
                "SCM tenant instance does not match "
                "the GitLab client"
            )

        if (
            tenant.namespace.casefold()
            != self.group.casefold()
        ):
            raise ValueError(
                "SCM tenant namespace does not match "
                "the configured GitLab group"
            )

    def _validate_path(
        self,
        path: str,
    ) -> None:
        if any(
            pattern.fullmatch(path)
            for pattern in _ALLOWED_PATHS
        ):
            return

        super()._validate_path(path)
