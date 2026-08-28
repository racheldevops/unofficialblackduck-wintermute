from __future__ import annotations

import json
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen


MAX_RESPONSE_BYTES = 32 * 1024 * 1024
RETRYABLE_STATUSES = {
    408,
    409,
    425,
    429,
    500,
    502,
    503,
    504,
}


class GitLabGraphQLError(RuntimeError):
    def __init__(
        self,
        category: str,
        message: str,
        *,
        attempts: int,
        status_code: int | None = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.attempts = attempts
        self.status_code = status_code
        self.retryable = retryable


@dataclass(frozen=True)
class GitLabGraphQLStats:
    requests: int
    retries: int
    graphql_cost: int = 0
    rate_remaining: int | None = None


@dataclass(frozen=True)
class GraphQLResult:
    data: dict[str, Any]
    errors: tuple[dict[str, Any], ...]


def normalize_graphql_url(
    value: str,
) -> str:
    selected = str(value or "").strip()
    parsed = urlsplit(selected)

    if (
        parsed.scheme.casefold() != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "GitLab GraphQL URL must be HTTPS "
            "without credentials, query, or fragment"
        )

    path = parsed.path.rstrip("/")
    marker = "/api/graphql"

    if marker in path:
        path = path.split(marker, 1)[0] + marker
    else:
        path = marker

    return urlunsplit(
        (
            "https",
            parsed.netloc.casefold(),
            path,
            "",
            "",
        )
    )


def base_type_name(
    value: Any,
) -> str:
    selected = value

    while isinstance(selected, dict):
        name = str(
            selected.get("name") or ""
        )

        if name:
            return name

        selected = selected.get("ofType")

    return ""


def type_kind(
    value: Any,
) -> str:
    selected = value
    last_kind = ""

    while isinstance(selected, dict):
        kind = str(
            selected.get("kind") or ""
        )

        if kind:
            last_kind = kind

        if selected.get("name"):
            return last_kind

        selected = selected.get("ofType")

    return last_kind


def field_map(
    payload: Any,
) -> dict[str, dict[str, Any]]:
    if not isinstance(payload, dict):
        return {}

    fields = payload.get("fields")

    if not isinstance(fields, list):
        return {}

    return {
        str(field.get("name") or ""): field
        for field in fields
        if (
            isinstance(field, dict)
            and str(field.get("name") or "")
        )
    }


def argument_names(
    field: dict[str, Any],
) -> set[str]:
    arguments = field.get("args")

    if not isinstance(arguments, list):
        return set()

    return {
        str(value.get("name") or "")
        for value in arguments
        if (
            isinstance(value, dict)
            and str(value.get("name") or "")
        )
    }


def numeric_project_id(value: Any) -> str:
    selected = str(value or "").strip()

    if not selected:
        return ""

    if selected.isdigit():
        return selected

    suffix = selected.rsplit("/", 1)[-1]

    return suffix if suffix.isdigit() else selected


def connection_nodes(
    value: Any,
) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [
            dict(item)
            for item in value
            if isinstance(item, dict)
        ]

    if not isinstance(value, dict):
        return []

    nodes = value.get("nodes")

    if not isinstance(nodes, list):
        return []

    return [
        dict(item)
        for item in nodes
        if isinstance(item, dict)
    ]


class GitLabGraphQLClient:
    def __init__(
        self,
        token: str,
        *,
        endpoint: str,
        timeout: float = 30,
        retries: int = 2,
        retry_delay: float = 1,
        request_interval_seconds: float = 0.2,
        insecure: bool = False,
        ca_bundle: str | None = None,
        deadline: float | None = None,
        sleeper: Any = time.sleep,
    ) -> None:
        token = str(token or "").strip()

        if not token:
            raise ValueError(
                "GitLab token must not be empty"
            )

        if "\r" in token or "\n" in token:
            raise ValueError(
                "GitLab token contains invalid characters"
            )

        if timeout <= 0:
            raise ValueError(
                "timeout must be greater than zero"
            )

        if retries < 0:
            raise ValueError(
                "retries cannot be negative"
            )

        if retry_delay < 0:
            raise ValueError(
                "retry_delay cannot be negative"
            )

        if request_interval_seconds < 0:
            raise ValueError(
                "request_interval_seconds cannot be negative"
            )

        if insecure and ca_bundle:
            raise ValueError(
                "Use either insecure mode or a CA bundle"
            )

        self.token = token
        self.endpoint = normalize_graphql_url(
            endpoint
        )
        self.timeout = float(timeout)
        self.retries = retries
        self.retry_delay = float(retry_delay)
        self.request_interval_seconds = float(
            request_interval_seconds
        )
        self.deadline = deadline
        self._sleeper = sleeper
        self._lock = threading.RLock()
        self._requests = 0
        self._retries = 0
        self._next_request_at = 0.0
        self._schema: dict[str, Any] | None = None

        if insecure:
            self.ssl_context = (
                ssl._create_unverified_context()
            )
        elif ca_bundle:
            self.ssl_context = (
                ssl.create_default_context(
                    cafile=ca_bundle
                )
            )
        else:
            self.ssl_context = None

    def stats(self) -> GitLabGraphQLStats:
        with self._lock:
            return GitLabGraphQLStats(
                requests=self._requests,
                retries=self._retries,
                graphql_cost=0,
                rate_remaining=None,
            )

    def execute(
        self,
        query: str,
        variables: dict[str, Any],
        *,
        operation: str,
    ) -> GraphQLResult:
        body = json.dumps(
            {
                "query": query,
                "variables": variables,
                "operationName": operation,
            },
            separators=(",", ":"),
        ).encode("utf-8")

        for attempt in range(
            self.retries + 1
        ):
            self._pace()
            self._ensure_deadline()
            request = Request(
                self.endpoint,
                data=body,
                headers={
                    "Authorization": (
                        f"Bearer {self.token}"
                    ),
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": (
                        "blackduck-wintermute-scm"
                    ),
                },
                method="POST",
            )

            with self._lock:
                self._requests += 1

            try:
                with urlopen(
                    request,
                    timeout=self.timeout,
                    context=self.ssl_context,
                ) as response:
                    content = response.read(
                        MAX_RESPONSE_BYTES + 1
                    )
                    status = int(
                        getattr(
                            response,
                            "status",
                            200,
                        )
                    )

                if len(content) > MAX_RESPONSE_BYTES:
                    raise GitLabGraphQLError(
                        "invalid_response",
                        "GitLab GraphQL response exceeded "
                        "the maximum supported size",
                        attempts=attempt + 1,
                        status_code=status,
                    )

                try:
                    payload = json.loads(
                        content.decode("utf-8")
                    )
                except (
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                ) as error:
                    raise GitLabGraphQLError(
                        "invalid_response",
                        "GitLab GraphQL returned "
                        "invalid JSON",
                        attempts=attempt + 1,
                    ) from error

                if not isinstance(payload, dict):
                    raise GitLabGraphQLError(
                        "invalid_response",
                        "GitLab GraphQL response must "
                        "be an object",
                        attempts=attempt + 1,
                    )

                data = payload.get("data")
                raw_errors = payload.get("errors") or []

                if data is None and raw_errors:
                    message = "; ".join(
                        str(error.get("message") or "")
                        for error in raw_errors
                        if isinstance(error, dict)
                    )
                    raise GitLabGraphQLError(
                        "graphql_error",
                        "GitLab GraphQL failed during "
                        f"{operation}: {message}",
                        attempts=attempt + 1,
                    )

                if not isinstance(data, dict):
                    raise GitLabGraphQLError(
                        "invalid_response",
                        "GitLab GraphQL omitted data",
                        attempts=attempt + 1,
                    )

                errors = tuple(
                    dict(error)
                    for error in raw_errors
                    if isinstance(error, dict)
                )

                return GraphQLResult(
                    data=data,
                    errors=errors,
                )

            except HTTPError as error:
                body_text = error.read(4000).decode(
                    "utf-8",
                    errors="replace",
                ).replace(
                    self.token,
                    "[REDACTED]",
                )
                retryable = (
                    error.code
                    in RETRYABLE_STATUSES
                )

                if (
                    retryable
                    and attempt < self.retries
                ):
                    self._retry(attempt)
                    continue

                if error.code == 401:
                    category = (
                        "authentication_failed"
                    )
                elif error.code == 403:
                    category = (
                        "authorization_failed"
                    )
                elif error.code == 404:
                    category = "not_found"
                else:
                    category = "graphql_http_error"

                raise GitLabGraphQLError(
                    category,
                    f"GitLab GraphQL returned HTTP "
                    f"{error.code}: {body_text}",
                    attempts=attempt + 1,
                    status_code=error.code,
                    retryable=retryable,
                ) from error

            except GitLabGraphQLError:
                raise

            except (
                URLError,
                TimeoutError,
                OSError,
            ) as error:
                if attempt < self.retries:
                    self._retry(attempt)
                    continue

                message = str(error).replace(
                    self.token,
                    "[REDACTED]",
                )
                raise GitLabGraphQLError(
                    "network_error",
                    "GitLab GraphQL network failure: "
                    f"{type(error).__name__}: {message}",
                    attempts=attempt + 1,
                    retryable=True,
                ) from error

        raise GitLabGraphQLError(
            "unexpected_error",
            "GitLab GraphQL failed unexpectedly",
            attempts=self.retries + 1,
        )

    def schema(self) -> dict[str, Any]:
        if self._schema is not None:
            return self._schema

        query = """
        query WintermuteGitLabSchema {
          project: __type(name: "Project") {
            fields {
              name
              args {
                name
              }
              type {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                    }
                  }
                }
              }
            }
          }
          group: __type(name: "Group") {
            fields {
              name
              args {
                name
              }
              type {
                kind
                name
                ofType {
                  kind
                  name
                }
              }
            }
          }
          repository: __type(name: "Repository") {
            fields {
              name
            }
          }
          pipeline: __type(name: "Pipeline") {
            fields {
              name
            }
          }
          repositoryLanguage: __type(
            name: "RepositoryLanguage"
          ) {
            fields {
              name
            }
          }
        }
        """
        result = self.execute(
            query,
            {},
            operation="WintermuteGitLabSchema",
        )
        self._schema = result.data
        return result.data

    def group_projects(
        self,
        group: str,
        *,
        page_size: int,
        pipeline_limit: int,
    ) -> list[dict[str, Any]]:
        schema = self.schema()
        project_fields = field_map(
            schema.get("project")
        )
        group_fields = field_map(
            schema.get("group")
        )
        repository_fields = field_map(
            schema.get("repository")
        )
        pipeline_fields = field_map(
            schema.get("pipeline")
        )
        language_fields = field_map(
            schema.get("repositoryLanguage")
        )
        projects_field = group_fields.get(
            "projects"
        )

        if (
            projects_field is None
            or "includeSubgroups"
            not in argument_names(
                projects_field
            )
        ):
            raise GitLabGraphQLError(
                "unsupported_schema",
                "GitLab GraphQL does not support "
                "nested group project discovery",
                attempts=1,
            )

        required = {
            "id",
            "fullPath",
            "name",
            "webUrl",
            "visibility",
            "archived",
        }

        if not required.issubset(
            project_fields
        ):
            raise GitLabGraphQLError(
                "unsupported_schema",
                "GitLab GraphQL project fields are "
                "not sufficient for inventory",
                attempts=1,
            )

        selections = [
            "id",
            "fullPath",
            "name",
            "webUrl",
            "visibility",
            "archived",
        ]

        if "lastActivityAt" in project_fields:
            selections.append("lastActivityAt")

        if (
            "repository" in project_fields
            and "rootRef" in repository_fields
        ):
            selections.append(
                "repository { rootRef }"
            )

        if "forkedFromProject" in project_fields:
            selections.append(
                "forkedFromProject { id }"
            )

        ci_field = next(
            (
                name
                for name in (
                    "ciConfigPath",
                    "ciConfigPathOrDefault",
                )
                if name in project_fields
            ),
            "",
        )

        if ci_field:
            selections.append(ci_field)

        language_field = project_fields.get(
            "languages"
        )

        if (
            language_field is not None
            and {"name", "share"}.issubset(
                language_fields
            )
        ):
            language_type = base_type_name(
                language_field.get("type")
            )

            if language_type.endswith(
                "Connection"
            ):
                selections.append(
                    "languages(first: 100) { "
                    "nodes { name share } }"
                )
            else:
                selections.append(
                    "languages { name share }"
                )

        pipeline_field = project_fields.get(
            "pipelines"
        )
        supported_pipeline_fields = [
            name
            for name in (
                "id",
                "status",
                "sha",
                "ref",
                "createdAt",
                "updatedAt",
                "webPath",
            )
            if name in pipeline_fields
        ]

        if (
            pipeline_limit > 0
            and pipeline_field is not None
            and {"id", "status"}.issubset(
                supported_pipeline_fields
            )
        ):
            selections.append(
                "pipelines(first: "
                f"{pipeline_limit}) {{ nodes {{ "
                + " ".join(
                    supported_pipeline_fields
                )
                + " } } }"
            )

        query = """
        query WintermuteGitLabProjects(
          $group: ID!
          $first: Int!
          $after: String
        ) {
          group(fullPath: $group) {
            id
            fullPath
            projects(
              includeSubgroups: true
              first: $first
              after: $after
            ) {
              pageInfo {
                hasNextPage
                endCursor
              }
              nodes {
                PROJECT_SELECTIONS
              }
            }
          }
        }
        """.replace(
            "PROJECT_SELECTIONS",
            "\n".join(selections),
        )
        cursor: str | None = None
        used_cursors: set[str] = set()
        projects: list[dict[str, Any]] = []

        while True:
            result = self.execute(
                query,
                {
                    "group": group,
                    "first": page_size,
                    "after": cursor,
                },
                operation=(
                    "WintermuteGitLabProjects"
                ),
            )
            group_payload = result.data.get(
                "group"
            )

            if not isinstance(
                group_payload,
                dict,
            ):
                raise GitLabGraphQLError(
                    "invalid_response",
                    "GitLab GraphQL group is unavailable",
                    attempts=1,
                )

            connection = group_payload.get(
                "projects"
            )

            if not isinstance(connection, dict):
                raise GitLabGraphQLError(
                    "invalid_response",
                    "GitLab GraphQL projects are "
                    "unavailable",
                    attempts=1,
                )

            nodes = connection_nodes(connection)

            for node in nodes:
                project_id = numeric_project_id(
                    node.get("id")
                )
                full_path = str(
                    node.get("fullPath") or ""
                )
                repository = node.get(
                    "repository"
                )
                default_branch = (
                    str(
                        repository.get("rootRef")
                        or ""
                    )
                    if isinstance(
                        repository,
                        dict,
                    )
                    else ""
                )
                languages: dict[str, float] = {}

                for language in connection_nodes(
                    node.get("languages")
                ):
                    name = str(
                        language.get("name") or ""
                    )

                    try:
                        share = float(
                            language.get("share")
                        )
                    except (
                        TypeError,
                        ValueError,
                    ):
                        continue

                    if name and share > 0:
                        languages[name] = share

                pipelines = connection_nodes(
                    node.get("pipelines")
                )
                forked = node.get(
                    "forkedFromProject"
                )
                projects.append(
                    {
                        "id": project_id,
                        "path_with_namespace": (
                            full_path
                        ),
                        "name": str(
                            node.get("name") or ""
                        ),
                        "web_url": str(
                            node.get("webUrl") or ""
                        ),
                        "visibility": str(
                            node.get("visibility")
                            or ""
                        ).casefold(),
                        "archived": bool(
                            node.get("archived")
                        ),
                        "default_branch": (
                            default_branch
                        ),
                        "last_activity_at": str(
                            node.get(
                                "lastActivityAt"
                            )
                            or ""
                        ),
                        "forked_from_project": (
                            {"id": forked.get("id")}
                            if isinstance(
                                forked,
                                dict,
                            )
                            else None
                        ),
                        "_wintermute_graphql": True,
                        "_wintermute_languages": (
                            languages
                        ),
                        "_wintermute_pipelines": (
                            pipelines
                        ),
                        "_wintermute_pipelines_complete": (
                            "pipelines" in node
                            and node.get(
                                "pipelines"
                            )
                            is not None
                        ),
                        "_wintermute_ci_config_path": (
                            str(
                                node.get(ci_field)
                                or ""
                            )
                            if ci_field
                            else ""
                        ),
                    }
                )

            page_info = connection.get(
                "pageInfo"
            )

            if not isinstance(page_info, dict):
                raise GitLabGraphQLError(
                    "invalid_response",
                    "GitLab GraphQL pageInfo is missing",
                    attempts=1,
                )

            has_next = bool(
                page_info.get("hasNextPage")
            )
            next_cursor = page_info.get(
                "endCursor"
            )

            if not has_next:
                break

            if (
                not isinstance(
                    next_cursor,
                    str,
                )
                or not next_cursor
                or next_cursor in used_cursors
            ):
                raise GitLabGraphQLError(
                    "pagination_error",
                    "GitLab GraphQL pagination "
                    "did not advance",
                    attempts=1,
                )

            used_cursors.add(next_cursor)
            cursor = next_cursor

        unique: dict[str, dict[str, Any]] = {}

        for project in projects:
            project_id = str(
                project.get("id") or ""
            )

            if not project_id:
                raise GitLabGraphQLError(
                    "invalid_response",
                    "GitLab GraphQL project has no ID",
                    attempts=1,
                )

            if project_id in unique:
                raise GitLabGraphQLError(
                    "pagination_error",
                    "GitLab GraphQL returned a "
                    "duplicate project ID",
                    attempts=1,
                )

            unique[project_id] = project

        return sorted(
            unique.values(),
            key=lambda value: (
                str(
                    value.get(
                        "path_with_namespace"
                    )
                    or ""
                ).casefold(),
                str(value.get("id") or ""),
            ),
        )

    def _pace(self) -> None:
        with self._lock:
            now = time.monotonic()
            scheduled = max(
                now,
                self._next_request_at,
            )
            delay = max(
                0.0,
                scheduled - now,
            )
            self._next_request_at = (
                scheduled
                + self.request_interval_seconds
            )

        if delay:
            self._sleep(delay)

    def _retry(self, attempt: int) -> None:
        with self._lock:
            self._retries += 1

        self._sleep(
            self.retry_delay * (attempt + 1)
        )

    def _sleep(self, seconds: float) -> None:
        delay = max(
            0.0,
            float(seconds),
        )

        if self.deadline is not None:
            remaining = (
                self.deadline
                - time.monotonic()
            )

            if (
                remaining <= 0
                or delay >= remaining
            ):
                raise GitLabGraphQLError(
                    "runtime_budget_exceeded",
                    "A GitLab GraphQL wait would "
                    "exceed the runtime budget",
                    attempts=1,
                )

        self._sleeper(delay)

    def _ensure_deadline(self) -> None:
        if (
            self.deadline is not None
            and time.monotonic()
            >= self.deadline
        ):
            raise GitLabGraphQLError(
                "runtime_budget_exceeded",
                "The runtime budget was exhausted "
                "before a GitLab GraphQL request",
                attempts=1,
            )
