from __future__ import annotations

import email.utils
import json
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

from wintermute.scm.models import (
    RepositoryInventory,
    ScmTenant,
)
from wintermute.scm.providers.github.graphql import (
    DISCOVERY_QUERY,
    PREFLIGHT_QUERY,
)
from wintermute.scm.providers.github.mapper import (
    GitHubMappingError,
    map_discovery_payload,
)


DEFAULT_GRAPHQL_ENDPOINT = (
    "https://api.github.com/graphql"
)
DEFAULT_PAGE_SIZE = 100
MAX_RESPONSE_BYTES = 16 * 1024 * 1024

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

TRANSIENT_GRAPHQL_TYPES = {
    "INTERNAL",
    "RATE_LIMITED",
    "SERVICE_UNAVAILABLE",
    "TIMEOUT",
}


class GitHubClientError(RuntimeError):
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
class GitHubClientStats:
    requests: int
    retries: int
    graphql_cost: int
    rate_remaining: int | None
    rate_reset_at: str


def normalize_endpoint(
    value: str,
) -> str:
    endpoint = str(value or "").strip()
    parsed = urlsplit(endpoint)

    if (
        parsed.scheme.casefold() != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "GitHub GraphQL endpoint must be an HTTPS URL "
            "without credentials, query, or fragment"
        )

    return urlunsplit(
        (
            "https",
            parsed.netloc.casefold(),
            parsed.path,
            "",
            "",
        )
    )


def provider_instance_from_endpoint(
    endpoint: str,
) -> str:
    return urlsplit(
        normalize_endpoint(endpoint)
    ).netloc.casefold()


def _required_string(
    value: Any,
    field: str,
) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
    ):
        raise GitHubClientError(
            "invalid_response",
            f"GitHub field {field!r} must be a nonempty string",
            attempts=1,
        )

    return value.strip()


def _object(
    value: Any,
    field: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GitHubClientError(
            "invalid_response",
            f"GitHub field {field!r} must be an object",
            attempts=1,
        )

    return value


def _nonnegative_integer(
    value: Any,
    field: str,
) -> int:
    if (
        type(value) is not int
        or value < 0
    ):
        raise GitHubClientError(
            "invalid_response",
            f"GitHub field {field!r} must be a "
            "nonnegative integer",
            attempts=1,
        )

    return value


def _boolean(
    value: Any,
    field: str,
) -> bool:
    if type(value) is not bool:
        raise GitHubClientError(
            "invalid_response",
            f"GitHub field {field!r} must be boolean",
            attempts=1,
        )

    return value


class GitHubClient:
    provider = "github"

    def __init__(
        self,
        organization: str,
        token: str,
        *,
        endpoint: str = DEFAULT_GRAPHQL_ENDPOINT,
        timeout: float = 30.0,
        retries: int = 3,
        retry_delay: float = 1.0,
        page_size: int = DEFAULT_PAGE_SIZE,
        activity_days: int = 180,
        insecure: bool = False,
        ca_bundle: str | None = None,
        deadline: float | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] = (
            lambda: datetime.now(timezone.utc)
        ),
    ) -> None:
        organization = str(
            organization or ""
        ).strip()
        token = str(token or "").strip()

        if (
            not organization
            or "/"
            in organization
            or any(
                character.isspace()
                for character in organization
            )
        ):
            raise ValueError(
                "GitHub organization is invalid"
            )

        if not token:
            raise ValueError(
                "GitHub token must not be empty"
            )

        if "\r" in token or "\n" in token:
            raise ValueError(
                "GitHub token contains invalid characters"
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

        if (
            type(page_size) is not int
            or not 1 <= page_size <= 100
        ):
            raise ValueError(
                "page_size must be between 1 and 100"
            )

        if (
            type(activity_days) is not int
            or activity_days < 1
        ):
            raise ValueError(
                "activity_days must be a positive integer"
            )

        if insecure and ca_bundle:
            raise ValueError(
                "Use either insecure mode or a CA bundle, not both"
            )

        self.organization = organization
        self.token = token
        self.endpoint = normalize_endpoint(
            endpoint
        )
        self.provider_instance = (
            provider_instance_from_endpoint(
                self.endpoint
            )
        )
        self.timeout = float(timeout)
        self.retries = retries
        self.retry_delay = float(
            retry_delay
        )
        self.page_size = page_size
        self.activity_days = activity_days
        self.deadline = deadline
        self._sleeper = sleeper
        self._clock = clock
        self._lock = threading.RLock()
        self._requests = 0
        self._retries = 0
        self._graphql_cost = 0
        self._rate_remaining: int | None = None
        self._rate_reset_at = ""
        self._rate_reset_epoch: float | None = None

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

    def stats(self) -> GitHubClientStats:
        with self._lock:
            return GitHubClientStats(
                requests=self._requests,
                retries=self._retries,
                graphql_cost=self._graphql_cost,
                rate_remaining=(
                    self._rate_remaining
                ),
                rate_reset_at=(
                    self._rate_reset_at
                ),
            )

    def graphql(
        self,
        query: str,
        variables: dict[str, Any],
        *,
        operation: str,
    ) -> dict[str, Any]:
        if not str(query or "").strip():
            raise ValueError(
                "GraphQL query must not be empty"
            )

        if not isinstance(variables, dict):
            raise ValueError(
                "GraphQL variables must be an object"
            )

        operation = str(
            operation or ""
        ).strip()

        if not operation:
            raise ValueError(
                "GraphQL operation must not be empty"
            )

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
            self._wait_for_rate_limit()
            self._ensure_deadline()

            request = Request(
                self.endpoint,
                data=body,
                headers={
                    "Authorization": (
                        f"Bearer {self.token}"
                    ),
                    "Accept": (
                        "application/vnd.github+json"
                    ),
                    "Content-Type": (
                        "application/json"
                    ),
                    "X-GitHub-Api-Version": (
                        "2022-11-28"
                    ),
                    "User-Agent": (
                        "blackduck-wintermute-scm"
                    ),
                },
                method="POST",
            )
            self._increment_request()

            try:
                with urlopen(
                    request,
                    timeout=self.timeout,
                    context=self.ssl_context,
                ) as response:
                    response_body = response.read(
                        MAX_RESPONSE_BYTES + 1
                    )
                    status = int(
                        getattr(
                            response,
                            "status",
                            200,
                        )
                    )
                    headers = getattr(
                        response,
                        "headers",
                        {},
                    )

                self._update_header_rate(
                    headers
                )

                if (
                    len(response_body)
                    > MAX_RESPONSE_BYTES
                ):
                    raise GitHubClientError(
                        "invalid_response",
                        "GitHub response exceeded the "
                        "maximum supported size",
                        attempts=attempt + 1,
                        status_code=status,
                    )

                if status != 200:
                    message = (
                        f"GitHub returned HTTP {status} "
                        f"during {operation}"
                    )

                    if (
                        status in RETRYABLE_STATUSES
                        and attempt < self.retries
                    ):
                        self._retry(
                            attempt,
                            headers=headers,
                        )
                        continue

                    raise GitHubClientError(
                        "github_http_error",
                        message,
                        attempts=attempt + 1,
                        status_code=status,
                        retryable=(
                            status
                            in RETRYABLE_STATUSES
                        ),
                    )

                try:
                    payload = json.loads(
                        response_body.decode(
                            "utf-8"
                        )
                    )
                except (
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                ) as error:
                    raise GitHubClientError(
                        "invalid_response",
                        "GitHub returned invalid JSON "
                        f"during {operation}",
                        attempts=attempt + 1,
                    ) from error

                if not isinstance(
                    payload,
                    dict,
                ):
                    raise GitHubClientError(
                        "invalid_response",
                        "GitHub returned a non-object "
                        f"during {operation}",
                        attempts=attempt + 1,
                    )

                data = payload.get("data")

                if isinstance(data, dict):
                    self._update_graphql_rate(
                        data.get("rateLimit")
                    )

                errors = payload.get("errors", [])

                if errors:
                    (
                        category,
                        message,
                        transient,
                    ) = self._graphql_error(
                        errors,
                        operation,
                    )

                    if (
                        transient
                        and attempt < self.retries
                    ):
                        self._retry(
                            attempt,
                            headers=headers,
                        )
                        continue

                    raise GitHubClientError(
                        category,
                        message,
                        attempts=attempt + 1,
                        retryable=transient,
                    )

                if not isinstance(data, dict):
                    raise GitHubClientError(
                        "invalid_response",
                        "GitHub omitted GraphQL data "
                        f"during {operation}",
                        attempts=attempt + 1,
                    )

                return data

            except HTTPError as error:
                message = (
                    self._http_error_message(
                        error,
                        operation,
                    )
                )
                self._update_header_rate(
                    error.headers
                )
                rate_limited = (
                    error.code == 429
                    or (
                        error.code == 403
                        and (
                            error.headers.get(
                                "X-RateLimit-Remaining"
                            )
                            == "0"
                            or "rate limit"
                            in message.casefold()
                        )
                    )
                )
                retryable = (
                    error.code
                    in RETRYABLE_STATUSES
                    or rate_limited
                )

                if (
                    retryable
                    and attempt < self.retries
                ):
                    self._retry(
                        attempt,
                        headers=error.headers,
                    )
                    continue

                if error.code == 401:
                    category = (
                        "authentication_failed"
                    )
                elif error.code == 403:
                    category = (
                        "rate_limited"
                        if rate_limited
                        else "authorization_failed"
                    )
                elif error.code == 404:
                    category = "not_found"
                else:
                    category = (
                        "github_http_error"
                    )

                raise GitHubClientError(
                    category,
                    message,
                    attempts=attempt + 1,
                    status_code=error.code,
                    retryable=retryable,
                ) from error

            except GitHubClientError:
                raise

            except (
                URLError,
                TimeoutError,
                OSError,
            ) as error:
                if attempt < self.retries:
                    self._retry(attempt)
                    continue

                detail = self._redact(
                    str(error)
                )

                raise GitHubClientError(
                    "network_error",
                    "GitHub network failure during "
                    f"{operation} after "
                    f"{attempt + 1} attempt(s): "
                    f"{type(error).__name__}: "
                    f"{detail}",
                    attempts=attempt + 1,
                    retryable=True,
                ) from error

        raise GitHubClientError(
            "unexpected_error",
            f"GitHub operation {operation} "
            "failed unexpectedly",
            attempts=self.retries + 1,
        )

    def list_tenants(
        self,
    ) -> tuple[ScmTenant, ...]:
        data = self.graphql(
            PREFLIGHT_QUERY,
            {
                "organization": (
                    self.organization
                )
            },
            operation="InventoryPreflight",
        )
        viewer = _object(
            data.get("viewer"),
            "viewer",
        )
        _required_string(
            viewer.get("login"),
            "viewer.login",
        )
        organization = _object(
            data.get("organization"),
            "organization",
        )
        organization_id = _required_string(
            organization.get("id"),
            "organization.id",
        )
        login = _required_string(
            organization.get("login"),
            "organization.login",
        )

        if (
            login.casefold()
            != self.organization.casefold()
        ):
            raise GitHubClientError(
                "invalid_response",
                "GitHub returned a different "
                "organization during preflight",
                attempts=1,
            )

        repositories = _object(
            organization.get(
                "repositories"
            ),
            "organization.repositories",
        )
        _nonnegative_integer(
            repositories.get("totalCount"),
            (
                "organization.repositories."
                "totalCount"
            ),
        )

        return (
            ScmTenant(
                provider=self.provider,
                provider_instance=(
                    self.provider_instance
                ),
                tenant_id=organization_id,
                namespace=login,
            ),
        )

    def inventory(
        self,
        tenant: ScmTenant,
    ) -> RepositoryInventory:
        self._validate_tenant(tenant)
        payload = self._discover_payload(
            tenant
        )
        now = self._clock()

        if (
            now.tzinfo is None
            or now.utcoffset() is None
        ):
            raise ValueError(
                "GitHub inventory clock must "
                "return a timezone-aware datetime"
            )

        cutoff = (
            now.astimezone(timezone.utc)
            - timedelta(
                days=self.activity_days
            )
        )

        return map_discovery_payload(
            payload,
            provider_instance=(
                self.provider_instance
            ),
            tenant_id=tenant.tenant_id,
            namespace=tenant.namespace,
            activity_cutoff=cutoff,
        )

    def _discover_payload(
        self,
        tenant: ScmTenant,
    ) -> dict[str, Any]:
        cursor: str | None = None
        used_cursors: set[str] = set()
        nodes: list[Any] = []
        expected_total: int | None = None

        while True:
            data = self.graphql(
                DISCOVERY_QUERY,
                {
                    "organization": (
                        tenant.namespace
                    ),
                    "cursor": cursor,
                    "pageSize": self.page_size,
                },
                operation=(
                    "OrganizationInventory"
                ),
            )
            organization = _object(
                data.get("organization"),
                "organization",
            )
            organization_id = (
                _required_string(
                    organization.get("id"),
                    "organization.id",
                )
            )
            login = _required_string(
                organization.get("login"),
                "organization.login",
            )

            if (
                organization_id
                != tenant.tenant_id
                or login.casefold()
                != tenant.namespace.casefold()
            ):
                raise GitHubClientError(
                    "invalid_response",
                    "GitHub organization identity "
                    "changed during discovery",
                    attempts=1,
                )

            connection = _object(
                organization.get(
                    "repositories"
                ),
                "organization.repositories",
            )
            total_count = (
                _nonnegative_integer(
                    connection.get(
                        "totalCount"
                    ),
                    (
                        "repositories."
                        "totalCount"
                    ),
                )
            )

            if expected_total is None:
                expected_total = total_count
            elif expected_total != total_count:
                raise GitHubClientError(
                    "pagination_error",
                    "GitHub repository total "
                    "changed during discovery",
                    attempts=1,
                )

            page_nodes = connection.get(
                "nodes"
            )

            if not isinstance(
                page_nodes,
                list,
            ):
                raise GitHubClientError(
                    "invalid_response",
                    "GitHub repositories.nodes "
                    "must be a list",
                    attempts=1,
                )

            page_info = _object(
                connection.get("pageInfo"),
                "repositories.pageInfo",
            )
            has_next = _boolean(
                page_info.get(
                    "hasNextPage"
                ),
                (
                    "repositories.pageInfo."
                    "hasNextPage"
                ),
            )
            next_cursor = page_info.get(
                "endCursor"
            )

            if has_next and not page_nodes:
                raise GitHubClientError(
                    "pagination_error",
                    "GitHub returned an empty "
                    "continued page",
                    attempts=1,
                )

            nodes.extend(page_nodes)

            if not has_next:
                break

            if (
                not isinstance(
                    next_cursor,
                    str,
                )
                or not next_cursor
            ):
                raise GitHubClientError(
                    "pagination_error",
                    "GitHub indicated another "
                    "page without an end cursor",
                    attempts=1,
                )

            if next_cursor in used_cursors:
                raise GitHubClientError(
                    "pagination_error",
                    "GitHub repeated a "
                    "pagination cursor",
                    attempts=1,
                )

            used_cursors.add(
                next_cursor
            )
            cursor = next_cursor

        if expected_total is None:
            raise GitHubClientError(
                "invalid_response",
                "GitHub omitted repository total",
                attempts=1,
            )

        if len(nodes) != expected_total:
            raise GitHubClientError(
                "pagination_error",
                "GitHub repository count does "
                "not match the organization total",
                attempts=1,
            )

        return {
            "data": {
                "organization": {
                    "repositories": {
                        "totalCount": (
                            expected_total
                        ),
                        "pageInfo": {
                            "hasNextPage": False,
                            "endCursor": None,
                        },
                        "nodes": nodes,
                    }
                }
            }
        }

    def _validate_tenant(
        self,
        tenant: ScmTenant,
    ) -> None:
        if tenant.provider != self.provider:
            raise ValueError(
                "SCM tenant provider does not "
                "match the GitHub client"
            )

        if (
            tenant.provider_instance
            != self.provider_instance
        ):
            raise ValueError(
                "SCM tenant provider instance "
                "does not match the GitHub client"
            )

        if (
            tenant.namespace.casefold()
            != self.organization.casefold()
        ):
            raise ValueError(
                "SCM tenant namespace does not "
                "match the configured organization"
            )

    def _graphql_error(
        self,
        errors: Any,
        operation: str,
    ) -> tuple[str, str, bool]:
        if not isinstance(errors, list):
            return (
                "invalid_response",
                "GitHub GraphQL errors must be a list",
                False,
            )

        messages: list[str] = []
        error_types: set[str] = set()

        for error in errors:
            if not isinstance(error, dict):
                continue

            messages.append(
                self._redact(
                    str(
                        error.get("message")
                        or "GraphQL error"
                    )
                )
            )
            error_types.add(
                str(
                    error.get("type")
                    or ""
                ).strip().upper()
            )

        message_text = "; ".join(
            messages
        ) or "GraphQL error"
        lowered = message_text.casefold()
        transient = bool(
            error_types
            & TRANSIENT_GRAPHQL_TYPES
        ) or any(
            marker in lowered
            for marker in (
                "rate limit",
                "something went wrong",
                "temporarily unavailable",
                "timeout",
                "internal server",
            )
        )

        if "FORBIDDEN" in error_types:
            category = (
                "authorization_failed"
            )
        elif "NOT_FOUND" in error_types:
            category = "not_found"
        elif transient:
            category = (
                "graphql_transient_error"
            )
        else:
            category = "graphql_error"

        return (
            category,
            "GitHub GraphQL failure during "
            f"{operation}: {message_text}",
            transient,
        )

    def _http_error_message(
        self,
        error: HTTPError,
        operation: str,
    ) -> str:
        body = error.read(4000).decode(
            "utf-8",
            errors="replace",
        )
        body = self._redact(body)

        return (
            f"GitHub returned HTTP "
            f"{error.code} {error.reason} "
            f"during {operation}: {body}"
        )

    def _update_graphql_rate(
        self,
        rate: Any,
    ) -> None:
        if not isinstance(rate, dict):
            return

        remaining = self._optional_integer(
            rate.get("remaining")
        )
        cost = self._optional_integer(
            rate.get("cost")
        )
        reset_at = str(
            rate.get("resetAt") or ""
        ).strip()
        reset_epoch = self._timestamp_epoch(
            reset_at
        )

        with self._lock:
            if remaining is not None:
                self._rate_remaining = (
                    remaining
                )

            if cost is not None:
                self._graphql_cost += max(
                    0,
                    cost,
                )

            if reset_at:
                self._rate_reset_at = (
                    reset_at
                )

            if reset_epoch is not None:
                self._rate_reset_epoch = (
                    reset_epoch
                )

    def _update_header_rate(
        self,
        headers: Any,
    ) -> None:
        if not hasattr(headers, "get"):
            return

        remaining = self._optional_integer(
            headers.get(
                "X-RateLimit-Remaining"
            )
        )
        reset_epoch = self._optional_float(
            headers.get(
                "X-RateLimit-Reset"
            )
        )

        with self._lock:
            if remaining is not None:
                self._rate_remaining = (
                    remaining
                )

            if reset_epoch is not None:
                self._rate_reset_epoch = (
                    reset_epoch
                )

    def _wait_for_rate_limit(
        self,
    ) -> None:
        self._ensure_deadline()

        with self._lock:
            remaining = (
                self._rate_remaining
            )
            reset_epoch = (
                self._rate_reset_epoch
            )

        if (
            remaining is not None
            and remaining <= 0
            and reset_epoch is not None
        ):
            delay = (
                reset_epoch
                - time.time()
                + 1.0
            )

            if delay > 0:
                self._sleep(delay)

    def _retry(
        self,
        attempt: int,
        *,
        headers: Any = None,
    ) -> None:
        with self._lock:
            self._retries += 1

        self._sleep(
            self._retry_delay(
                attempt,
                headers,
            )
        )

    def _retry_delay(
        self,
        attempt: int,
        headers: Any,
    ) -> float:
        if hasattr(headers, "get"):
            retry_after = headers.get(
                "Retry-After"
            )

            if retry_after:
                try:
                    return max(
                        0.0,
                        float(retry_after),
                    )
                except ValueError:
                    try:
                        parsed = (
                            email.utils
                            .parsedate_to_datetime(
                                retry_after
                            )
                        )

                        if (
                            parsed.tzinfo
                            is None
                        ):
                            parsed = (
                                parsed.replace(
                                    tzinfo=(
                                        timezone.utc
                                    )
                                )
                            )

                        return max(
                            0.0,
                            parsed.timestamp()
                            - time.time(),
                        )
                    except (
                        TypeError,
                        ValueError,
                        OverflowError,
                    ):
                        pass

            reset_epoch = (
                self._optional_float(
                    headers.get(
                        "X-RateLimit-Reset"
                    )
                )
            )

            if reset_epoch is not None:
                delay = (
                    reset_epoch
                    - time.time()
                    + 1.0
                )

                if delay > 0:
                    return delay

        return self.retry_delay * (
            attempt + 1
        )

    def _sleep(
        self,
        seconds: float,
    ) -> None:
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
                raise GitHubClientError(
                    "runtime_budget_exceeded",
                    "A required GitHub wait "
                    "would exceed the runtime budget",
                    attempts=1,
                )

        self._sleeper(delay)

    def _ensure_deadline(
        self,
    ) -> None:
        if (
            self.deadline is not None
            and time.monotonic()
            >= self.deadline
        ):
            raise GitHubClientError(
                "runtime_budget_exceeded",
                "The runtime budget was exhausted "
                "before a GitHub request",
                attempts=1,
            )

    def _increment_request(
        self,
    ) -> None:
        with self._lock:
            self._requests += 1

    def _redact(
        self,
        value: str,
    ) -> str:
        return str(value).replace(
            self.token,
            "[REDACTED]",
        )

    @staticmethod
    def _optional_integer(
        value: Any,
    ) -> int | None:
        try:
            return int(value)
        except (
            TypeError,
            ValueError,
        ):
            return None

    @staticmethod
    def _optional_float(
        value: Any,
    ) -> float | None:
        try:
            return float(value)
        except (
            TypeError,
            ValueError,
        ):
            return None

    @staticmethod
    def _timestamp_epoch(
        value: str,
    ) -> float | None:
        if not value:
            return None

        normalized = (
            value[:-1] + "+00:00"
            if value.endswith("Z")
            else value
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

        return parsed.timestamp()
