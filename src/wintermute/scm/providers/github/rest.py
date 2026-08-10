from __future__ import annotations

import email.utils
import json
import re
import ssl
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen


DEFAULT_REST_BASE_URL = "https://api.github.com"
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_PAGES = 10000

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

_SEGMENT = r"[^/?#]+"
ALLOWED_PATHS = (
    re.compile(
        rf"^/orgs/{_SEGMENT}/properties/schema$"
    ),
    re.compile(
        rf"^/orgs/{_SEGMENT}/properties/values$"
    ),
    re.compile(
        rf"^/orgs/{_SEGMENT}/rulesets$"
    ),
    re.compile(
        rf"^/orgs/{_SEGMENT}/rulesets/[0-9]+$"
    ),
    re.compile(
        rf"^/repos/{_SEGMENT}/{_SEGMENT}/"
        r"actions/workflows$"
    ),
)


class GitHubRestError(RuntimeError):
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
class GitHubRestStats:
    requests: int
    retries: int
    rate_remaining: int | None


def normalize_rest_base_url(
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
            "GitHub REST base URL must be HTTPS "
            "without credentials, query, or fragment"
        )

    return urlunsplit(
        (
            "https",
            parsed.netloc.casefold(),
            parsed.path.rstrip("/"),
            "",
            "",
        )
    )


class GitHubRestClient:
    provider = "github"

    def __init__(
        self,
        token: str,
        *,
        base_url: str = DEFAULT_REST_BASE_URL,
        timeout: float = 30.0,
        retries: int = 3,
        retry_delay: float = 1.0,
        insecure: bool = False,
        ca_bundle: str | None = None,
        deadline: float | None = None,
        sleeper: Any = time.sleep,
    ) -> None:
        token = str(token or "").strip()

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

        if insecure and ca_bundle:
            raise ValueError(
                "Use either insecure mode or a CA bundle, not both"
            )

        self.token = token
        self.base_url = normalize_rest_base_url(
            base_url
        )
        self.provider_instance = (
            urlsplit(self.base_url)
            .netloc
            .casefold()
        )
        self.timeout = float(timeout)
        self.retries = retries
        self.retry_delay = float(
            retry_delay
        )
        self.deadline = deadline
        self._sleeper = sleeper
        self._lock = threading.RLock()
        self._requests = 0
        self._retries = 0
        self._rate_remaining: int | None = None

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

    def stats(self) -> GitHubRestStats:
        with self._lock:
            return GitHubRestStats(
                requests=self._requests,
                retries=self._retries,
                rate_remaining=(
                    self._rate_remaining
                ),
            )

    def organization_path(
        self,
        organization: str,
        suffix: str,
    ) -> str:
        selected = str(
            organization or ""
        ).strip()

        if (
            not selected
            or "/" in selected
            or any(
                character.isspace()
                for character in selected
            )
        ):
            raise ValueError(
                "GitHub organization is invalid"
            )

        return (
            f"/orgs/{quote(selected, safe='')}"
            f"/{suffix.lstrip('/')}"
        )

    def repository_path(
        self,
        namespace: str,
        repository: str,
        suffix: str,
    ) -> str:
        values = {
            "namespace": str(
                namespace or ""
            ).strip(),
            "repository": str(
                repository or ""
            ).strip(),
        }

        for field, value in values.items():
            if (
                not value
                or value in {".", ".."}
                or "/" in value
                or any(
                    character.isspace()
                    for character in value
                )
            ):
                raise ValueError(
                    f"GitHub repository {field} is invalid"
                )

        return (
            f"/repos/"
            f"{quote(values['namespace'], safe='')}/"
            f"{quote(values['repository'], safe='')}/"
            f"{suffix.lstrip('/')}"
        )

    def get_json(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        self._validate_path(path)
        url = self._make_url(
            path,
            params,
        )

        for attempt in range(
            self.retries + 1
        ):
            self._ensure_deadline()
            request = Request(
                url,
                headers={
                    "Authorization": (
                        f"Bearer {self.token}"
                    ),
                    "Accept": (
                        "application/vnd.github+json"
                    ),
                    "X-GitHub-Api-Version": (
                        "2022-11-28"
                    ),
                    "User-Agent": (
                        "blackduck-wintermute-scm"
                    ),
                },
                method="GET",
            )
            self._increment_request()

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
                    headers = getattr(
                        response,
                        "headers",
                        {},
                    )

                self._update_rate(headers)

                if len(content) > MAX_RESPONSE_BYTES:
                    raise GitHubRestError(
                        "invalid_response",
                        "GitHub REST response exceeded "
                        "the maximum supported size",
                        attempts=attempt + 1,
                        status_code=status,
                    )

                if status != 200:
                    if (
                        status in RETRYABLE_STATUSES
                        and attempt < self.retries
                    ):
                        self._retry(
                            attempt,
                            headers,
                        )
                        continue

                    raise GitHubRestError(
                        "github_rest_error",
                        f"GET {path} returned HTTP {status}",
                        attempts=attempt + 1,
                        status_code=status,
                        retryable=(
                            status
                            in RETRYABLE_STATUSES
                        ),
                    )

                try:
                    return json.loads(
                        content.decode("utf-8")
                    )
                except (
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                ) as error:
                    raise GitHubRestError(
                        "invalid_response",
                        f"GET {path} returned invalid JSON",
                        attempts=attempt + 1,
                    ) from error

            except HTTPError as error:
                self._update_rate(
                    error.headers
                )
                body = error.read(4000).decode(
                    "utf-8",
                    errors="replace",
                )
                body = self._redact(body)
                rate_limited = (
                    error.code == 429
                    or (
                        error.code == 403
                        and (
                            self._header(
                                error.headers,
                                "X-RateLimit-Remaining",
                            )
                            == "0"
                            or "rate limit"
                            in body.casefold()
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
                        error.headers,
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
                        "github_rest_error"
                    )

                raise GitHubRestError(
                    category,
                    f"GET {path} failed: HTTP "
                    f"{error.code} {error.reason}: {body}",
                    attempts=attempt + 1,
                    status_code=error.code,
                    retryable=retryable,
                ) from error

            except GitHubRestError:
                raise

            except (
                URLError,
                TimeoutError,
                OSError,
            ) as error:
                if attempt < self.retries:
                    self._retry(
                        attempt,
                        {},
                    )
                    continue

                raise GitHubRestError(
                    "network_error",
                    "GitHub REST network failure "
                    f"during GET {path}: "
                    f"{type(error).__name__}: "
                    f"{self._redact(str(error))}",
                    attempts=attempt + 1,
                    retryable=True,
                ) from error

        raise GitHubRestError(
            "unexpected_error",
            f"GET {path} failed unexpectedly",
            attempts=self.retries + 1,
        )

    def paged_list(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        if (
            type(page_size) is not int
            or not 1 <= page_size <= 100
        ):
            raise ValueError(
                "page_size must be between 1 and 100"
            )

        values: list[dict[str, Any]] = []

        for page in range(
            1,
            MAX_PAGES + 1,
        ):
            page_params = dict(
                params or {}
            )
            page_params.update(
                {
                    "per_page": page_size,
                    "page": page,
                }
            )
            payload = self.get_json(
                path,
                params=page_params,
            )

            if not isinstance(payload, list):
                raise GitHubRestError(
                    "invalid_response",
                    f"GET {path} returned a non-list",
                    attempts=1,
                )

            if not all(
                isinstance(item, dict)
                for item in payload
            ):
                raise GitHubRestError(
                    "invalid_response",
                    f"GET {path} returned a malformed list",
                    attempts=1,
                )

            values.extend(
                dict(item)
                for item in payload
            )

            if len(payload) < page_size:
                return values

        raise GitHubRestError(
            "pagination_error",
            f"GET {path} exceeded the page limit",
            attempts=1,
        )

    def paged_workflows(
        self,
        path: str,
        *,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        if (
            type(page_size) is not int
            or not 1 <= page_size <= 100
        ):
            raise ValueError(
                "page_size must be between 1 and 100"
            )

        workflows: list[
            dict[str, Any]
        ] = []
        expected_total: int | None = None
        workflow_ids: set[str] = set()

        for page in range(
            1,
            MAX_PAGES + 1,
        ):
            payload = self.get_json(
                path,
                params={
                    "per_page": page_size,
                    "page": page,
                },
            )

            if not isinstance(payload, dict):
                raise GitHubRestError(
                    "invalid_response",
                    f"GET {path} returned a non-object",
                    attempts=1,
                )

            total_count = payload.get(
                "total_count"
            )

            if (
                type(total_count) is not int
                or total_count < 0
            ):
                raise GitHubRestError(
                    "invalid_response",
                    f"GET {path} returned an invalid "
                    "workflow total",
                    attempts=1,
                )

            if expected_total is None:
                expected_total = total_count
            elif expected_total != total_count:
                raise GitHubRestError(
                    "pagination_error",
                    f"GET {path} workflow total changed "
                    "during pagination",
                    attempts=1,
                )

            page_values = payload.get(
                "workflows"
            )

            if (
                not isinstance(page_values, list)
                or not all(
                    isinstance(value, dict)
                    for value in page_values
                )
            ):
                raise GitHubRestError(
                    "invalid_response",
                    f"GET {path} returned malformed "
                    "workflows",
                    attempts=1,
                )

            for value in page_values:
                workflow_id = str(
                    value.get("id") or ""
                ).strip()

                if not workflow_id:
                    raise GitHubRestError(
                        "invalid_response",
                        "GitHub workflow has no ID",
                        attempts=1,
                    )

                if workflow_id in workflow_ids:
                    raise GitHubRestError(
                        "pagination_error",
                        "GitHub returned a duplicate "
                        f"workflow ID: {workflow_id}",
                        attempts=1,
                    )

                workflow_ids.add(workflow_id)
                workflows.append(
                    dict(value)
                )

            if len(workflows) >= total_count:
                if len(workflows) != total_count:
                    raise GitHubRestError(
                        "pagination_error",
                        "GitHub workflow count exceeded "
                        "the reported total",
                        attempts=1,
                    )

                return workflows

            if len(page_values) < page_size:
                raise GitHubRestError(
                    "pagination_error",
                    "GitHub workflow pagination ended "
                    "before the reported total",
                    attempts=1,
                )

        raise GitHubRestError(
            "pagination_error",
            f"GET {path} exceeded the page limit",
            attempts=1,
        )

    def _validate_path(
        self,
        path: str,
    ) -> None:
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or "?" in path
            or "#" in path
            or "://" in path
            or not any(
                pattern.fullmatch(path)
                for pattern in ALLOWED_PATHS
            )
        ):
            raise GitHubRestError(
                "endpoint_not_allowlisted",
                f"GitHub REST endpoint is not allowlisted: "
                f"GET {path}",
                attempts=1,
            )

    def _make_url(
        self,
        path: str,
        params: Mapping[str, Any] | None,
    ) -> str:
        url = f"{self.base_url}{path}"

        if not params:
            return url

        query = urlencode(
            {
                str(key): str(value)
                for key, value in params.items()
                if value is not None
            }
        )

        return (
            f"{url}?{query}"
            if query
            else url
        )

    def _retry(
        self,
        attempt: int,
        headers: Any,
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
        retry_after = self._header(
            headers,
            "Retry-After",
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

                    if parsed.tzinfo is None:
                        from datetime import timezone

                        parsed = parsed.replace(
                            tzinfo=timezone.utc
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
                raise GitHubRestError(
                    "runtime_budget_exceeded",
                    "A required GitHub REST wait "
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
            raise GitHubRestError(
                "runtime_budget_exceeded",
                "The runtime budget was exhausted "
                "before a GitHub REST request",
                attempts=1,
            )

    def _increment_request(
        self,
    ) -> None:
        with self._lock:
            self._requests += 1

    def _update_rate(
        self,
        headers: Any,
    ) -> None:
        value = self._header(
            headers,
            "X-RateLimit-Remaining",
        )

        try:
            remaining = int(value)
        except (
            TypeError,
            ValueError,
        ):
            return

        with self._lock:
            self._rate_remaining = remaining

    def _redact(
        self,
        value: str,
    ) -> str:
        return str(value).replace(
            self.token,
            "[REDACTED]",
        )

    @staticmethod
    def _header(
        headers: Any,
        name: str,
    ) -> str:
        if not hasattr(headers, "get"):
            return ""

        value = headers.get(name)

        if value is None:
            value = headers.get(
                name.casefold()
            )

        return str(value or "")
