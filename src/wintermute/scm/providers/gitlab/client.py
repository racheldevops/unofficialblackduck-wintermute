from __future__ import annotations

import email.utils
import json
import re
import ssl
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import (
    quote,
    urlencode,
    urlsplit,
    urlunsplit,
)
from urllib.request import Request, urlopen


DEFAULT_REST_BASE_URL = (
    "https://gitlab.com/api/v4"
)
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
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

_COMMIT_RE = re.compile(
    r"^[a-f0-9]{40}|[a-f0-9]{64}$"
)
_ENCODED = r"[A-Za-z0-9._~%+-]+"
_ALLOWED_PATHS = (
    re.compile(
        rf"^/projects/{_ENCODED}$"
    ),
    re.compile(
        rf"^/projects/{_ENCODED}/"
        rf"repository/tags/{_ENCODED}$"
    ),
    re.compile(
        rf"^/projects/{_ENCODED}/"
        rf"repository/commits/{_ENCODED}$"
    ),
    re.compile(
        rf"^/projects/{_ENCODED}/"
        rf"repository/files/{_ENCODED}/raw$"
    ),
    re.compile(
        rf"^/projects/{_ENCODED}/"
        r"repository/tree$"
    ),
)


class GitLabRestError(RuntimeError):
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
class GitLabRestStats:
    requests: int
    retries: int
    rate_remaining: int | None


@dataclass(frozen=True)
class GitLabRepositoryRef:
    repository_url: str
    project_path: str
    revision: str
    commit: str


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
            "GitLab REST base URL must be HTTPS "
            "without credentials, query, or fragment"
        )

    path = parsed.path.rstrip("/")

    if not path.endswith("/api/v4"):
        raise ValueError(
            "GitLab REST base URL must end in /api/v4"
        )

    return urlunsplit(
        (
            "https",
            parsed.netloc.casefold(),
            path,
            "",
            "",
        )
    )


def repository_path_from_url(
    repository_url: str,
    *,
    provider_instance: str,
) -> str:
    selected = str(
        repository_url or ""
    ).strip()
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
            "GitLab repository URL must be HTTPS "
            "without credentials, query, or fragment"
        )

    if (
        parsed.netloc.casefold()
        != provider_instance.casefold()
    ):
        raise ValueError(
            "GitLab repository URL belongs to another "
            "provider instance"
        )

    path = parsed.path.strip("/")

    if "/-/" in path:
        path = path.split("/-/", 1)[0]

    if path.endswith(".git"):
        path = path[:-4]

    parts = [
        part
        for part in path.split("/")
        if part
    ]

    if (
        len(parts) < 2
        or any(
            part in {".", ".."}
            for part in parts
        )
    ):
        raise ValueError(
            "GitLab repository URL has no project path"
        )

    return "/".join(parts)


def validate_revision(value: str) -> str:
    revision = str(value or "").strip()

    if (
        not revision
        or revision.startswith("-")
        or ".." in revision
        or "@{" in revision
        or ":"
        in revision
        or "\\"
        in revision
        or len(revision) > 200
    ):
        raise ValueError(
            f"Invalid Git revision: {value!r}"
        )

    allowed = set(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789._/-"
    )

    if any(
        character not in allowed
        for character in revision
    ):
        raise ValueError(
            f"Invalid Git revision: {value!r}"
        )

    return revision


def validate_repository_file(
    value: str,
) -> str:
    selected = str(value or "").strip()
    path = Path(selected)

    if (
        not selected
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in selected
    ):
        raise ValueError(
            f"Invalid repository file path: "
            f"{value!r}"
        )

    return selected


class GitLabRestClient:
    provider = "gitlab"

    def __init__(
        self,
        token: str = "",
        *,
        base_url: str = DEFAULT_REST_BASE_URL,
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
                "request_interval_seconds cannot be "
                "negative"
            )

        if insecure and ca_bundle:
            raise ValueError(
                "Use either insecure mode or a CA bundle"
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
        self.retry_delay = float(retry_delay)
        self.request_interval_seconds = float(
            request_interval_seconds
        )
        self.deadline = deadline
        self._sleeper = sleeper
        self._lock = threading.RLock()
        self._requests = 0
        self._retries = 0
        self._rate_remaining: int | None = None
        self._next_request_at = 0.0

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

    def stats(self) -> GitLabRestStats:
        with self._lock:
            return GitLabRestStats(
                requests=self._requests,
                retries=self._retries,
                rate_remaining=(
                    self._rate_remaining
                ),
            )

    def resolve_repository_ref(
        self,
        repository_url: str,
        revision: str,
        *,
        tag: bool = False,
    ) -> GitLabRepositoryRef:
        project_path = repository_path_from_url(
            repository_url,
            provider_instance=(
                self.provider_instance
            ),
        )
        revision = validate_revision(revision)
        project = quote(
            project_path,
            safe="",
        )
        encoded_revision = quote(
            revision,
            safe="",
        )
        resource = (
            f"/projects/{project}/repository/tags/"
            f"{encoded_revision}"
            if tag
            else (
                f"/projects/{project}/repository/"
                f"commits/{encoded_revision}"
            )
        )
        payload = self.get_json(resource)
        commit_value = (
            payload.get("commit")
            if tag
            else payload
        )

        if not isinstance(commit_value, dict):
            raise GitLabRestError(
                "invalid_response",
                "GitLab revision response has no commit",
                attempts=1,
            )

        commit = str(
            commit_value.get("id") or ""
        ).strip().casefold()

        if not _COMMIT_RE.fullmatch(commit):
            raise GitLabRestError(
                "invalid_response",
                "GitLab revision response has an "
                "invalid commit ID",
                attempts=1,
            )

        return GitLabRepositoryRef(
            repository_url=repository_url,
            project_path=project_path,
            revision=revision,
            commit=commit,
        )

    def read_repository_file(
        self,
        repository: GitLabRepositoryRef,
        path: str,
    ) -> bytes:
        selected_path = validate_repository_file(
            path
        )
        project = quote(
            repository.project_path,
            safe="",
        )
        encoded_path = quote(
            selected_path,
            safe="",
        )

        return self.get_bytes(
            (
                f"/projects/{project}/repository/"
                f"files/{encoded_path}/raw"
            ),
            params={
                "ref": repository.commit,
            },
        )

    def try_read_repository_file(
        self,
        repository: GitLabRepositoryRef,
        path: str,
    ) -> bytes | None:
        try:
            return self.read_repository_file(
                repository,
                path,
            )
        except GitLabRestError as error:
            if error.category == "not_found":
                return None

            raise

    def repository_tree(
        self,
        repository: GitLabRepositoryRef,
        *,
        path: str = "",
        recursive: bool = False,
        page_size: int = 100,
    ) -> tuple[dict[str, Any], ...]:
        if not 1 <= page_size <= 100:
            raise ValueError(
                "page_size must be between 1 and 100"
            )

        project = quote(
            repository.project_path,
            safe="",
        )
        resource = (
            f"/projects/{project}/repository/tree"
        )
        parameters: dict[str, Any] = {
            "ref": repository.commit,
            "recursive": str(
                recursive
            ).lower(),
        }

        if path:
            parameters["path"] = (
                validate_repository_file(path)
            )

        values: list[dict[str, Any]] = []

        for page in range(1, MAX_PAGES + 1):
            payload, headers = self._json_response(
                resource,
                params={
                    **parameters,
                    "per_page": page_size,
                    "page": page,
                },
            )

            if (
                not isinstance(payload, list)
                or not all(
                    isinstance(item, dict)
                    for item in payload
                )
            ):
                raise GitLabRestError(
                    "invalid_response",
                    "GitLab repository tree must be "
                    "a list of objects",
                    attempts=1,
                )

            values.extend(
                dict(item)
                for item in payload
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
                        "GitLab did not advance pagination",
                        attempts=1,
                    )

                continue

            if len(payload) < page_size:
                return tuple(values)

            if not self._header(
                headers,
                "X-Total-Pages",
            ):
                return tuple(values)

        raise GitLabRestError(
            "pagination_error",
            "GitLab repository tree exceeded the "
            "page limit",
            attempts=1,
        )

    def get_json(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        payload, _ = self._json_response(
            path,
            params=params,
        )
        return payload

    def get_bytes(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> bytes:
        content, _ = self._request(
            path,
            params=params,
        )
        return content

    def _json_response(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> tuple[Any, Any]:
        content, headers = self._request(
            path,
            params=params,
        )

        try:
            payload = json.loads(
                content.decode("utf-8")
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as error:
            raise GitLabRestError(
                "invalid_response",
                f"GET {path} returned invalid JSON",
                attempts=1,
            ) from error

        return payload, headers

    def _request(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None,
    ) -> tuple[bytes, Any]:
        self._validate_path(path)
        url = self._make_url(
            path,
            params,
        )

        for attempt in range(
            self.retries + 1
        ):
            self._pace()
            self._ensure_deadline()
            headers = {
                "Accept": "application/json",
                "User-Agent": (
                    "blackduck-wintermute-scm"
                ),
            }

            if self.token:
                headers["PRIVATE-TOKEN"] = (
                    self.token
                )

            request = Request(
                url,
                headers=headers,
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
                    response_headers = getattr(
                        response,
                        "headers",
                        {},
                    )

                self._update_rate(
                    response_headers
                )

                if len(content) > MAX_RESPONSE_BYTES:
                    raise GitLabRestError(
                        "invalid_response",
                        "GitLab response exceeded the "
                        "maximum supported size",
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
                            response_headers,
                        )
                        continue

                    raise GitLabRestError(
                        "gitlab_rest_error",
                        f"GET {path} returned HTTP "
                        f"{status}",
                        attempts=attempt + 1,
                        status_code=status,
                        retryable=(
                            status
                            in RETRYABLE_STATUSES
                        ),
                    )

                return content, response_headers

            except HTTPError as error:
                body = error.read(4000).decode(
                    "utf-8",
                    errors="replace",
                )
                body = self._redact(body)
                self._update_rate(error.headers)
                retryable = (
                    error.code
                    in RETRYABLE_STATUSES
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
                        "authorization_failed"
                    )
                elif error.code == 404:
                    category = "not_found"
                elif error.code == 429:
                    category = "rate_limited"
                else:
                    category = "gitlab_rest_error"

                raise GitLabRestError(
                    category,
                    f"GET {path} failed: HTTP "
                    f"{error.code} {error.reason}: "
                    f"{body}",
                    attempts=attempt + 1,
                    status_code=error.code,
                    retryable=retryable,
                ) from error

            except GitLabRestError:
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

                raise GitLabRestError(
                    "network_error",
                    f"GET {path} failed: "
                    f"{type(error).__name__}: "
                    f"{self._redact(str(error))}",
                    attempts=attempt + 1,
                    retryable=True,
                ) from error

        raise GitLabRestError(
            "unexpected_error",
            f"GET {path} failed unexpectedly",
            attempts=self.retries + 1,
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
                for pattern in _ALLOWED_PATHS
            )
        ):
            raise GitLabRestError(
                "endpoint_not_allowlisted",
                f"GitLab endpoint is not allowlisted: "
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

        if not query:
            return url

        return f"{url}?{query}"

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
                raise GitLabRestError(
                    "runtime_budget_exceeded",
                    "A GitLab wait would exceed the "
                    "runtime budget",
                    attempts=1,
                )

        self._sleeper(delay)

    def _ensure_deadline(self) -> None:
        if (
            self.deadline is not None
            and time.monotonic()
            >= self.deadline
        ):
            raise GitLabRestError(
                "runtime_budget_exceeded",
                "The runtime budget was exhausted "
                "before a GitLab request",
                attempts=1,
            )

    def _increment_request(self) -> None:
        with self._lock:
            self._requests += 1

    def _update_rate(
        self,
        headers: Any,
    ) -> None:
        value = (
            self._header(
                headers,
                "RateLimit-Remaining",
            )
            or self._header(
                headers,
                "X-RateLimit-Remaining",
            )
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

    def _redact(self, value: str) -> str:
        rendered = str(value)

        if self.token:
            rendered = rendered.replace(
                self.token,
                "[REDACTED]",
            )

        return rendered

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
