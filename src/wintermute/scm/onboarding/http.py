from __future__ import annotations

import json
import re
import ssl
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request

from wintermute.scan.security import secure_urlopen as urlopen


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
_SEGMENT = r"[^/?#]+"

GITHUB_ROUTES = {
    "GET": (
        re.compile(
            rf"^/orgs/{_SEGMENT}/properties/schema$"
        ),
        re.compile(
            rf"^/orgs/{_SEGMENT}/properties/values$"
        ),
        re.compile(
            rf"^/repos/{_SEGMENT}/{_SEGMENT}$"
        ),
        re.compile(
            rf"^/repos/{_SEGMENT}/{_SEGMENT}/"
            r"properties/values$"
        ),
        re.compile(
            rf"^/repos/{_SEGMENT}/{_SEGMENT}/"
            r"contents/.+$"
        ),
        re.compile(
            r"^/repositories/[0-9]+$"
        ),
        re.compile(
            rf"^/orgs/{_SEGMENT}/rulesets$"
        ),
        re.compile(
            rf"^/orgs/{_SEGMENT}/rulesets/[0-9]+$"
        ),
    ),
    "POST": (
        re.compile(
            rf"^/orgs/{_SEGMENT}/repos$"
        ),
        re.compile(
            rf"^/orgs/{_SEGMENT}/rulesets$"
        ),
    ),
    "PUT": (
        re.compile(
            rf"^/orgs/{_SEGMENT}/"
            rf"properties/schema/{_SEGMENT}$"
        ),
        re.compile(
            rf"^/repos/{_SEGMENT}/{_SEGMENT}/"
            r"contents/.+$"
        ),
    ),
    "PATCH": (
        re.compile(
            rf"^/orgs/{_SEGMENT}/properties/values$"
        ),
    ),
}

GITLAB_ROUTES = {
    "GET": (
        re.compile(r"^/user$"),
        re.compile(
            rf"^/groups/{_SEGMENT}$"
        ),
        re.compile(
            rf"^/groups/{_SEGMENT}/"
            r"security_policy_project$"
        ),
        re.compile(
            rf"^/projects/{_SEGMENT}$"
        ),
        re.compile(
            rf"^/projects/{_SEGMENT}/"
            rf"repository/files/{_SEGMENT}/raw$"
        ),
    ),
    "POST": (
        re.compile(r"^/projects$"),
        re.compile(
            rf"^/projects/{_SEGMENT}/"
            rf"repository/files/{_SEGMENT}$"
        ),
    ),
}


class OnboardingHttpError(RuntimeError):
    def __init__(
        self,
        category: str,
        message: str,
        *,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.status_code = status_code


@dataclass(frozen=True)
class HttpResult:
    status_code: int
    payload: Any
    headers: Any


class OnboardingHttpClient:
    def __init__(
        self,
        provider: str,
        base_url: str,
        token: str,
        *,
        timeout: float = 30,
        retries: int = 2,
        retry_delay: float = 1,
        request_interval_seconds: float = 0.5,
        insecure: bool = False,
        ca_bundle: str | None = None,
    ) -> None:
        if provider not in {
            "github",
            "gitlab",
        }:
            raise ValueError(
                "Unsupported SCM provider"
            )

        parsed = urlsplit(
            str(base_url or "").strip()
        )

        if (
            parsed.scheme.casefold() != "https"
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "SCM API base URL is invalid"
            )

        token = str(token or "").strip()

        if not token:
            raise ValueError(
                "SCM API token is required"
            )

        if "\r" in token or "\n" in token:
            raise ValueError(
                "SCM API token is invalid"
            )

        if timeout <= 0:
            raise ValueError(
                "timeout must be positive"
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
                "request_interval_seconds cannot "
                "be negative"
            )

        if insecure and ca_bundle:
            raise ValueError(
                "Use insecure mode or a CA bundle"
            )

        self.provider = provider
        self.base_url = str(
            base_url
        ).rstrip("/")
        self.token = token
        self.timeout = float(timeout)
        self.retries = retries
        self.retry_delay = float(retry_delay)
        self.request_interval_seconds = float(
            request_interval_seconds
        )
        self._lock = threading.RLock()
        self._next_request_at = 0.0
        self._requests = 0
        self._writes = 0

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

    @property
    def requests(self) -> int:
        with self._lock:
            return self._requests

    @property
    def writes(self) -> int:
        with self._lock:
            return self._writes

    def get_json(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        allow_not_found: bool = False,
    ) -> HttpResult:
        return self._request(
            "GET",
            path,
            params=params,
            body=None,
            raw=False,
            allow_not_found=allow_not_found,
            expected_statuses={200},
        )

    def get_bytes(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        allow_not_found: bool = False,
    ) -> HttpResult:
        return self._request(
            "GET",
            path,
            params=params,
            body=None,
            raw=True,
            allow_not_found=allow_not_found,
            expected_statuses={200},
        )

    def mutate_json(
        self,
        method: str,
        path: str,
        body: dict[str, Any],
        *,
        expected_statuses: set[int],
    ) -> HttpResult:
        selected_method = method.upper()

        if selected_method not in {
            "POST",
            "PUT",
            "PATCH",
        }:
            raise ValueError(
                "Mutation method is not supported"
            )

        return self._request(
            selected_method,
            path,
            params=None,
            body=body,
            raw=False,
            allow_not_found=False,
            expected_statuses=expected_statuses,
        )

    def paged_list(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        values: list[dict[str, Any]] = []

        for page in range(1, 1001):
            result = self.get_json(
                path,
                params={
                    **dict(params or {}),
                    "per_page": 100,
                    "page": page,
                },
            )
            payload = result.payload

            if (
                not isinstance(payload, list)
                or not all(
                    isinstance(value, dict)
                    for value in payload
                )
            ):
                raise OnboardingHttpError(
                    "invalid_response",
                    f"GET {path} returned a "
                    "malformed list"
                )

            values.extend(
                dict(value)
                for value in payload
            )

            if self.provider == "gitlab":
                next_page = self._header(
                    result.headers,
                    "X-Next-Page",
                ).strip()

                if next_page:
                    continue

            if len(payload) < 100:
                return values

        raise OnboardingHttpError(
            "pagination_error",
            f"GET {path} exceeded the page limit"
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None,
        body: dict[str, Any] | None,
        raw: bool,
        allow_not_found: bool,
        expected_statuses: set[int],
    ) -> HttpResult:
        self._validate_route(
            method,
            path,
        )
        url = f"{self.base_url}{path}"

        if params:
            query = urlencode(
                [
                    (
                        str(key),
                        str(item),
                    )
                    for key, value in params.items()
                    if value is not None
                    for item in (
                        value
                        if isinstance(
                            value,
                            (list, tuple),
                        )
                        else (value,)
                    )
                ]
            )

            if query:
                url = f"{url}?{query}"

        encoded_body = (
            json.dumps(
                body,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
            if body is not None
            else None
        )
        attempts = (
            self.retries + 1
            if method == "GET"
            else 1
        )

        for attempt in range(attempts):
            self._pace()
            headers = {
                "Accept": "application/json",
                "User-Agent": (
                    "blackduck-wintermute-onboarding"
                ),
            }

            if self.provider == "github":
                headers["Authorization"] = (
                    f"Bearer {self.token}"
                )
                headers["X-GitHub-Api-Version"] = (
                    "2022-11-28"
                )
            else:
                headers["PRIVATE-TOKEN"] = (
                    self.token
                )

            if encoded_body is not None:
                headers["Content-Type"] = (
                    "application/json"
                )

            request = Request(
                url,
                data=encoded_body,
                headers=headers,
                method=method,
            )

            with self._lock:
                self._requests += 1

                if method != "GET":
                    self._writes += 1

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

                if len(content) > MAX_RESPONSE_BYTES:
                    raise OnboardingHttpError(
                        "invalid_response",
                        "SCM response exceeded the "
                        "maximum supported size",
                        status_code=status,
                    )

                if status not in expected_statuses:
                    raise OnboardingHttpError(
                        "http_error",
                        f"{method} {path} returned "
                        f"HTTP {status}",
                        status_code=status,
                    )

                return HttpResult(
                    status_code=status,
                    payload=(
                        content
                        if raw
                        else self._decode_json(
                            content,
                            path,
                        )
                    ),
                    headers=response_headers,
                )

            except HTTPError as error:
                body_text = error.read(4000).decode(
                    "utf-8",
                    errors="replace",
                ).replace(
                    self.token,
                    "[REDACTED]",
                )

                if (
                    error.code == 404
                    and allow_not_found
                ):
                    return HttpResult(
                        status_code=404,
                        payload=(
                            b""
                            if raw
                            else None
                        ),
                        headers=error.headers,
                    )

                if (
                    method == "GET"
                    and error.code
                    in RETRYABLE_STATUSES
                    and attempt + 1 < attempts
                ):
                    time.sleep(
                        self.retry_delay
                        * (attempt + 1)
                    )
                    continue

                category = (
                    "authentication_failed"
                    if error.code == 401
                    else "authorization_failed"
                    if error.code == 403
                    else "not_found"
                    if error.code == 404
                    else "http_error"
                )
                raise OnboardingHttpError(
                    category,
                    f"{method} {path} failed: "
                    f"HTTP {error.code}: "
                    f"{body_text}",
                    status_code=error.code,
                ) from error

            except OnboardingHttpError:
                raise

            except (
                URLError,
                TimeoutError,
                OSError,
            ) as error:
                if (
                    method == "GET"
                    and attempt + 1 < attempts
                ):
                    time.sleep(
                        self.retry_delay
                        * (attempt + 1)
                    )
                    continue

                message = str(error).replace(
                    self.token,
                    "[REDACTED]",
                )
                raise OnboardingHttpError(
                    "network_error",
                    f"{method} {path} failed: "
                    f"{type(error).__name__}: "
                    f"{message}",
                ) from error

        raise OnboardingHttpError(
            "unexpected_error",
            f"{method} {path} failed unexpectedly"
        )

    def _validate_route(
        self,
        method: str,
        path: str,
    ) -> None:
        routes = (
            GITHUB_ROUTES
            if self.provider == "github"
            else GITLAB_ROUTES
        )
        patterns = routes.get(method, ())

        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or "?" in path
            or "#" in path
            or "://" in path
            or not any(
                pattern.fullmatch(path)
                for pattern in patterns
            )
        ):
            raise OnboardingHttpError(
                "endpoint_not_allowlisted",
                "SCM endpoint is not allowlisted: "
                f"{method} {path}"
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
            time.sleep(delay)

    @staticmethod
    def _decode_json(
        content: bytes,
        path: str,
    ) -> Any:
        if not content:
            return {}

        try:
            return json.loads(
                content.decode("utf-8")
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as error:
            raise OnboardingHttpError(
                "invalid_response",
                f"Request for {path} returned "
                "invalid JSON"
            ) from error

    @staticmethod
    def _header(
        headers: Any,
        name: str,
    ) -> str:
        if not hasattr(headers, "get"):
            return ""

        return str(
            headers.get(name)
            or headers.get(
                name.casefold()
            )
            or ""
        )
