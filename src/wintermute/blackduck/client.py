from __future__ import annotations

import copy
import json
import ssl
import sys
import threading
import time
from contextlib import AbstractContextManager
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import (
    parse_qsl,
    urlencode,
    urlparse,
    urlunparse,
)
from urllib.request import Request, urlopen

from wintermute.blackduck.cache import ApiResponseCache
from wintermute.blackduck.request_control import (
    BlackDuckRequestController,
    RequestPermit,
    blackduck_request_context,
)


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


class _BearerTokenState:
    def __init__(self, token: str | None = None) -> None:
        self.token = token
        self.lock = threading.RLock()


class BlackDuckClient:
    cache_raw_gets = True
    cache_paged_results = True

    def __init__(
        self,
        base_url: str,
        api_token: str,
        insecure: bool = False,
        ca_bundle: str | None = None,
        timeout: int = 30,
        retries: int = 1,
        retry_delay: float = 2.0,
        page_limit: int = 100,
        debug: bool = False,
        api_cache: ApiResponseCache | None = None,
        bearer_token: str | None = None,
        refresh_on_unauthorized: bool = True,
        request_control: (
            BlackDuckRequestController | None
        ) = None,
        request_interval_seconds: float | None = None,
        circuit_breaker_threshold: int | None = None,
        circuit_breaker_window_seconds: (
            float | None
        ) = None,
    ) -> None:
        if insecure and ca_bundle:
            raise ValueError(
                "Use either insecure mode or a CA bundle, not both."
            )

        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.timeout = timeout
        self.retries = retries
        self.retry_delay = retry_delay
        self.page_limit = page_limit
        self.debug = debug
        self.api_cache = api_cache
        self.refresh_on_unauthorized = (
            refresh_on_unauthorized
        )
        self._token_state = _BearerTokenState(
            bearer_token
        )
        self._cache_lock = threading.RLock()
        self.raw_get_cache: dict[
            str,
            dict[str, Any],
        ] = {}
        self.paged_result_cache: dict[
            str,
            list[dict[str, Any]],
        ] = {}
        self.vulnerability_summary_cache: dict[
            tuple[str, str, float],
            list[dict[str, Any]],
        ] = {}
        self.request_control = (
            request_control
            or BlackDuckRequestController.from_environment(
                request_interval_seconds=(
                    request_interval_seconds
                ),
                circuit_breaker_threshold=(
                    circuit_breaker_threshold
                ),
                circuit_breaker_window_seconds=(
                    circuit_breaker_window_seconds
                ),
            )
        )

        if insecure:
            self.ssl_context = ssl._create_unverified_context()
        elif ca_bundle:
            self.ssl_context = (
                ssl.create_default_context(
                    cafile=ca_bundle
                )
            )
        else:
            self.ssl_context = None

    @property
    def bearer_token(self) -> str | None:
        with self._token_state.lock:
            return self._token_state.token

    @bearer_token.setter
    def bearer_token(self, value: str | None) -> None:
        with self._token_state.lock:
            self._token_state.token = value

    def request_context(
        self,
        **values: Any,
    ) -> AbstractContextManager[None]:
        return blackduck_request_context(
            **values
        )

    def clone_for_worker(
        self,
    ) -> BlackDuckClient:
        worker = self.__class__(
            base_url=self.base_url,
            api_token=self.api_token,
            timeout=self.timeout,
            retries=self.retries,
            retry_delay=self.retry_delay,
            page_limit=self.page_limit,
            debug=self.debug,
            api_cache=self.api_cache,
            bearer_token=self.bearer_token,
            refresh_on_unauthorized=(
                self.refresh_on_unauthorized
            ),
            request_control=self.request_control,
        )
        worker.ssl_context = self.ssl_context
        worker._token_state = self._token_state
        worker.cache_raw_gets = self.cache_raw_gets
        worker.cache_paged_results = (
            self.cache_paged_results
        )
        return worker

    def clone_for_uncached_reads(
        self,
    ) -> BlackDuckClient:
        worker = self.clone_for_worker()
        worker.api_cache = None
        worker.cache_raw_gets = False
        worker.cache_paged_results = False
        worker.raw_get_cache.clear()
        worker.paged_result_cache.clear()
        return worker

    def authenticate(self) -> None:
        with self._token_state.lock:
            url = (
                f"{self.base_url}/api/tokens/authenticate"
            )
            headers = {
                "Authorization": f"token {self.api_token}",
                "Accept": "application/json",
            }
            attempts = self.retries + 1

            for attempt in range(attempts):
                request = Request(
                    url,
                    data=b"",
                    headers=headers,
                    method="POST",
                )
                permit = (
                    self.request_control.before_request(
                        "POST",
                        url,
                    )
                )
                started = time.monotonic()

                try:
                    with urlopen(
                        request,
                        timeout=self.timeout,
                        context=self.ssl_context,
                    ) as response:
                        text = response.read().decode("utf-8")

                    duration = (
                        time.monotonic() - started
                    )
                    self.request_control.record_success()
                    self._log_network_result(
                        "POST",
                        permit,
                        attempt,
                        attempts,
                        duration,
                        "success",
                        getattr(
                            response,
                            "status",
                            200,
                        ),
                    )
                    payload = json.loads(text)
                    token = str(
                        payload.get("bearerToken") or ""
                    )

                    if not token:
                        raise RuntimeError(
                            "Authentication response has no "
                            "bearerToken"
                        )

                    self._token_state.token = token
                    return

                except HTTPError as error:
                    duration = (
                        time.monotonic() - started
                    )
                    message = (
                        self._http_error_message(
                            error
                        )
                    )
                    count, opened = (
                        self._record_http_failure(
                            "POST",
                            url,
                            permit,
                            attempt,
                            attempts,
                            duration,
                            error.code,
                        )
                    )

                    if opened:
                        raise (
                            self.request_control
                            .circuit_error()
                        ) from error

                    if (
                        error.code
                        not in RETRYABLE_STATUSES
                        or attempt >= self.retries
                    ):
                        raise RuntimeError(
                            "Authentication failed: "
                            f"{message}"
                        ) from error

                    self._sleep_for_retry(
                        error,
                        attempt,
                        circuit_failure_count=count,
                    )

                except (
                    URLError,
                    TimeoutError,
                    OSError,
                ) as error:
                    duration = (
                        time.monotonic() - started
                    )
                    self._log_network_result(
                        "POST",
                        permit,
                        attempt,
                        attempts,
                        duration,
                        type(error).__name__,
                        None,
                    )

                    if attempt >= self.retries:
                        raise RuntimeError(
                            "Authentication failed after "
                            f"{attempts} attempt(s): "
                            f"{error}"
                        ) from error

                    self._sleep_for_retry(
                        error,
                        attempt,
                    )

                except json.JSONDecodeError as error:
                    duration = (
                        time.monotonic() - started
                    )
                    self._log_network_result(
                        "POST",
                        permit,
                        attempt,
                        attempts,
                        duration,
                        "invalid-json",
                        None,
                    )
                    raise RuntimeError(
                        "Authentication returned "
                        f"invalid JSON: {error}"
                    ) from error

            raise RuntimeError(
                "Authentication failed unexpectedly"
            )

    def get(
        self,
        url_or_path: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.request(
            "GET",
            url_or_path,
            params=params,
        )

    def request(
        self,
        method: str,
        url_or_path: str,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        method = method.upper()
        url = self._make_url(
            url_or_path,
            params,
        )
        raw_cache_key = (
            url
            if (
                self.cache_raw_gets
                and method == "GET"
                and body is None
            )
            else ""
        )

        if raw_cache_key:
            with self._cache_lock:
                cached = self.raw_get_cache.get(
                    raw_cache_key
                )

                if cached is not None:
                    return copy.deepcopy(cached)

        data = None

        if body is not None:
            data = json.dumps(
                body
            ).encode("utf-8")

        attempt = 0
        token_refreshed = False
        attempts = self.retries + 1

        while attempt <= self.retries:
            headers = {
                "Accept": "application/json",
            }
            token = self.bearer_token

            if token:
                headers["Authorization"] = (
                    f"Bearer {token}"
                )

            if data is not None:
                headers["Content-Type"] = "application/json"

            request = Request(
                url,
                data=data,
                headers=headers,
                method=method,
            )
            permit = (
                self.request_control.before_request(
                    method,
                    url,
                )
            )
            started = time.monotonic()

            try:
                with urlopen(
                    request,
                    timeout=self.timeout,
                    context=self.ssl_context,
                ) as response:
                    text = response.read().decode("utf-8")

                duration = (
                    time.monotonic() - started
                )
                self.request_control.record_success()
                self._log_network_result(
                    method,
                    permit,
                    attempt,
                    attempts,
                    duration,
                    "success",
                    getattr(
                        response,
                        "status",
                        200,
                    ),
                )
                payload: dict[str, Any] = (
                    json.loads(text)
                    if text
                    else {}
                )

                if raw_cache_key:
                    with self._cache_lock:
                        self.raw_get_cache[
                            raw_cache_key
                        ] = copy.deepcopy(payload)

                return payload

            except HTTPError as error:
                duration = (
                    time.monotonic() - started
                )
                message = (
                    self._http_error_message(
                        error
                    )
                )
                count, opened = (
                    self._record_http_failure(
                        method,
                        url,
                        permit,
                        attempt,
                        attempts,
                        duration,
                        error.code,
                    )
                )

                if opened:
                    raise (
                        self.request_control
                        .circuit_error()
                    ) from error

                if (
                    error.code == 401
                    and self.refresh_on_unauthorized
                    and not token_refreshed
                ):
                    token_refreshed = True
                    self.authenticate()
                    continue

                if (
                    error.code not in RETRYABLE_STATUSES
                    or attempt >= self.retries
                ):
                    raise RuntimeError(
                        f"{method} {url} failed: {message}"
                    ) from error

                self._sleep_for_retry(error, attempt)
                attempt += 1

            except (
                URLError,
                TimeoutError,
                OSError,
            ) as error:
                duration = (
                    time.monotonic() - started
                )
                self._log_network_result(
                    method,
                    permit,
                    attempt,
                    attempts,
                    duration,
                    type(error).__name__,
                    None,
                )

                if attempt >= self.retries:
                    raise RuntimeError(
                        f"{method} {url} failed after "
                        f"{attempts} attempt(s): "
                        f"{error}"
                    ) from error

                self._sleep_for_retry(error, attempt)
                attempt += 1

            except json.JSONDecodeError as error:
                duration = (
                    time.monotonic() - started
                )
                self._log_network_result(
                    method,
                    permit,
                    attempt,
                    attempts,
                    duration,
                    "invalid-json",
                    None,
                )
                raise RuntimeError(
                    f"{method} {url} returned invalid JSON: "
                    f"{error}"
                ) from error

        raise RuntimeError(
            f"{method} {url} failed unexpectedly"
        )

    def paged_get(
        self,
        url_or_path: str,
        params: dict[str, Any] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        page_limit = (
            limit
            if limit is not None
            else self.page_limit
        )
        source_url = self._make_url(
            url_or_path,
            params,
        )

        if self.cache_paged_results:
            with self._cache_lock:
                cached = (
                    self.paged_result_cache.get(
                        source_url
                    )
                )

                if cached is not None:
                    return copy.deepcopy(cached)

        def load_pages() -> tuple[
            list[dict[str, Any]],
            int | None,
        ]:
            return self._fetch_paged_items(
                url_or_path,
                params,
                page_limit,
            )

        if self.api_cache is not None:
            items = (
                self.api_cache.get_or_load_items(
                    source_url,
                    load_pages,
                )
            )
        else:
            items, _ = load_pages()

        if self.cache_paged_results:
            with self._cache_lock:
                self.paged_result_cache[source_url] = (
                    copy.deepcopy(items)
                )

        return copy.deepcopy(items)

    def _fetch_paged_items(
        self,
        url_or_path: str,
        params: dict[str, Any] | None,
        page_limit: int,
    ) -> tuple[list[dict[str, Any]], int | None]:
        items: list[dict[str, Any]] = []
        offset = 0
        total_count: int | None = None

        while True:
            page_params = dict(params or {})
            page_params["offset"] = offset
            page_params["limit"] = page_limit

            payload = self.get(
                url_or_path,
                page_params,
            )

            if "items" not in payload:
                return (
                    [payload] if payload else [],
                    1 if payload else 0,
                )

            page_items = payload.get("items") or []
            items.extend(page_items)

            raw_total = payload.get("totalCount")
            total_count = (
                int(raw_total)
                if raw_total is not None
                else None
            )

            if not page_items:
                break

            offset += len(page_items)

            if (
                total_count is not None
                and offset >= total_count
            ):
                break

            if len(page_items) < page_limit:
                break

        return items, total_count

    def collection_count_and_items(
        self,
        url_or_path: str,
        params: dict[str, Any] | None = None,
        limit: int = 1,
    ) -> tuple[int, list[dict[str, Any]]]:
        page_params = dict(params or {})
        page_params["offset"] = 0
        page_params["limit"] = limit
        payload = self.get(
            url_or_path,
            page_params,
        )

        if "items" in payload:
            items = list(payload.get("items") or [])
            total_count = payload.get("totalCount")

            if total_count is not None:
                return int(total_count), items

            return len(items), items

        return (
            (1, [payload])
            if payload
            else (0, [])
        )

    def count_items(
        self,
        url_or_path: str,
        params: dict[str, Any] | None = None,
    ) -> int:
        count, _ = (
            self.collection_count_and_items(
                url_or_path,
                params=params,
                limit=1,
            )
        )
        return count

    def _make_url(
        self,
        url_or_path: str,
        params: dict[str, Any] | None = None,
    ) -> str:
        if url_or_path.startswith(
            ("http://", "https://")
        ):
            url = url_or_path
        else:
            url = (
                f"{self.base_url}/"
                f"{url_or_path.lstrip('/')}"
            )

        if not params:
            return url

        parsed = urlparse(url)
        query = dict(
            parse_qsl(
                parsed.query,
                keep_blank_values=True,
            )
        )

        for key, value in params.items():
            if value is not None:
                query[key] = str(value)

        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                urlencode(query),
                parsed.fragment,
            )
        )

    def _record_http_failure(
        self,
        method: str,
        url: str,
        permit: RequestPermit,
        attempt: int,
        attempts: int,
        duration: float,
        status: int,
    ) -> tuple[int, bool]:
        count, opened = (
            self.request_control
            .record_server_failure(
                status,
                url,
                context=permit.context,
            )
        )
        self._log_network_result(
            method,
            permit,
            attempt,
            attempts,
            duration,
            "http-error",
            status,
            circuit_failure_count=count,
            circuit_open=opened,
        )
        return count, opened

    def _log_network_result(
        self,
        method: str,
        permit: RequestPermit,
        attempt: int,
        attempts: int,
        duration: float,
        outcome: str,
        status: int | None,
        *,
        circuit_failure_count: (
            int | None
        ) = None,
        circuit_open: bool | None = None,
    ) -> None:
        if not self.debug:
            return

        context = ",".join(
            f"{key}={value}"
            for key, value
            in sorted(permit.context.items())
        )
        context = context or "none"

        print(
            "Black Duck network request: "
            f"method={method} "
            f"url={permit.sanitized_url} "
            f"attempt={attempt + 1}/{attempts} "
            f"duration={duration:.3f}s "
            f"pacing_wait="
            f"{permit.wait_seconds:.3f}s "
            f"outcome={outcome} "
            f"status={status} "
            f"context={context} "
            f"circuit_failures="
            f"{circuit_failure_count} "
            f"circuit_open={circuit_open}",
            file=sys.stderr,
        )

    def _http_error_message(
        self,
        error: HTTPError,
    ) -> str:
        body = error.read().decode(
            "utf-8",
            errors="replace",
        )
        return (
            f"HTTP {error.code} "
            f"{error.reason}: "
            f"{body[:4000]}"
        )

    def _sleep_for_retry(
        self,
        error: object,
        attempt: int,
        *,
        circuit_failure_count: (
            int | None
        ) = None,
    ) -> None:
        retry_after: float | None = None

        if isinstance(error, HTTPError):
            value = error.headers.get("Retry-After")

            if value:
                try:
                    retry_after = float(value)
                except ValueError:
                    retry_after = None

        sleep_seconds = (
            retry_after
            if retry_after is not None
            else self.retry_delay * (attempt + 1)
        )

        if self.debug:
            print(
                "Retrying Black Duck request after "
                f"{error}; sleeping "
                f"{sleep_seconds}s; "
                f"circuit_failures="
                f"{circuit_failure_count}",
                file=sys.stderr,
            )

        time.sleep(sleep_seconds)
