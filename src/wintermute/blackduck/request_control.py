from __future__ import annotations

import os
import threading
import time
from collections import deque
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Iterator
from urllib.parse import (
    parse_qsl,
    quote,
    urlsplit,
    urlunsplit,
)


DEFAULT_REQUEST_INTERVAL_SECONDS = 0.25
DEFAULT_CIRCUIT_BREAKER_THRESHOLD = 5
DEFAULT_CIRCUIT_BREAKER_WINDOW_SECONDS = 60.0

REQUEST_INTERVAL_ENV = (
    "WINTERMUTE_BLACKDUCK_REQUEST_INTERVAL_SECONDS"
)
CIRCUIT_THRESHOLD_ENV = (
    "WINTERMUTE_BLACKDUCK_CIRCUIT_BREAKER_THRESHOLD"
)
CIRCUIT_WINDOW_ENV = (
    "WINTERMUTE_BLACKDUCK_CIRCUIT_BREAKER_WINDOW_SECONDS"
)

_REQUEST_CONTEXT: ContextVar[
    dict[str, str]
] = ContextVar(
    "wintermute_blackduck_request_context",
    default={},
)

_SHARED_CONTROLLERS: dict[
    tuple[float, int, float],
    BlackDuckRequestController,
] = {}
_SHARED_CONTROLLERS_LOCK = threading.Lock()


def environment_float(
    name: str,
    default: float,
) -> float:
    raw = os.getenv(name, "").strip()

    if not raw:
        return default

    try:
        return float(raw)
    except ValueError as error:
        raise ValueError(
            f"{name} must be numeric"
        ) from error


def environment_int(
    name: str,
    default: int,
) -> int:
    raw = os.getenv(name, "").strip()

    if not raw:
        return default

    try:
        return int(raw)
    except ValueError as error:
        raise ValueError(
            f"{name} must be an integer"
        ) from error


def sanitized_url(value: str) -> str:
    parsed = urlsplit(str(value or ""))
    query_names = sorted(
        {
            key
            for key, _ in parse_qsl(
                parsed.query,
                keep_blank_values=True,
            )
        }
    )
    query = "&".join(
        f"{quote(name, safe='')}=<redacted>"
        for name in query_names
    )

    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            query,
            "",
        )
    )


@contextmanager
def blackduck_request_context(
    **values: Any,
) -> Iterator[None]:
    updated = dict(_REQUEST_CONTEXT.get())

    for key, value in values.items():
        rendered = str(value or "").strip()

        if rendered:
            updated[str(key)] = rendered

    token = _REQUEST_CONTEXT.set(updated)

    try:
        yield
    finally:
        _REQUEST_CONTEXT.reset(token)


def current_request_context() -> dict[str, str]:
    return dict(_REQUEST_CONTEXT.get())


@dataclass(frozen=True)
class RequestPermit:
    wait_seconds: float
    sanitized_url: str
    context: dict[str, str]


@dataclass(frozen=True)
class CircuitSnapshot:
    open: bool
    failure_count: int
    threshold: int
    window_seconds: float
    opened_at_epoch: float | None
    last_status: int | None
    last_url: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "open": self.open,
            "failure_count": self.failure_count,
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "opened_at_epoch": self.opened_at_epoch,
            "last_status": self.last_status,
            "last_url": self.last_url,
        }


class BlackDuckCircuitOpenError(RuntimeError):
    pass


class BlackDuckRequestController:
    def __init__(
        self,
        *,
        request_interval_seconds: float,
        circuit_breaker_threshold: int,
        circuit_breaker_window_seconds: float,
        monotonic: Any = time.monotonic,
        wall_time: Any = time.time,
        sleeper: Any = time.sleep,
    ) -> None:
        self.request_interval_seconds = float(
            request_interval_seconds
        )
        self.circuit_breaker_threshold = int(
            circuit_breaker_threshold
        )
        self.circuit_breaker_window_seconds = float(
            circuit_breaker_window_seconds
        )

        if self.request_interval_seconds < 0:
            raise ValueError(
                "Black Duck request interval cannot "
                "be negative"
            )

        if self.circuit_breaker_threshold < 1:
            raise ValueError(
                "Black Duck circuit-breaker threshold "
                "must be greater than zero"
            )

        if self.circuit_breaker_window_seconds <= 0:
            raise ValueError(
                "Black Duck circuit-breaker window "
                "must be greater than zero"
            )

        self._monotonic = monotonic
        self._wall_time = wall_time
        self._sleeper = sleeper
        self._lock = threading.RLock()
        self._next_request_at = 0.0
        self._failures: deque[
            tuple[float, int, str]
        ] = deque()
        self._circuit_open = False
        self._opened_at_epoch: float | None = None
        self._last_status: int | None = None
        self._last_url = ""

    @classmethod
    def from_environment(
        cls,
        *,
        request_interval_seconds: float | None = None,
        circuit_breaker_threshold: int | None = None,
        circuit_breaker_window_seconds: (
            float | None
        ) = None,
    ) -> BlackDuckRequestController:
        interval = (
            environment_float(
                REQUEST_INTERVAL_ENV,
                DEFAULT_REQUEST_INTERVAL_SECONDS,
            )
            if request_interval_seconds is None
            else float(request_interval_seconds)
        )
        threshold = (
            environment_int(
                CIRCUIT_THRESHOLD_ENV,
                DEFAULT_CIRCUIT_BREAKER_THRESHOLD,
            )
            if circuit_breaker_threshold is None
            else int(circuit_breaker_threshold)
        )
        window = (
            environment_float(
                CIRCUIT_WINDOW_ENV,
                DEFAULT_CIRCUIT_BREAKER_WINDOW_SECONDS,
            )
            if circuit_breaker_window_seconds is None
            else float(circuit_breaker_window_seconds)
        )
        key = (
            interval,
            threshold,
            window,
        )

        with _SHARED_CONTROLLERS_LOCK:
            existing = _SHARED_CONTROLLERS.get(key)

            if existing is not None:
                return existing

            created = cls(
                request_interval_seconds=interval,
                circuit_breaker_threshold=threshold,
                circuit_breaker_window_seconds=window,
            )
            _SHARED_CONTROLLERS[key] = created
            return created

    def before_request(
        self,
        method: str,
        url: str,
    ) -> RequestPermit:
        del method
        safe_url = sanitized_url(url)

        with self._lock:
            self._raise_if_open_locked()
            now = float(self._monotonic())
            scheduled = max(
                now,
                self._next_request_at,
            )
            wait_seconds = max(
                0.0,
                scheduled - now,
            )
            self._next_request_at = (
                scheduled
                + self.request_interval_seconds
            )

        if wait_seconds:
            self._sleeper(wait_seconds)

        with self._lock:
            self._raise_if_open_locked()

        return RequestPermit(
            wait_seconds=wait_seconds,
            sanitized_url=safe_url,
            context=current_request_context(),
        )

    def raise_if_open(self) -> None:
        with self._lock:
            self._raise_if_open_locked()

    def record_success(self) -> None:
        with self._lock:
            self._prune_failures_locked(
                float(self._monotonic())
            )

    def record_server_failure(
        self,
        status: int,
        url: str,
    ) -> tuple[int, bool]:
        status = int(status)

        if not 500 <= status <= 599:
            return self.failure_count(), False

        safe_url = sanitized_url(url)

        with self._lock:
            now = float(self._monotonic())
            self._prune_failures_locked(now)
            self._failures.append(
                (
                    now,
                    status,
                    safe_url,
                )
            )
            self._last_status = status
            self._last_url = safe_url

            if (
                not self._circuit_open
                and len(self._failures)
                >= self.circuit_breaker_threshold
            ):
                self._circuit_open = True
                self._opened_at_epoch = float(
                    self._wall_time()
                )

            return (
                len(self._failures),
                self._circuit_open,
            )

    def failure_count(self) -> int:
        with self._lock:
            self._prune_failures_locked(
                float(self._monotonic())
            )
            return len(self._failures)

    def snapshot(self) -> CircuitSnapshot:
        with self._lock:
            self._prune_failures_locked(
                float(self._monotonic())
            )
            return CircuitSnapshot(
                open=self._circuit_open,
                failure_count=len(self._failures),
                threshold=(
                    self.circuit_breaker_threshold
                ),
                window_seconds=(
                    self.circuit_breaker_window_seconds
                ),
                opened_at_epoch=self._opened_at_epoch,
                last_status=self._last_status,
                last_url=self._last_url,
            )

    def circuit_error(
        self,
    ) -> BlackDuckCircuitOpenError:
        snapshot = self.snapshot()

        return BlackDuckCircuitOpenError(
            "Black Duck circuit breaker is open after "
            f"{snapshot.failure_count} server failure(s) "
            f"within {snapshot.window_seconds:g}s; "
            f"threshold={snapshot.threshold}, "
            f"last_status={snapshot.last_status}, "
            f"last_url={snapshot.last_url}, "
            f"opened_at_epoch={snapshot.opened_at_epoch}"
        )

    def _raise_if_open_locked(self) -> None:
        if self._circuit_open:
            raise self.circuit_error()

    def _prune_failures_locked(
        self,
        now: float,
    ) -> None:
        if self._circuit_open:
            return

        cutoff = (
            now
            - self.circuit_breaker_window_seconds
        )

        while (
            self._failures
            and self._failures[0][0] < cutoff
        ):
            self._failures.popleft()
