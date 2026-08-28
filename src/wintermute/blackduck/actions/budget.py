from __future__ import annotations

import threading
from typing import Any


class RequestBudgetExceeded(RuntimeError):
    pass


class BudgetedRequestController:
    def __init__(
        self,
        controller: Any,
        maximum_requests: int,
    ) -> None:
        if maximum_requests < 1:
            raise ValueError(
                "maximum_requests must be positive"
            )

        self.controller = controller
        self.maximum_requests = (
            maximum_requests
        )
        self._lock = threading.RLock()
        self._request_count = 0

    @property
    def request_count(self) -> int:
        with self._lock:
            return self._request_count

    def before_request(
        self,
        method: str,
        url: str,
    ) -> Any:
        with self._lock:
            if (
                self._request_count
                >= self.maximum_requests
            ):
                raise RequestBudgetExceeded(
                    "Black Duck request budget "
                    "was exhausted"
                )

            self._request_count += 1

        return self.controller.before_request(
            method,
            url,
        )

    def record_success(self) -> None:
        self.controller.record_success()

    def record_server_failure(
        self,
        status: int,
        url: str,
        *,
        context: dict[str, str] | None = None,
    ) -> tuple[int, bool]:
        return (
            self.controller.record_server_failure(
                status,
                url,
                context=context,
            )
        )

    def failure_count(self) -> int:
        return self.controller.failure_count()

    def snapshot(self) -> Any:
        return self.controller.snapshot()

    def reset(self) -> None:
        self.controller.reset()

    def circuit_error(self) -> BaseException:
        return self.controller.circuit_error()

    def raise_if_open(self) -> None:
        self.controller.raise_if_open()
