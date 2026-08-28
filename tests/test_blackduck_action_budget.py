from __future__ import annotations

import pytest

from wintermute.blackduck.actions.budget import (
    BudgetedRequestController,
    RequestBudgetExceeded,
)


class Controller:
    def __init__(self) -> None:
        self.requests = 0

    def before_request(
        self,
        method: str,
        url: str,
    ):
        self.requests += 1
        return method, url

    def record_success(self) -> None:
        pass

    def record_server_failure(
        self,
        status: int,
        url: str,
        *,
        context=None,
    ):
        del status
        del url
        del context
        return 1, False


def test_request_budget() -> None:
    controller = Controller()
    budget = BudgetedRequestController(
        controller,
        2,
    )

    budget.before_request("GET", "/one")
    budget.before_request("GET", "/two")

    with pytest.raises(
        RequestBudgetExceeded,
    ):
        budget.before_request(
            "GET",
            "/three",
        )

    assert budget.request_count == 2
    assert controller.requests == 2
