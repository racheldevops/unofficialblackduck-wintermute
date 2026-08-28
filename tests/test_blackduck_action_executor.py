from __future__ import annotations

from typing import Any

import pytest

from wintermute.blackduck.actions.executor import (
    ActionExecutor,
    ExecutionPolicy,
)
from wintermute.blackduck.actions.models import (
    ActionEvidence,
    ActionLimits,
    ActionOwnership,
    ActionPlan,
    ActionTarget,
    BlackDuckAction,
    stable_digest,
)
from wintermute.blackduck.actions.registry import (
    ActionRegistry,
)


BASE_URL = "https://blackduck.example.invalid"


class Handler:
    kind = "resource.set"

    def __init__(
        self,
        states: dict[str, dict[str, Any]],
    ) -> None:
        self.states = states
        self.writes: list[str] = []

    def read_state(
        self,
        action: BlackDuckAction,
    ) -> dict[str, Any]:
        return dict(
            self.states[action.action_id]
        )

    def is_satisfied(
        self,
        action: BlackDuckAction,
        state: dict[str, Any],
    ) -> bool:
        return (
            state.get("value")
            == action.desired.get("value")
        )

    def conflict_reason(
        self,
        action: BlackDuckAction,
        state: dict[str, Any],
    ) -> str:
        del action

        if state.get("owner") == "human":
            return "Current state is owned by a user"

        return ""

    def apply(
        self,
        action: BlackDuckAction,
        state: dict[str, Any],
    ) -> None:
        del state
        self.writes.append(action.action_id)
        self.states[action.action_id] = {
            "value": action.desired["value"],
            "owner": (
                action.ownership.marker
            ),
        }


def make_action(
    value: str,
    *,
    observed: dict[str, Any] | None = None,
) -> BlackDuckAction:
    state = observed or {
        "value": "old",
        "owner": "",
    }

    return BlackDuckAction.build(
        kind="resource.set",
        target=ActionTarget(
            resource_type="test-resource",
            resource_href=(
                f"{BASE_URL}/api/test/{value}"
            ),
            project_version_href=(
                f"{BASE_URL}/api/projects/p"
                "/versions/v"
            ),
            identifiers={"name": value},
        ),
        observed=state,
        desired={"value": value},
        ownership=ActionOwnership(
            producer="test-producer",
            marker="wintermute:test:v1",
        ),
        evidence=ActionEvidence(
            provider="test",
            subject=value,
            revision="revision",
            digest=stable_digest(
                {"value": value}
            ),
            details={"value": value},
        ),
        reason="test",
    )


def make_plan(
    actions: tuple[BlackDuckAction, ...],
) -> ActionPlan:
    return ActionPlan.create(
        producer="test-producer",
        producer_version="1",
        blackduck_base_url=BASE_URL,
        actions=actions,
        limits=ActionLimits(
            maximum_actions=10,
            maximum_blackduck_reads=20,
            maximum_blackduck_writes=10,
        ),
    )


def registry_for(
    handler: Handler,
) -> ActionRegistry:
    registry = ActionRegistry()
    registry.register(handler)
    return registry


def apply_policy(
    **changes: Any,
) -> ExecutionPolicy:
    values = {
        "mode": "apply",
        "confirm_apply": True,
        "expected_blackduck_base_url": (
            BASE_URL
        ),
        "allowed_producers": (
            "test-producer",
        ),
        "allowed_action_kinds": (
            "resource.set",
        ),
        "maximum_actions": 10,
        "maximum_blackduck_reads": 20,
        "maximum_blackduck_writes": 10,
        "stop_on_failure": True,
    }
    values.update(changes)
    return ExecutionPolicy(**values)


def test_dry_run_does_not_write() -> None:
    action = make_action("new")
    handler = Handler(
        {
            action.action_id: dict(
                action.observed
            )
        }
    )
    result = ActionExecutor(
        registry_for(handler)
    ).execute(
        make_plan((action,)),
        ExecutionPolicy(),
    )

    assert result.counts == {"planned": 1}
    assert result.reads == 1
    assert result.writes == 0
    assert handler.writes == []


def test_apply_requires_confirmation() -> None:
    action = make_action("new")
    handler = Handler(
        {
            action.action_id: dict(
                action.observed
            )
        }
    )

    with pytest.raises(
        ValueError,
        match="requires confirmation",
    ):
        ActionExecutor(
            registry_for(handler)
        ).execute(
            make_plan((action,)),
            ExecutionPolicy(mode="apply"),
        )


def test_apply_writes_and_verifies() -> None:
    action = make_action("new")
    handler = Handler(
        {
            action.action_id: dict(
                action.observed
            )
        }
    )
    result = ActionExecutor(
        registry_for(handler)
    ).execute(
        make_plan((action,)),
        apply_policy(),
    )

    assert result.counts == {"applied": 1}
    assert result.reads == 2
    assert result.writes == 1
    assert handler.writes == [
        action.action_id
    ]


def test_stale_plan_does_not_write() -> None:
    action = make_action("new")
    handler = Handler(
        {
            action.action_id: {
                "value": "changed",
                "owner": "",
            }
        }
    )
    result = ActionExecutor(
        registry_for(handler)
    ).execute(
        make_plan((action,)),
        apply_policy(),
    )

    assert result.counts == {
        "stale-plan": 1
    }
    assert handler.writes == []


def test_human_state_is_preserved() -> None:
    observed = {
        "value": "old",
        "owner": "human",
    }
    action = make_action(
        "new",
        observed=observed,
    )
    handler = Handler(
        {
            action.action_id: observed
        }
    )
    result = ActionExecutor(
        registry_for(handler)
    ).execute(
        make_plan((action,)),
        apply_policy(),
    )

    assert result.counts == {
        "protected-conflict": 1
    }
    assert handler.writes == []


def test_write_limit_is_enforced() -> None:
    first = make_action("one")
    second = make_action("two")
    handler = Handler(
        {
            first.action_id: dict(
                first.observed
            ),
            second.action_id: dict(
                second.observed
            ),
        }
    )
    result = ActionExecutor(
        registry_for(handler)
    ).execute(
        make_plan((first, second)),
        apply_policy(
            maximum_blackduck_writes=1,
            stop_on_failure=False,
        ),
    )

    assert result.counts == {
        "applied": 1,
        "budget-exhausted": 1,
    }
    assert result.writes == 1
