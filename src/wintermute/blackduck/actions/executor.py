from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from wintermute.blackduck.actions.models import (
    ActionPlan,
    BlackDuckAction,
    json_copy,
    normalize_base_url,
    stable_digest,
    utc_now,
    utc_text,
)
from wintermute.blackduck.actions.registry import (
    ActionRegistry,
)


SUCCESS_OUTCOMES = {
    "planned",
    "applied",
    "applied-after-error",
    "already-satisfied",
}


@dataclass(frozen=True)
class ExecutionPolicy:
    mode: str = "dry-run"
    confirm_apply: bool = False
    expected_plan_digest: str = ""
    expected_blackduck_base_url: str = ""
    allowed_producers: tuple[str, ...] = ()
    allowed_action_kinds: tuple[str, ...] = ()
    maximum_actions: int = 10
    maximum_blackduck_reads: int = 500
    maximum_blackduck_writes: int = 10
    stop_on_failure: bool = True

    def validate(self) -> None:
        if self.mode not in {
            "dry-run",
            "apply",
        }:
            raise ValueError(
                f"Unsupported execution mode: "
                f"{self.mode}"
            )

        if self.mode == "apply":
            if not self.confirm_apply:
                raise ValueError(
                    "Apply mode requires confirmation"
                )

            if not self.allowed_producers:
                raise ValueError(
                    "Apply mode requires allowed producers"
                )

            if not self.allowed_action_kinds:
                raise ValueError(
                    "Apply mode requires allowed action kinds"
                )

        for value in (
            self.maximum_actions,
            self.maximum_blackduck_reads,
            self.maximum_blackduck_writes,
        ):
            if value < 0:
                raise ValueError(
                    "Execution limits cannot be negative"
                )

        if (
            self.maximum_blackduck_writes
            > self.maximum_actions
        ):
            raise ValueError(
                "Write limit cannot exceed action limit"
            )


@dataclass(frozen=True)
class ActionReceipt:
    action_id: str
    kind: str
    outcome: str
    started_at: str
    completed_at: str
    reads: int
    writes: int
    before: dict[str, Any]
    after: dict[str, Any]
    detail: str
    error: str

    @property
    def succeeded(self) -> bool:
        return self.outcome in SUCCESS_OUTCOMES

    def as_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "kind": self.kind,
            "outcome": self.outcome,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "reads": self.reads,
            "writes": self.writes,
            "before": json_copy(self.before),
            "after": json_copy(self.after),
            "detail": self.detail,
            "error": self.error,
        }

    @classmethod
    def from_dict(
        cls,
        payload: dict[str, Any],
    ) -> ActionReceipt:
        before = payload.get("before", {})
        after = payload.get("after", {})

        if not isinstance(before, dict):
            raise ValueError(
                "Receipt before state must be an object"
            )

        if not isinstance(after, dict):
            raise ValueError(
                "Receipt after state must be an object"
            )

        return cls(
            action_id=str(
                payload.get("action_id") or ""
            ),
            kind=str(
                payload.get("kind") or ""
            ),
            outcome=str(
                payload.get("outcome") or ""
            ),
            started_at=str(
                payload.get("started_at") or ""
            ),
            completed_at=str(
                payload.get("completed_at") or ""
            ),
            reads=int(payload.get("reads") or 0),
            writes=int(payload.get("writes") or 0),
            before=json_copy(before),
            after=json_copy(after),
            detail=str(
                payload.get("detail") or ""
            ),
            error=str(
                payload.get("error") or ""
            ),
        )


@dataclass(frozen=True)
class ExecutionResult:
    schema_version: int
    execution_id: str
    plan_id: str
    plan_digest: str
    producer: str
    blackduck_base_url: str
    mode: str
    started_at: str
    completed_at: str
    reads: int
    writes: int
    receipts: tuple[ActionReceipt, ...]

    @property
    def status(self) -> str:
        if all(
            receipt.succeeded
            for receipt in self.receipts
        ):
            return "ok"

        if any(
            receipt.succeeded
            for receipt in self.receipts
        ):
            return "partial"

        return "failed"

    @property
    def counts(self) -> dict[str, int]:
        values: dict[str, int] = {}

        for receipt in self.receipts:
            values[receipt.outcome] = (
                values.get(receipt.outcome, 0) + 1
            )

        return dict(sorted(values.items()))

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "execution_id": self.execution_id,
            "plan_id": self.plan_id,
            "plan_digest": self.plan_digest,
            "producer": self.producer,
            "blackduck_base_url": (
                self.blackduck_base_url
            ),
            "mode": self.mode,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "reads": self.reads,
            "writes": self.writes,
            "counts": self.counts,
            "receipts": [
                receipt.as_dict()
                for receipt in self.receipts
            ],
        }

    @classmethod
    def from_dict(
        cls,
        payload: dict[str, Any],
    ) -> ExecutionResult:
        raw_receipts = payload.get("receipts", [])

        if not isinstance(raw_receipts, list):
            raise ValueError(
                "Execution receipts must be an array"
            )

        return cls(
            schema_version=int(
                payload.get("schema_version") or 0
            ),
            execution_id=str(
                payload.get("execution_id") or ""
            ),
            plan_id=str(
                payload.get("plan_id") or ""
            ),
            plan_digest=str(
                payload.get("plan_digest") or ""
            ),
            producer=str(
                payload.get("producer") or ""
            ),
            blackduck_base_url=str(
                payload.get(
                    "blackduck_base_url"
                )
                or ""
            ),
            mode=str(
                payload.get("mode") or ""
            ),
            started_at=str(
                payload.get("started_at") or ""
            ),
            completed_at=str(
                payload.get("completed_at") or ""
            ),
            reads=int(payload.get("reads") or 0),
            writes=int(payload.get("writes") or 0),
            receipts=tuple(
                ActionReceipt.from_dict(
                    dict(receipt)
                )
                for receipt in raw_receipts
            ),
        )


def receipt(
    action: BlackDuckAction,
    *,
    outcome: str,
    started_at: str,
    reads: int,
    writes: int,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    detail: str = "",
    error: str = "",
) -> ActionReceipt:
    return ActionReceipt(
        action_id=action.action_id,
        kind=action.kind,
        outcome=outcome,
        started_at=started_at,
        completed_at=utc_text(utc_now()),
        reads=reads,
        writes=writes,
        before=json_copy(before or {}),
        after=json_copy(after or {}),
        detail=detail,
        error=error,
    )


class ActionExecutor:
    def __init__(
        self,
        registry: ActionRegistry,
    ) -> None:
        self.registry = registry

    def execute(
        self,
        plan: ActionPlan,
        policy: ExecutionPolicy,
    ) -> ExecutionResult:
        plan.validate()
        plan.assert_not_expired()
        policy.validate()

        if (
            policy.expected_plan_digest
            and policy.expected_plan_digest
            != plan.digest
        ):
            raise ValueError(
                "Plan digest does not match"
            )

        if policy.expected_blackduck_base_url:
            expected_url = normalize_base_url(
                policy.expected_blackduck_base_url
            )

            if expected_url != plan.blackduck_base_url:
                raise ValueError(
                    "Plan targets another Black Duck "
                    "instance"
                )

        if (
            policy.allowed_producers
            and plan.producer
            not in set(policy.allowed_producers)
        ):
            raise ValueError(
                f"Producer is not allowed: "
                f"{plan.producer}"
            )

        kinds = {
            action.kind
            for action in plan.actions
        }

        if policy.allowed_action_kinds:
            disallowed = kinds - set(
                policy.allowed_action_kinds
            )

            if disallowed:
                raise ValueError(
                    "Action kinds are not allowed: "
                    + ", ".join(sorted(disallowed))
                )

        self.registry.validate_kinds(kinds)

        action_limit = min(
            plan.limits.maximum_actions,
            policy.maximum_actions,
        )
        read_limit = min(
            plan.limits.maximum_blackduck_reads,
            policy.maximum_blackduck_reads,
        )
        write_limit = min(
            plan.limits.maximum_blackduck_writes,
            policy.maximum_blackduck_writes,
        )

        if len(plan.actions) > action_limit:
            raise ValueError(
                "Plan exceeds execution action limit"
            )

        execution_started = utc_now()
        receipts: list[ActionReceipt] = []
        reads = 0
        writes = 0
        stop = False

        for action in plan.actions:
            action_started = utc_text(utc_now())

            if stop:
                receipts.append(
                    receipt(
                        action,
                        outcome="not-run",
                        started_at=action_started,
                        reads=0,
                        writes=0,
                        detail=(
                            "Execution stopped after an "
                            "earlier failure"
                        ),
                    )
                )
                continue

            if reads >= read_limit:
                current_receipt = receipt(
                    action,
                    outcome="budget-exhausted",
                    started_at=action_started,
                    reads=0,
                    writes=0,
                    detail=(
                        "Black Duck read limit reached"
                    ),
                )
                receipts.append(current_receipt)
                stop = policy.stop_on_failure
                continue

            handler = self.registry.get(
                action.kind
            )

            try:
                before = json_copy(
                    handler.read_state(action)
                )
                reads += 1
            except Exception as error:
                current_receipt = receipt(
                    action,
                    outcome="failed",
                    started_at=action_started,
                    reads=1,
                    writes=0,
                    error=str(error),
                )
                receipts.append(current_receipt)
                stop = policy.stop_on_failure
                continue

            if handler.is_satisfied(
                action,
                before,
            ):
                receipts.append(
                    receipt(
                        action,
                        outcome="already-satisfied",
                        started_at=action_started,
                        reads=1,
                        writes=0,
                        before=before,
                        after=before,
                    )
                )
                continue

            if (
                stable_digest(before)
                != action.observed_fingerprint
            ):
                current_receipt = receipt(
                    action,
                    outcome="stale-plan",
                    started_at=action_started,
                    reads=1,
                    writes=0,
                    before=before,
                    detail=(
                        "Current state differs from "
                        "planned state"
                    ),
                )
                receipts.append(current_receipt)
                stop = policy.stop_on_failure
                continue

            conflict = handler.conflict_reason(
                action,
                before,
            )

            if conflict:
                current_receipt = receipt(
                    action,
                    outcome="protected-conflict",
                    started_at=action_started,
                    reads=1,
                    writes=0,
                    before=before,
                    detail=conflict,
                )
                receipts.append(current_receipt)
                stop = policy.stop_on_failure
                continue

            if policy.mode == "dry-run":
                receipts.append(
                    receipt(
                        action,
                        outcome="planned",
                        started_at=action_started,
                        reads=1,
                        writes=0,
                        before=before,
                    )
                )
                continue

            if writes >= write_limit:
                current_receipt = receipt(
                    action,
                    outcome="budget-exhausted",
                    started_at=action_started,
                    reads=1,
                    writes=0,
                    before=before,
                    detail=(
                        "Black Duck write limit reached"
                    ),
                )
                receipts.append(current_receipt)
                stop = policy.stop_on_failure
                continue

            if reads >= read_limit:
                current_receipt = receipt(
                    action,
                    outcome="budget-exhausted",
                    started_at=action_started,
                    reads=1,
                    writes=0,
                    before=before,
                    detail=(
                        "No read capacity remains for "
                        "write verification"
                    ),
                )
                receipts.append(current_receipt)
                stop = policy.stop_on_failure
                continue

            writes += 1

            try:
                handler.apply(action, before)
            except Exception as error:
                try:
                    after = json_copy(
                        handler.read_state(action)
                    )
                    reads += 1
                except Exception as read_error:
                    current_receipt = receipt(
                        action,
                        outcome="failed",
                        started_at=action_started,
                        reads=1,
                        writes=1,
                        before=before,
                        error=(
                            f"{error}; verification "
                            f"failed: {read_error}"
                        ),
                    )
                else:
                    if handler.is_satisfied(
                        action,
                        after,
                    ):
                        current_receipt = receipt(
                            action,
                            outcome=(
                                "applied-after-error"
                            ),
                            started_at=action_started,
                            reads=2,
                            writes=1,
                            before=before,
                            after=after,
                            detail=str(error),
                        )
                    else:
                        current_receipt = receipt(
                            action,
                            outcome="failed",
                            started_at=action_started,
                            reads=2,
                            writes=1,
                            before=before,
                            after=after,
                            error=str(error),
                        )

                receipts.append(current_receipt)
                stop = (
                    policy.stop_on_failure
                    and not current_receipt.succeeded
                )
                continue

            try:
                after = json_copy(
                    handler.read_state(action)
                )
                reads += 1
            except Exception as error:
                current_receipt = receipt(
                    action,
                    outcome="verification-failed",
                    started_at=action_started,
                    reads=2,
                    writes=1,
                    before=before,
                    error=str(error),
                )
                receipts.append(current_receipt)
                stop = policy.stop_on_failure
                continue

            if handler.is_satisfied(
                action,
                after,
            ):
                receipts.append(
                    receipt(
                        action,
                        outcome="applied",
                        started_at=action_started,
                        reads=2,
                        writes=1,
                        before=before,
                        after=after,
                    )
                )
            else:
                current_receipt = receipt(
                    action,
                    outcome="verification-failed",
                    started_at=action_started,
                    reads=2,
                    writes=1,
                    before=before,
                    after=after,
                    detail=(
                        "Result does not match desired "
                        "state"
                    ),
                )
                receipts.append(current_receipt)
                stop = policy.stop_on_failure

        completed = utc_now()

        return ExecutionResult(
            schema_version=1,
            execution_id=(
                f"{completed.strftime('%Y%m%dT%H%M%SZ')}-"
                f"{uuid.uuid4().hex[:12]}"
            ),
            plan_id=plan.plan_id,
            plan_digest=plan.digest,
            producer=plan.producer,
            blackduck_base_url=(
                plan.blackduck_base_url
            ),
            mode=policy.mode,
            started_at=utc_text(
                execution_started
            ),
            completed_at=utc_text(completed),
            reads=reads,
            writes=writes,
            receipts=tuple(receipts),
        )
