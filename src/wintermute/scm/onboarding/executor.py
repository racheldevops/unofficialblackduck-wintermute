from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from wintermute.scm.onboarding.artifacts import (
    LoadedOnboardingPlan,
    create_execution_id,
    now_text,
)


class OnboardingAdapter(Protocol):
    provider: str

    def probe(
        self,
        bundle: LoadedOnboardingPlan,
    ) -> dict[str, Any]:
        ...

    def apply(
        self,
        bundle: LoadedOnboardingPlan,
        actions: list[dict[str, Any]],
    ) -> int:
        ...


@dataclass(frozen=True)
class ExecutionOptions:
    mode: str = "dry-run"
    confirm_apply: bool = False
    expected_plan_digest: str = ""
    maximum_writes: int = 2

    def validate(
        self,
        bundle: LoadedOnboardingPlan,
    ) -> None:
        if self.mode not in {
            "dry-run",
            "apply",
        }:
            raise ValueError(
                "Execution mode is invalid"
            )

        if self.maximum_writes < 0:
            raise ValueError(
                "maximum_writes cannot be negative"
            )

        if self.mode == "apply":
            if not self.confirm_apply:
                raise ValueError(
                    "Apply mode requires confirmation"
                )

            if (
                not self.expected_plan_digest
                or self.expected_plan_digest
                != bundle.digest
            ):
                raise ValueError(
                    "Expected onboarding plan digest "
                    "does not match"
                )


def execute_plan(
    bundle: LoadedOnboardingPlan,
    adapter: OnboardingAdapter,
    options: ExecutionOptions,
) -> dict[str, Any]:
    options.validate(bundle)
    repository = bundle.plan[
        "repository"
    ]
    provider = str(
        repository["provider"]
    )

    if adapter.provider != provider:
        raise ValueError(
            "Onboarding adapter does not match "
            "the plan provider"
        )

    started_at = now_text()
    capability = adapter.probe(bundle)
    capability_status = str(
        capability.get("status") or ""
    )
    actions = capability.get("actions")

    if (
        not isinstance(actions, list)
        or not all(
            isinstance(value, dict)
            for value in actions
        )
    ):
        raise ValueError(
            "Capability actions are invalid"
        )

    writes = 0
    verification: dict[str, Any] | None = None

    if capability_status != "ready":
        status = "blocked"
        outcome = capability_status
    elif options.mode == "dry-run":
        status = "ok"
        outcome = (
            "planned"
            if actions
            else "already-satisfied"
        )
    elif len(actions) > options.maximum_writes:
        status = "blocked"
        outcome = "budget-exhausted"
    else:
        writes = adapter.apply(
            bundle,
            actions,
        )
        verification = adapter.probe(bundle)

        if (
            verification.get("status")
            == "ready"
            and verification.get("actions")
            == []
        ):
            status = "ok"
            outcome = "applied"
        else:
            status = "failed"
            outcome = "verification-failed"

    return {
        "schema_version": 1,
        "execution_id": (
            create_execution_id()
        ),
        "plan_id": bundle.plan["plan_id"],
        "plan_digest": bundle.digest,
        "provider": provider,
        "repository": repository,
        "mode": options.mode,
        "started_at": started_at,
        "completed_at": now_text(),
        "status": status,
        "outcome": outcome,
        "writes": writes,
        "capability": capability,
        "verification": verification,
    }
