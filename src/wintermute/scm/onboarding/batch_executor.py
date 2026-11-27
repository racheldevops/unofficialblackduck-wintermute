from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from wintermute.scm.onboarding.artifacts import (
    create_execution_id,
    now_text,
)
from wintermute.scm.onboarding.batch_artifacts import (
    LoadedBatchOnboardingPlan,
)


class BatchOnboardingAdapter(Protocol):
    provider: str

    def probe(
        self,
        bundle: LoadedBatchOnboardingPlan,
    ) -> dict[str, Any]:
        ...

    def estimated_writes(
        self,
        actions: list[dict[str, Any]],
    ) -> int:
        ...

    def apply(
        self,
        bundle: LoadedBatchOnboardingPlan,
        actions: list[dict[str, Any]],
    ) -> int:
        ...


@dataclass(frozen=True)
class BatchExecutionOptions:
    mode: str = "dry-run"
    confirm_apply: bool = False
    expected_plan_digest: str = ""
    maximum_writes: int = 100

    def validate(
        self,
        bundle: LoadedBatchOnboardingPlan,
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
                    "Expected onboarding batch-plan "
                    "digest does not match"
                )


def execute_batch_plan(
    bundle: LoadedBatchOnboardingPlan,
    adapters: dict[
        str,
        BatchOnboardingAdapter,
    ],
    options: BatchExecutionOptions,
) -> dict[str, Any]:
    options.validate(bundle)
    providers = tuple(
        bundle.plan["providers"]
    )

    if set(adapters) != set(providers):
        raise ValueError(
            "Onboarding adapters do not match "
            "the batch-plan providers"
        )

    started_at = now_text()
    probes: dict[str, dict[str, Any]] = {}
    estimated_writes = 0

    for provider in providers:
        probe = adapters[
            provider
        ].probe(bundle)
        probes[provider] = probe
        actions = probe.get("actions")

        if (
            not isinstance(actions, list)
            or not all(
                isinstance(value, dict)
                for value in actions
            )
        ):
            raise ValueError(
                f"{provider} capability actions "
                "are invalid"
            )

        if probe.get("status") == "ready":
            estimated_writes += adapters[
                provider
            ].estimated_writes(actions)

    blocked = [
        provider
        for provider in providers
        if probes[provider].get("status")
        != "ready"
    ]
    provider_results: list[
        dict[str, Any]
    ] = []
    writes = 0

    if blocked:
        status = "blocked"
        outcome = "capability-blocked"

        for provider in providers:
            provider_results.append(
                {
                    "provider": provider,
                    "before": probes[
                        provider
                    ],
                    "writes": 0,
                    "after": None,
                    "status": (
                        "blocked"
                        if provider in blocked
                        else "not-run"
                    ),
                }
            )

    elif (
        estimated_writes
        > options.maximum_writes
    ):
        status = "blocked"
        outcome = "budget-exhausted"

        for provider in providers:
            provider_results.append(
                {
                    "provider": provider,
                    "before": probes[
                        provider
                    ],
                    "writes": 0,
                    "after": None,
                    "status": "not-run",
                }
            )

    elif options.mode == "dry-run":
        status = "ok"
        outcome = (
            "planned"
            if estimated_writes
            else "already-satisfied"
        )

        for provider in providers:
            provider_results.append(
                {
                    "provider": provider,
                    "before": probes[
                        provider
                    ],
                    "writes": 0,
                    "after": None,
                    "status": (
                        "planned"
                        if probes[provider][
                            "actions"
                        ]
                        else "already-satisfied"
                    ),
                }
            )

    else:
        status = "ok"
        outcome = "applied"

        for provider in providers:
            before = probes[provider]
            actions = before["actions"]

            try:
                provider_writes = adapters[
                    provider
                ].apply(
                    bundle,
                    actions,
                )
                writes += provider_writes
                after = adapters[
                    provider
                ].probe(bundle)
                verified = (
                    after.get("status")
                    == "ready"
                    and after.get("actions")
                    == []
                )
                provider_status = (
                    "verified"
                    if verified
                    else "verification-failed"
                )

                if not verified:
                    status = "failed"
                    outcome = (
                        "verification-failed"
                    )

                provider_results.append(
                    {
                        "provider": provider,
                        "before": before,
                        "writes": (
                            provider_writes
                        ),
                        "after": after,
                        "status": (
                            provider_status
                        ),
                    }
                )

                if not verified:
                    break

            except Exception as error:
                status = "failed"
                outcome = "apply-failed"
                provider_results.append(
                    {
                        "provider": provider,
                        "before": before,
                        "writes": 0,
                        "after": None,
                        "status": "failed",
                        "error": str(error),
                    }
                )
                break

        completed = {
            value["provider"]
            for value in provider_results
        }

        for provider in providers:
            if provider in completed:
                continue

            provider_results.append(
                {
                    "provider": provider,
                    "before": probes[
                        provider
                    ],
                    "writes": 0,
                    "after": None,
                    "status": "not-run",
                }
            )

    return {
        "schema_version": 1,
        "execution_id": (
            create_execution_id()
        ),
        "plan_id": bundle.plan["plan_id"],
        "plan_digest": bundle.digest,
        "mode": options.mode,
        "started_at": started_at,
        "completed_at": now_text(),
        "status": status,
        "outcome": outcome,
        "estimated_writes": (
            estimated_writes
        ),
        "writes": writes,
        "providers": provider_results,
    }
