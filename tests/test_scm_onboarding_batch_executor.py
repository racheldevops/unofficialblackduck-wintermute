from __future__ import annotations

from pathlib import Path

import pytest

from wintermute.scm.onboarding.batch_artifacts import (
    LoadedBatchOnboardingPlan,
)
from wintermute.scm.onboarding.batch_executor import (
    BatchExecutionOptions,
    execute_batch_plan,
)


class Adapter:
    def __init__(
        self,
        provider: str,
        action_count: int,
    ) -> None:
        self.provider = provider
        self.action_count = action_count
        self.applied = False

    def probe(self, bundle):
        del bundle

        return {
            "status": "ready",
            "provider": self.provider,
            "actions": (
                []
                if self.applied
                else [
                    {
                        "kind": (
                            f"{self.provider}.test"
                        )
                    }
                    for _ in range(
                        self.action_count
                    )
                ]
            ),
            "reason": "",
        }

    def estimated_writes(
        self,
        actions,
    ) -> int:
        return len(actions)

    def apply(
        self,
        bundle,
        actions,
    ) -> int:
        del bundle
        self.applied = True
        return len(actions)


def bundle(
    tmp_path: Path,
) -> LoadedBatchOnboardingPlan:
    return LoadedBatchOnboardingPlan(
        directory=tmp_path,
        plan={
            "plan_id": "plan-one",
            "providers": [
                "github",
                "gitlab",
            ],
        },
        registry={},
        github_plan={},
        github_ruleset={},
        gitlab_plan={},
        gitlab_policy=(
            "enabled: false\n"
        ),
        digest=(
            "sha256:" + "a" * 64
        ),
    )


def adapters():
    return {
        "github": Adapter(
            "github",
            2,
        ),
        "gitlab": Adapter(
            "gitlab",
            1,
        ),
    }


def test_batch_dry_run_does_not_apply(
    tmp_path: Path,
) -> None:
    selected = adapters()
    result = execute_batch_plan(
        bundle(tmp_path),
        selected,
        BatchExecutionOptions(),
    )

    assert result["status"] == "ok"
    assert result["outcome"] == "planned"
    assert result["estimated_writes"] == 3
    assert result["writes"] == 0
    assert selected["github"].applied is False
    assert selected["gitlab"].applied is False


def test_batch_apply_requires_digest(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        ValueError,
        match="digest",
    ):
        execute_batch_plan(
            bundle(tmp_path),
            adapters(),
            BatchExecutionOptions(
                mode="apply",
                confirm_apply=True,
            ),
        )


def test_batch_budget_blocks_all_providers(
    tmp_path: Path,
) -> None:
    selected = adapters()
    current = bundle(tmp_path)
    result = execute_batch_plan(
        current,
        selected,
        BatchExecutionOptions(
            mode="apply",
            confirm_apply=True,
            expected_plan_digest=(
                current.digest
            ),
            maximum_writes=2,
        ),
    )

    assert result["status"] == "blocked"
    assert result["outcome"] == (
        "budget-exhausted"
    )
    assert result["writes"] == 0
    assert selected["github"].applied is False
    assert selected["gitlab"].applied is False


def test_batch_apply_is_sequential_and_verified(
    tmp_path: Path,
) -> None:
    selected = adapters()
    current = bundle(tmp_path)
    result = execute_batch_plan(
        current,
        selected,
        BatchExecutionOptions(
            mode="apply",
            confirm_apply=True,
            expected_plan_digest=(
                current.digest
            ),
            maximum_writes=3,
        ),
    )

    assert result["status"] == "ok"
    assert result["outcome"] == "applied"
    assert result["writes"] == 3
    assert [
        value["status"]
        for value in result["providers"]
    ] == [
        "verified",
        "verified",
    ]
