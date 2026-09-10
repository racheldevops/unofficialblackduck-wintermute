from __future__ import annotations

from pathlib import Path

import pytest

from wintermute.ai.artifacts import (
    load_verified_analysis,
)
from wintermute.ai.models import (
    AnalysisResult,
    AnalysisRound,
    ModelUsage,
)
from wintermute.ai.storage import (
    write_analysis,
)
from wintermute.scm.onboarding.artifacts import (
    load_verified_plan,
)
from wintermute.scm.onboarding.executor import (
    ExecutionOptions,
    execute_plan,
)
from wintermute.scm.onboarding.planning import (
    GitHubPolicyConfiguration,
    RepositoryTarget,
    build_plan,
    write_plan,
)


class Adapter:
    provider = "github"

    def __init__(self) -> None:
        self.applied = False

    def probe(self, bundle):
        del bundle

        return {
            "status": "ready",
            "provider": "github",
            "actions": (
                []
                if self.applied
                else [
                    {
                        "kind": (
                            "github.repository-property.set"
                        )
                    }
                ]
            ),
            "reason": "",
        }

    def apply(
        self,
        bundle,
        actions,
    ) -> int:
        del bundle
        assert len(actions) == 1
        self.applied = True
        return 1


def bundle(tmp_path: Path):
    analysis = AnalysisResult(
        analysis_id="analysis-one",
        task="scm.scan-profile",
        task_version="1",
        provider="vllm",
        model="test",
        input_digest="sha256:" + "a" * 64,
        result={
            "schema_version": 1,
            "languages": ["python"],
            "build_systems": ["python"],
            "package_managers": ["pip"],
            "layout": "single-project",
            "scan_mode": "detector",
            "central_template": "python",
            "parameters": {
                "buildless": True,
            },
            "confidence": 1.0,
            "evidence_ids": ["ev-one"],
            "conflicts": [],
            "unresolved_questions": [],
        },
        evidence_ids=("ev-one",),
        rounds=(
            AnalysisRound(
                round_number=1,
                request_digest=(
                    "sha256:" + "b" * 64
                ),
                cache_hit=False,
                requested_evidence_ids=(),
                usage=ModelUsage(),
                estimated_cost_usd=0,
                latency_seconds=0,
            ),
        ),
        created_at="2026-08-28T00:00:00Z",
    )
    analysis_path = write_analysis(
        tmp_path / "analyses",
        analysis,
        evidence_catalog=[
            {
                "evidence_id": "ev-one",
                "safe_path": "pyproject.toml",
                "relative_path": "pyproject.toml",
                "kind": "build",
                "digest": (
                    "sha256:" + "c" * 64
                ),
            }
        ],
    )
    loaded_analysis = load_verified_analysis(
        analysis_path
    )
    plan, registry, policy = build_plan(
        loaded_analysis,
        RepositoryTarget(
            provider="github",
            provider_instance="api.github.com",
            repository_id="101",
            name_with_owner="acme/service",
            canonical_url=(
                "https://github.com/acme/service"
            ),
        ),
        github=GitHubPolicyConfiguration(
            organization="acme",
            workflow_repository_id=42,
            workflow_path=(
                ".github/workflows/blackduck.yml"
            ),
            workflow_ref="refs/heads/main",
            ruleset_name=(
                "Wintermute Black Duck SCA"
            ),
        ),
    )
    plan_path = write_plan(
        tmp_path / "plans",
        plan,
        registry,
        policy,
    )

    return load_verified_plan(plan_path)


def test_dry_run_does_not_apply(
    tmp_path: Path,
) -> None:
    selected = bundle(tmp_path)
    adapter = Adapter()
    result = execute_plan(
        selected,
        adapter,
        ExecutionOptions(),
    )

    assert result["status"] == "ok"
    assert result["outcome"] == "planned"
    assert result["writes"] == 0
    assert adapter.applied is False


def test_apply_requires_digest(
    tmp_path: Path,
) -> None:
    selected = bundle(tmp_path)

    with pytest.raises(
        ValueError,
        match="digest",
    ):
        execute_plan(
            selected,
            Adapter(),
            ExecutionOptions(
                mode="apply",
                confirm_apply=True,
            ),
        )


def test_apply_and_verify(
    tmp_path: Path,
) -> None:
    selected = bundle(tmp_path)
    adapter = Adapter()
    result = execute_plan(
        selected,
        adapter,
        ExecutionOptions(
            mode="apply",
            confirm_apply=True,
            expected_plan_digest=(
                selected.digest
            ),
            maximum_writes=1,
        ),
    )

    assert result["status"] == "ok"
    assert result["outcome"] == "applied"
    assert result["writes"] == 1


def test_budget_blocks_before_apply(
    tmp_path: Path,
) -> None:
    selected = bundle(tmp_path)
    adapter = Adapter()
    result = execute_plan(
        selected,
        adapter,
        ExecutionOptions(
            mode="apply",
            confirm_apply=True,
            expected_plan_digest=(
                selected.digest
            ),
            maximum_writes=0,
        ),
    )

    assert result["status"] == "blocked"
    assert result["outcome"] == (
        "budget-exhausted"
    )
    assert adapter.applied is False
