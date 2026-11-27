from __future__ import annotations

import json
from pathlib import Path

import pytest

from wintermute.ai.artifacts import (
    AnalysisArtifactError,
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
from wintermute.scm.onboarding.planning import (
    GitHubPolicyConfiguration,
    GitLabPolicyConfiguration,
    RepositoryTarget,
    build_plan,
    write_plan,
)


def analysis_directory(
    tmp_path: Path,
) -> Path:
    result = AnalysisResult(
        analysis_id=(
            "20260828T120000Z-"
            "scm-scan-profile-example"
        ),
        task="scm.scan-profile",
        task_version="1",
        provider="vllm",
        model="example",
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
                "detector_search_depth": 3,
            },
            "confidence": 0.9,
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
                usage=ModelUsage(
                    input_tokens=100,
                    output_tokens=50,
                ),
                estimated_cost_usd=0,
                latency_seconds=1,
            ),
        ),
        created_at="2026-08-28T12:00:00Z",
    )

    return write_analysis(
        tmp_path / "analyses",
        result,
        evidence_catalog=[
            {
                "evidence_id": "ev-one",
                "safe_path": "pyproject.toml",
                "relative_path": (
                    "pyproject.toml"
                ),
                "kind": "build",
                "digest": (
                    "sha256:" + "c" * 64
                ),
            }
        ],
    )


def github_target() -> RepositoryTarget:
    return RepositoryTarget(
        provider="github",
        provider_instance="github.example",
        repository_id="101",
        name_with_owner="acme/service",
        canonical_url=(
            "https://github.example/acme/service"
        ),
    )


def gitlab_target() -> RepositoryTarget:
    return RepositoryTarget(
        provider="gitlab",
        provider_instance="gitlab.example",
        repository_id="202",
        name_with_owner=(
            "group/subgroup/service"
        ),
        canonical_url=(
            "https://gitlab.example/"
            "group/subgroup/service"
        ),
    )


def test_analysis_artifact_round_trip(
    tmp_path: Path,
) -> None:
    loaded = load_verified_analysis(
        analysis_directory(tmp_path)
    )

    assert loaded.analysis[
        "task"
    ] == "scm.scan-profile"
    assert (
        loaded.analysis["result"][
            "central_template"
        ]
        == "python"
    )


def test_modified_analysis_is_rejected(
    tmp_path: Path,
) -> None:
    directory = analysis_directory(
        tmp_path
    )
    path = directory / "analysis.json"
    payload = json.loads(
        path.read_text(encoding="utf-8")
    )
    payload["model"] = "changed"
    path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    with pytest.raises(
        AnalysisArtifactError,
        match="Checksum mismatch",
    ):
        load_verified_analysis(directory)


def test_github_plan_is_staged(
    tmp_path: Path,
) -> None:
    analysis = load_verified_analysis(
        analysis_directory(tmp_path)
    )
    plan, registry, policy = build_plan(
        analysis,
        github_target(),
        github=GitHubPolicyConfiguration(
            organization="acme",
            workflow_repository_id=42,
            workflow_path=(
                ".github/workflows/"
                "blackduck.yml"
            ),
            workflow_ref=(
                "refs/heads/main"
            ),
            ruleset_name=(
                "Wintermute Black Duck SCA"
            ),
        ),
    )

    assert plan["mutation_allowed"] is False
    assert plan["status"] == (
        "review-required"
    )
    assert policy["enforcement"] == (
        "evaluate"
    )
    assert policy["bypass_actors"] == []
    assert (
        registry["scan_profile"][
            "central_template"
        ]
        == "python"
    )

    directory = write_plan(
        tmp_path / "plans",
        plan,
        registry,
        policy,
    )

    assert (
        directory / "provider-policy.json"
    ).is_file()
    assert (
        directory / "checksums.json"
    ).is_file()
    assert (
        directory / "READY"
    ).is_file()


def test_gitlab_policy_is_disabled(
    tmp_path: Path,
) -> None:
    analysis = load_verified_analysis(
        analysis_directory(tmp_path)
    )
    plan, registry, policy = build_plan(
        analysis,
        gitlab_target(),
        gitlab=GitLabPolicyConfiguration(
            group="group/subgroup",
            policy_project=(
                "security/policies"
            ),
            policy_file=(
                ".gitlab/security-policies/"
                "policy.yml"
            ),
            template_project=(
                "security/templates"
            ),
            template_file=(
                "blackduck.yml"
            ),
            template_ref="main",
            policy_name=(
                "Wintermute Black Duck SCA"
            ),
        ),
    )

    assert isinstance(policy, str)
    assert "enabled: false" in policy
    assert (
        "pipeline_config_strategy: "
        "inject_policy"
        in policy
    )
    assert (
        "security/templates"
        in policy
    )
    assert plan["mutation_allowed"] is False
    assert (
        registry["repository"][
            "repository_id"
        ]
        == "202"
    )
