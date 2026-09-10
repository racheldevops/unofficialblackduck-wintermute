from __future__ import annotations

from pathlib import Path

from wintermute.ai.batch import (
    write_batch,
)
from wintermute.ai.batch_artifacts import (
    load_verified_profile_batch,
)
from wintermute.scm.onboarding.batch_planning import (
    build_batch_plan,
    write_batch_plan,
)
from wintermute.scm.onboarding.planning import (
    GitHubPolicyConfiguration,
    GitLabPolicyConfiguration,
)


def profile_entry(
    provider: str,
    external_id: str,
    name: str,
    *,
    confidence: float = 0.9,
    conflicts: list[str] | None = None,
) -> dict:
    instance = (
        "api.github.com"
        if provider == "github"
        else "gitlab.example"
    )
    canonical_host = (
        "github.com"
        if provider == "github"
        else instance
    )

    return {
        "repository": {
            "provider": provider,
            "provider_instance": instance,
            "tenant_id": (
                f"tenant-{provider}"
            ),
            "repository_id": external_id,
            "external_id": external_id,
            "namespace": (
                "acme"
                if provider == "github"
                else "group"
            ),
            "name": name,
            "name_with_owner": (
                f"acme/{name}"
                if provider == "github"
                else f"group/{name}"
            ),
            "canonical_url": (
                f"https://{canonical_host}/"
                + (
                    f"acme/{name}"
                    if provider == "github"
                    else f"group/{name}"
                )
            ),
        },
        "source_snapshot_id": (
            f"snapshot-{provider}"
        ),
        "analysis_id": (
            f"analysis-{provider}-{name}"
        ),
        "analysis_digest": (
            "sha256:" + external_id * 64
        )[:71],
        "analysis_directory": (
            f"/analyses/{external_id}"
        ),
        "scan_profile": {
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
            "confidence": confidence,
            "evidence_ids": [
                f"ev-{external_id}"
            ],
            "conflicts": (
                conflicts or []
            ),
            "unresolved_questions": [],
        },
        "reused": False,
        "profile_group_key": (
            "sha256:" + "a" * 64
        ),
    }


def batch_directory(
    tmp_path: Path,
) -> Path:
    profiles = [
        profile_entry(
            "github",
            "1",
            "service",
        ),
        profile_entry(
            "gitlab",
            "2",
            "service",
        ),
        profile_entry(
            "gitlab",
            "3",
            "review",
            confidence=0.4,
        ),
    ]
    registry = {
        "schema_version": 1,
        "profile_count": 3,
        "profile_group_count": 1,
        "profiles": profiles,
        "groups": [
            {
                "profile_group_key": (
                    "sha256:" + "a" * 64
                ),
                "repository_external_ids": [
                    "1",
                    "2",
                    "3",
                ],
            }
        ],
    }
    summary = {
        "schema_version": 1,
        "batch_id": "batch-one",
        "status": "succeeded",
        "profile_count": 3,
        "failure_count": 0,
    }

    return write_batch(
        tmp_path / "batches",
        "batch-one",
        registry,
        [],
        summary,
    )


def test_verified_batch_round_trip(
    tmp_path: Path,
) -> None:
    batch = (
        load_verified_profile_batch(
            batch_directory(tmp_path)
        )
    )

    assert batch.batch_id == "batch-one"
    assert (
        batch.registry["profile_count"]
        == 3
    )


def test_builds_both_provider_plans(
    tmp_path: Path,
) -> None:
    batch = (
        load_verified_profile_batch(
            batch_directory(tmp_path)
        )
    )
    (
        plan,
        registry,
        github_plan,
        github_ruleset,
        gitlab_plan,
        gitlab_policy,
    ) = build_batch_plan(
        batch,
        minimum_confidence=0.8,
        github=GitHubPolicyConfiguration(
            organization="acme",
            workflow_repository_id=42,
            workflow_path=(
                ".github/workflows/"
                "blackduck.yml"
            ),
            workflow_ref="refs/heads/main",
            ruleset_name=(
                "Wintermute Black Duck SCA"
            ),
        ),
        gitlab=GitLabPolicyConfiguration(
            group="group",
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

    assert plan["mutation_allowed"] is False
    assert plan["providers"] == [
        "github",
        "gitlab",
    ]
    assert plan["required_count"] == 2
    assert plan["review_count"] == 1
    assert registry["profile_count"] == 1
    assert (
        github_plan["stage"]
        == "evaluate"
    )
    assert (
        github_ruleset["enforcement"]
        == "evaluate"
    )
    assert (
        gitlab_plan["stage"]
        == "disabled"
    )
    assert "enabled: false" in gitlab_policy

    directory = write_batch_plan(
        tmp_path / "plans",
        plan,
        registry,
        github_plan,
        github_ruleset,
        gitlab_plan,
        gitlab_policy,
    )

    for name in (
        "plan.json",
        "scan-profile-registry.json",
        "github-plan.json",
        "github-ruleset.json",
        "gitlab-plan.json",
        "gitlab-policy.yml",
        "checksums.json",
        "READY",
    ):
        assert (
            directory / name
        ).is_file()


def test_conflict_requires_review(
    tmp_path: Path,
) -> None:
    directory = batch_directory(
        tmp_path
    )
    batch = (
        load_verified_profile_batch(
            directory
        )
    )
    batch.registry["profiles"][0][
        "scan_profile"
    ]["conflicts"] = [
        "ambiguous build system"
    ]
    _, registry, *_ = (
        build_batch_plan(
            batch,
            minimum_confidence=0.8,
            github=(
                GitHubPolicyConfiguration(
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
                        "Wintermute "
                        "Black Duck SCA"
                    ),
                )
            ),
            gitlab=(
                GitLabPolicyConfiguration(
                    group="group",
                    policy_project=(
                        "security/policies"
                    ),
                    policy_file=(
                        ".gitlab/"
                        "security-policies/"
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
                        "Wintermute "
                        "Black Duck SCA"
                    ),
                )
            ),
        )
    )

    github_assignment = next(
        value
        for value
        in registry["assignments"]
        if value["provider"] == "github"
    )

    assert (
        github_assignment["policy"]
        == "review"
    )
    assert (
        "profile-conflicts"
        in github_assignment[
            "review_reasons"
        ]
    )
