from __future__ import annotations

from pathlib import Path

from wintermute.scm.onboarding.central_planning import (
    GitHubCentralConfiguration,
    GitLabCentralConfiguration,
    build_provider_plan,
)
from wintermute.scm.onboarding.template_artifacts import (
    LoadedTemplatePlan,
)


def template_plan(
    tmp_path: Path,
) -> LoadedTemplatePlan:
    return LoadedTemplatePlan(
        directory=tmp_path,
        plan={
            "plan_id": "template-one",
            "required_count": 2,
            "review_count": 1,
        },
        catalog={},
        contracts={
            "contracts": [
                {
                    "scan_contract_id": (
                        "scan-python"
                    ),
                    "contract": {
                        "template_id": (
                            "python-detect"
                        ),
                    },
                }
            ]
        },
        assignments={
            "assignments": [
                {
                    "repository_external_id": (
                        "github-one"
                    ),
                    "provider": "github",
                    "provider_instance": (
                        "api.github.com"
                    ),
                    "repository_id": "101",
                    "name_with_owner": (
                        "acme/service"
                    ),
                    "scan_contract_id": (
                        "scan-python"
                    ),
                    "onboarding_policy": (
                        "required"
                    ),
                },
                {
                    "repository_external_id": (
                        "gitlab-one"
                    ),
                    "provider": "gitlab",
                    "provider_instance": (
                        "gitlab.example"
                    ),
                    "repository_id": "202",
                    "name_with_owner": (
                        "group/service"
                    ),
                    "scan_contract_id": (
                        "scan-python"
                    ),
                    "onboarding_policy": (
                        "required"
                    ),
                },
                {
                    "repository_external_id": (
                        "gitlab-review"
                    ),
                    "provider": "gitlab",
                    "provider_instance": (
                        "gitlab.example"
                    ),
                    "repository_id": "203",
                    "name_with_owner": (
                        "group/review"
                    ),
                    "scan_contract_id": (
                        "scan-python"
                    ),
                    "onboarding_policy": (
                        "review"
                    ),
                },
            ]
        },
        digest="sha256:" + "a" * 64,
    )


def test_only_required_repositories_are_planned(
    tmp_path: Path,
) -> None:
    (
        plan,
        github,
        gitlab,
        gitlab_yaml,
    ) = build_provider_plan(
        template_plan(tmp_path),
        github=GitHubCentralConfiguration(
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
        gitlab=GitLabCentralConfiguration(
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

    assert plan["repository_count"] == 2
    assert plan[
        "review_repository_count"
    ] == 1
    assert github is not None
    assert gitlab is not None
    assert len(
        github["assignments"]
    ) == 1
    assert len(
        gitlab["assignments"]
    ) == 1
    assert (
        gitlab["assignments"][0][
            "repository_id"
        ]
        == "202"
    )
    assert gitlab_yaml is not None
    assert "id: 202" in gitlab_yaml
    assert "id: 203" not in gitlab_yaml


def test_provider_plans_remain_staged(
    tmp_path: Path,
) -> None:
    (
        _,
        github,
        gitlab,
        gitlab_yaml,
    ) = build_provider_plan(
        template_plan(tmp_path),
        github=GitHubCentralConfiguration(
            organization="acme",
            workflow_repository_id=42,
            workflow_path=(
                ".github/workflows/"
                "blackduck.yml"
            ),
            workflow_ref=(
                "refs/heads/main"
            ),
            ruleset_name="Ruleset",
        ),
        gitlab=GitLabCentralConfiguration(
            group="group",
            policy_project="security/policies",
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
            policy_name="Policy",
        ),
    )

    assert github is not None
    assert github["stage"] == "evaluate"
    assert github[
        "mutation_allowed"
    ] is False
    assert github["ruleset"][
        "enforcement"
    ] == "evaluate"
    assert gitlab is not None
    assert gitlab["stage"] == "disabled"
    assert gitlab[
        "mutation_allowed"
    ] is False
    assert gitlab_yaml is not None
    assert "enabled: false" in gitlab_yaml
