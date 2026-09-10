from __future__ import annotations

import argparse
import json
import os
import sys

from wintermute.paths import output_root
from wintermute.scm.onboarding.central_planning import (
    GitHubCentralConfiguration,
    GitLabCentralConfiguration,
    build_provider_plan,
    write_provider_plan,
)
from wintermute.scm.onboarding.template_artifacts import (
    TemplatePlanError,
    load_verified_template_plan,
)


def default_output_root() -> str:
    return str(
        output_root()
        / "scm"
        / "onboarding"
        / "provider-plans"
    )


def github_configuration(
    args: argparse.Namespace,
) -> GitHubCentralConfiguration | None:
    if not args.github_organization:
        return None

    if (
        args.github_workflow_repository_id
        is None
    ):
        raise ValueError(
            "GitHub workflow repository ID "
            "is required"
        )

    return GitHubCentralConfiguration(
        organization=(
            args.github_organization
        ),
        workflow_repository_id=(
            args.github_workflow_repository_id
        ),
        workflow_path=(
            args.github_workflow_path
        ),
        workflow_ref=(
            args.github_workflow_ref
        ),
        ruleset_name=(
            args.github_ruleset_name
        ),
    )


def gitlab_configuration(
    args: argparse.Namespace,
) -> GitLabCentralConfiguration | None:
    if not args.gitlab_group:
        return None

    required = {
        "policy project": (
            args.gitlab_policy_project
        ),
        "template project": (
            args.gitlab_template_project
        ),
    }
    missing = [
        name
        for name, value in required.items()
        if not value
    ]

    if missing:
        raise ValueError(
            "Missing GitLab configuration: "
            + ", ".join(missing)
        )

    return GitLabCentralConfiguration(
        group=args.gitlab_group,
        policy_project=(
            args.gitlab_policy_project
        ),
        policy_file=(
            args.gitlab_policy_file
        ),
        template_project=(
            args.gitlab_template_project
        ),
        template_file=(
            args.gitlab_template_file
        ),
        template_ref=(
            args.gitlab_template_ref
        ),
        policy_name=(
            args.gitlab_policy_name
        ),
    )


def run(
    args: argparse.Namespace,
) -> int:
    template_plan = (
        load_verified_template_plan(
            args.template_plan
        )
    )
    (
        plan,
        github_payload,
        gitlab_payload,
        gitlab_yaml,
    ) = build_provider_plan(
        template_plan,
        github=github_configuration(args),
        gitlab=gitlab_configuration(args),
    )
    directory = write_provider_plan(
        args.output_root,
        plan,
        github_payload,
        gitlab_payload,
        gitlab_yaml,
    )

    print(
        json.dumps(
            {
                "plan_id": plan["plan_id"],
                "providers": plan["providers"],
                "repository_count": (
                    plan["repository_count"]
                ),
                "scan_contract_count": (
                    plan["scan_contract_count"]
                ),
                "review_repository_count": (
                    plan[
                        "review_repository_count"
                    ]
                ),
                "status": plan["status"],
                "mutation_allowed": (
                    plan["mutation_allowed"]
                ),
                "plan_directory": (
                    str(directory)
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )

    return 0


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate provider-specific plans "
            "from approved scan contracts."
        )
    )
    parser.add_argument(
        "--template-plan",
        required=True,
    )
    parser.add_argument(
        "--output-root",
        default=default_output_root(),
    )

    parser.add_argument(
        "--github-organization",
        default=os.getenv(
            "GITHUB_ORG",
            "",
        ),
    )
    parser.add_argument(
        "--github-workflow-repository-id",
        type=int,
    )
    parser.add_argument(
        "--github-workflow-path",
        default=(
            ".github/workflows/"
            "blackduck.yml"
        ),
    )
    parser.add_argument(
        "--github-workflow-ref",
        default="refs/heads/main",
    )
    parser.add_argument(
        "--github-ruleset-name",
        default=(
            "Wintermute Black Duck SCA"
        ),
    )

    parser.add_argument(
        "--gitlab-group",
        default=os.getenv(
            "GITLAB_GROUP",
            "",
        ),
    )
    parser.add_argument(
        "--gitlab-policy-project",
        default=os.getenv(
            "GITLAB_POLICY_PROJECT",
            "",
        ),
    )
    parser.add_argument(
        "--gitlab-policy-file",
        default=(
            ".gitlab/security-policies/"
            "policy.yml"
        ),
    )
    parser.add_argument(
        "--gitlab-template-project",
        default=os.getenv(
            "GITLAB_TEMPLATE_PROJECT",
            "",
        ),
    )
    parser.add_argument(
        "--gitlab-template-file",
        default="blackduck.yml",
    )
    parser.add_argument(
        "--gitlab-template-ref",
        default="main",
    )
    parser.add_argument(
        "--gitlab-policy-name",
        default=(
            "Wintermute Black Duck SCA"
        ),
    )

    return parser.parse_args(argv)


def main(
    argv: list[str] | None = None,
) -> int:
    try:
        return run(parse_args(argv))
    except KeyboardInterrupt:
        return 130
    except (
        OSError,
        RuntimeError,
        TemplatePlanError,
        ValueError,
    ) as error:
        print(
            f"ERROR: {error}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
