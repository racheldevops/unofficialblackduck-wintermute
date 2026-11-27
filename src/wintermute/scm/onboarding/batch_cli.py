from __future__ import annotations

import argparse
import json
import sys

from wintermute.ai.batch_artifacts import (
    BatchArtifactError,
    load_verified_profile_batch,
)
from wintermute.paths import output_root
from wintermute.scm.onboarding.batch_planning import (
    build_batch_plan,
    write_batch_plan,
)
from wintermute.scm.onboarding.planning import (
    GitHubPolicyConfiguration,
    GitLabPolicyConfiguration,
)


def default_plan_root() -> str:
    return str(
        output_root()
        / "scm"
        / "onboarding"
        / "batch-plans"
    )


def github_configuration(
    args: argparse.Namespace,
) -> GitHubPolicyConfiguration | None:
    supplied = any(
        (
            args.github_organization,
            args.github_workflow_repository_id,
        )
    )

    if not supplied:
        return None

    if (
        not args.github_organization
        or args.github_workflow_repository_id
        is None
    ):
        raise ValueError(
            "GitHub batch planning requires "
            "organization and workflow "
            "repository ID"
        )

    return GitHubPolicyConfiguration(
        organization=(
            args.github_organization
        ),
        workflow_repository_id=(
            args
            .github_workflow_repository_id
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
        property_name=(
            args.github_property_name
        ),
        property_value="required",
    )


def gitlab_configuration(
    args: argparse.Namespace,
) -> GitLabPolicyConfiguration | None:
    supplied = any(
        (
            args.gitlab_group,
            args.gitlab_policy_project,
            args.gitlab_template_project,
        )
    )

    if not supplied:
        return None

    required = {
        "group": args.gitlab_group,
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
            "Missing GitLab batch-planning "
            "value(s): "
            + ", ".join(missing)
        )

    return GitLabPolicyConfiguration(
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
    batch = load_verified_profile_batch(
        args.batch,
        allow_failures=(
            args.allow_partial_batch
        ),
    )
    (
        plan,
        registry,
        github_payload,
        github_policy,
        gitlab_payload,
        gitlab_policy,
    ) = build_batch_plan(
        batch,
        minimum_confidence=(
            args.minimum_confidence
        ),
        github=github_configuration(args),
        gitlab=gitlab_configuration(args),
    )
    directory = write_batch_plan(
        args.output_root,
        plan,
        registry,
        github_payload,
        github_policy,
        gitlab_payload,
        gitlab_policy,
    )

    print(
        json.dumps(
            {
                "plan_id": plan["plan_id"],
                "status": plan["status"],
                "mutation_allowed": (
                    plan["mutation_allowed"]
                ),
                "providers": plan["providers"],
                "repository_count": (
                    plan["repository_count"]
                ),
                "profile_count": (
                    plan["profile_count"]
                ),
                "required_count": (
                    plan["required_count"]
                ),
                "review_count": (
                    plan["review_count"]
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
            "Create reviewed central GitHub and "
            "GitLab onboarding plans from an "
            "AI scan-profile batch."
        )
    )
    parser.add_argument(
        "--batch",
        required=True,
    )
    parser.add_argument(
        "--output-root",
        default=default_plan_root(),
    )
    parser.add_argument(
        "--minimum-confidence",
        type=float,
        default=0.8,
    )
    parser.add_argument(
        "--allow-partial-batch",
        action="store_true",
    )

    parser.add_argument(
        "--github-organization",
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
        "--github-property-name",
        default="blackduck_sca_policy",
    )

    parser.add_argument(
        "--gitlab-group",
    )
    parser.add_argument(
        "--gitlab-policy-project",
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
    args = parser.parse_args(argv)

    if not 0 <= args.minimum_confidence <= 1:
        parser.error(
            "--minimum-confidence must be "
            "between 0 and 1"
        )

    return args


def main(
    argv: list[str] | None = None,
) -> int:
    try:
        return run(parse_args(argv))
    except KeyboardInterrupt:
        return 130
    except (
        BatchArtifactError,
        OSError,
        RuntimeError,
        ValueError,
    ) as error:
        print(
            f"ERROR: {error}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
