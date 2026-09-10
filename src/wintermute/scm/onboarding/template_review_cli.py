from __future__ import annotations

import argparse
import json
import sys

from wintermute.paths import output_root
from wintermute.scm.onboarding.template_artifacts import (
    TemplatePlanError,
    load_verified_template_plan,
)
from wintermute.scm.onboarding.template_review import (
    APPROVAL_CONFIRMATION,
    review_template_plan,
    write_reviewed_template_plan,
)


def default_output_root() -> str:
    return str(
        output_root()
        / "scm"
        / "onboarding"
        / "template-plans"
    )


def run(
    args: argparse.Namespace,
) -> int:
    source = load_verified_template_plan(
        args.template_plan
    )
    (
        plan,
        catalog,
        contracts,
        assignments,
    ) = review_template_plan(
        source,
        repository_external_id=(
            args.repository_external_id
        ),
        expected_analysis_digest=(
            args.expected_analysis_digest
        ),
        expected_contract_id=(
            args.expected_contract_id
        ),
        reviewer=args.reviewer,
        justification=args.justification,
        confirmation=args.confirmation,
        minimum_reviewed_confidence=(
            args.minimum_reviewed_confidence
        ),
    )
    directory = write_reviewed_template_plan(
        args.output_root,
        plan,
        catalog,
        contracts,
        assignments,
    )
    approval = plan[
        "review_approvals"
    ][-1]

    print(
        json.dumps(
            {
                "plan_id": plan["plan_id"],
                "plan_directory": str(directory),
                "source_template_plan_id": (
                    plan[
                        "source_template_plan_id"
                    ]
                ),
                "source_template_plan_digest": (
                    plan[
                        "source_template_plan_digest"
                    ]
                ),
                "repository_external_id": (
                    approval[
                        "repository_external_id"
                    ]
                ),
                "name_with_owner": (
                    approval["name_with_owner"]
                ),
                "scan_contract_id": (
                    approval["scan_contract_id"]
                ),
                "approval_id": (
                    approval["approval_id"]
                ),
                "approval_digest": (
                    approval["approval_digest"]
                ),
                "reviewer": (
                    approval["reviewer"]
                ),
                "required_count": (
                    plan["required_count"]
                ),
                "review_count": (
                    plan["review_count"]
                ),
                "status": plan["status"],
                "mutation_allowed": (
                    plan["mutation_allowed"]
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
            "Promote one review-only scan contract "
            "through an explicit checksum-bound "
            "human approval."
        )
    )
    parser.add_argument(
        "--template-plan",
        required=True,
    )
    parser.add_argument(
        "--repository-external-id",
        required=True,
    )
    parser.add_argument(
        "--expected-analysis-digest",
        required=True,
    )
    parser.add_argument(
        "--expected-contract-id",
        required=True,
    )
    parser.add_argument(
        "--reviewer",
        required=True,
    )
    parser.add_argument(
        "--justification",
        required=True,
    )
    parser.add_argument(
        "--confirmation",
        required=True,
        help=(
            "Must exactly equal "
            f"{APPROVAL_CONFIRMATION}"
        ),
    )
    parser.add_argument(
        "--minimum-reviewed-confidence",
        type=float,
        default=0.7,
    )
    parser.add_argument(
        "--output-root",
        default=default_output_root(),
    )
    args = parser.parse_args(argv)

    if not (
        0
        <= args.minimum_reviewed_confidence
        <= 1
    ):
        parser.error(
            "--minimum-reviewed-confidence must "
            "be between 0 and 1"
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
