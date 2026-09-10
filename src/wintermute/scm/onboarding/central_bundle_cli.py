from __future__ import annotations

import argparse
import json
import sys

from wintermute.paths import output_root
from wintermute.scm.onboarding.central_bundle import (
    CentralBundleConfiguration,
    write_bundle,
)
from wintermute.scm.onboarding.template_artifacts import (
    TemplatePlanError,
    load_verified_template_plan,
)


def run(
    args: argparse.Namespace,
) -> int:
    template_plan = (
        load_verified_template_plan(
            args.template_plan
        )
    )
    directory = write_bundle(
        args.output_root,
        template_plan,
        CentralBundleConfiguration(
            image=args.image,
            bridge_sha256=(
                args.bridge_sha256
            ),
            github_repository=(
                args.github_repository
            ),
            github_ref=(
                args.github_ref
            ),
            github_checkout_action_sha=(
                args.github_checkout_action_sha
            ),
            github_runner=(
                args.github_runner
            ),
            gitlab_project=(
                args.gitlab_project
            ),
            gitlab_ref=(
                args.gitlab_ref
            ),
        ),
    )

    print(
        json.dumps(
            {
                "bundle_directory": (
                    str(directory)
                ),
                "status": "succeeded",
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
            "Render one scanner-neutral "
            "central workflow per SCM provider."
        )
    )
    parser.add_argument(
        "--template-plan",
        required=True,
    )
    parser.add_argument(
        "--output-root",
        default=str(
            output_root()
            / "scm"
            / "onboarding"
            / "central-bundles"
        ),
    )
    parser.add_argument(
        "--image",
        required=True,
    )
    parser.add_argument(
        "--bridge-sha256",
        required=True,
    )
    parser.add_argument(
        "--github-repository",
        default="",
    )
    parser.add_argument(
        "--github-ref",
        default="",
    )
    parser.add_argument(
        "--github-checkout-action-sha",
        default="",
    )
    parser.add_argument(
        "--github-runner",
        default="ubuntu-latest",
    )
    parser.add_argument(
        "--gitlab-project",
        default="",
    )
    parser.add_argument(
        "--gitlab-ref",
        default="main",
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
