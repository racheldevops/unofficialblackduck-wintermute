from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from wintermute.paths import output_root
from wintermute.scm.onboarding.template_artifacts import (
    LoadedTemplatePlan,
    TemplatePlanError,
    load_verified_template_plan,
)
from wintermute.scm.onboarding.template_merge import (
    merge_template_plans,
    write_merged_template_plan,
)


def default_plan_root() -> Path:
    return (
        output_root()
        / "scm"
        / "onboarding"
        / "template-plans"
    )


def latest_plan_for_batch(
    root: Path,
    source_batch_id: str,
) -> LoadedTemplatePlan:
    selected_batch_id = str(
        source_batch_id or ""
    ).strip()

    if not selected_batch_id:
        raise ValueError(
            "Source batch ID must not be empty"
        )

    if not root.is_dir():
        raise ValueError(
            "Template-plan root does not exist: "
            f"{root}"
        )

    candidates: list[
        LoadedTemplatePlan
    ] = []
    errors: list[str] = []

    for path in sorted(
        root.iterdir(),
        key=lambda value: value.name,
        reverse=True,
    ):
        if (
            not path.is_dir()
            or not (
                path / "READY"
            ).is_file()
        ):
            continue

        try:
            loaded = (
                load_verified_template_plan(
                    path
                )
            )
        except Exception as error:
            errors.append(
                f"{path.name}: {error}"
            )
            continue

        if (
            str(
                loaded.plan.get(
                    "source_batch_id"
                )
                or ""
            )
            == selected_batch_id
        ):
            candidates.append(loaded)

    if not candidates:
        detail = (
            "; ".join(errors[:3])
            if errors
            else "no matching verified plans"
        )
        raise ValueError(
            "No verified template plan was found "
            f"for source batch {selected_batch_id}: "
            f"{detail}"
        )

    candidates.sort(
        key=lambda loaded: (
            str(
                loaded.plan.get(
                    "created_at"
                )
                or ""
            ),
            str(
                loaded.plan.get(
                    "plan_id"
                )
                or ""
            ),
        ),
        reverse=True,
    )

    return candidates[0]


def selected_sources(
    args: argparse.Namespace,
) -> tuple[LoadedTemplatePlan, ...]:
    root = Path(
        args.template_plan_root
    ).expanduser()
    values: list[
        LoadedTemplatePlan
    ] = [
        load_verified_template_plan(
            value
        )
        for value in args.template_plan
    ]

    values.extend(
        latest_plan_for_batch(
            root,
            batch_id,
        )
        for batch_id
        in args.source_batch_id
    )
    by_digest: dict[
        str,
        LoadedTemplatePlan,
    ] = {}

    for value in values:
        by_digest.setdefault(
            value.digest,
            value,
        )

    selected = tuple(
        sorted(
            by_digest.values(),
            key=lambda loaded: (
                str(
                    loaded.plan.get(
                        "plan_id"
                    )
                    or ""
                ),
                loaded.digest,
            ),
        )
    )

    if len(selected) < 2:
        raise ValueError(
            "Select at least two distinct verified "
            "template plans"
        )

    return selected


def require_expected_count(
    name: str,
    expected: int | None,
    actual: int,
) -> None:
    if (
        expected is not None
        and expected != actual
    ):
        raise ValueError(
            f"{name} count mismatch: "
            f"expected {expected}, received {actual}"
        )


def run(
    args: argparse.Namespace,
) -> int:
    sources = selected_sources(args)
    (
        plan,
        catalog,
        contracts,
        assignments,
    ) = merge_template_plans(
        sources
    )

    require_expected_count(
        "source plan",
        args.expected_source_count,
        plan[
            "source_template_plan_count"
        ],
    )
    require_expected_count(
        "repository",
        args.expected_repository_count,
        plan["repository_count"],
    )
    require_expected_count(
        "required repository",
        args.expected_required_count,
        plan["required_count"],
    )
    require_expected_count(
        "review repository",
        args.expected_review_count,
        plan["review_count"],
    )

    directory = write_merged_template_plan(
        args.output_root,
        plan,
        catalog,
        contracts,
        assignments,
    )
    loaded = load_verified_template_plan(
        directory
    )

    print(
        json.dumps(
            {
                "plan_id": (
                    loaded.plan["plan_id"]
                ),
                "plan_digest": loaded.digest,
                "plan_directory": str(
                    directory
                ),
                "source_template_plan_count": (
                    plan[
                        "source_template_plan_count"
                    ]
                ),
                "source_template_plans": (
                    plan[
                        "source_template_plans"
                    ]
                ),
                "repository_count": (
                    plan["repository_count"]
                ),
                "scan_contract_count": (
                    plan[
                        "scan_contract_count"
                    ]
                ),
                "required_count": (
                    plan["required_count"]
                ),
                "review_count": (
                    plan["review_count"]
                ),
                "reviewed_approval_count": (
                    plan[
                        "reviewed_approval_count"
                    ]
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


def optional_count(
    parser: argparse.ArgumentParser,
    name: str,
) -> None:
    parser.add_argument(
        name,
        type=int,
    )


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Deterministically merge several verified "
            "scan-template plans."
        )
    )
    parser.add_argument(
        "--template-plan",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--source-batch-id",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--template-plan-root",
        default=str(
            default_plan_root()
        ),
    )
    parser.add_argument(
        "--output-root",
        default=str(
            default_plan_root()
        ),
    )
    optional_count(
        parser,
        "--expected-source-count",
    )
    optional_count(
        parser,
        "--expected-repository-count",
    )
    optional_count(
        parser,
        "--expected-required-count",
    )
    optional_count(
        parser,
        "--expected-review-count",
    )
    args = parser.parse_args(argv)

    if (
        not args.template_plan
        and not args.source_batch_id
    ):
        parser.error(
            "Supply --template-plan or "
            "--source-batch-id at least twice"
        )

    for name in (
        "expected_source_count",
        "expected_repository_count",
        "expected_required_count",
        "expected_review_count",
    ):
        value = getattr(args, name)

        if value is not None and value < 0:
            parser.error(
                f"--{name.replace('_', '-')} "
                "cannot be negative"
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
