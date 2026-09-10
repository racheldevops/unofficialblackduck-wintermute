from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from wintermute.ai.batch_artifacts import (
    BatchArtifactError,
    load_verified_profile_batch,
)
from wintermute.paths import output_root
from wintermute.scm.onboarding.consolidation import (
    consolidate_batch,
    write_consolidation_plan,
)


def default_output_root() -> str:
    return str(
        output_root()
        / "scm"
        / "onboarding"
        / "template-plans"
    )


def latest_batch() -> Path:
    root = (
        output_root()
        / "ai"
        / "batches"
    )

    if not root.is_dir():
        raise ValueError(
            "No AI batch directory exists"
        )

    candidates = sorted(
        (
            path
            for path in root.iterdir()
            if (
                path.is_dir()
                and (path / "READY").is_file()
            )
        ),
        key=lambda path: path.name,
        reverse=True,
    )

    if not candidates:
        raise ValueError(
            "No ready AI batches exist"
        )

    return candidates[0]


def run(
    args: argparse.Namespace,
) -> int:
    batch_path = (
        Path(args.batch)
        if args.batch
        else latest_batch()
    )
    batch = load_verified_profile_batch(
        batch_path
    )
    (
        plan,
        contracts,
        assignments,
    ) = consolidate_batch(
        batch,
        minimum_confidence=(
            args.minimum_confidence
        ),
    )
    directory = write_consolidation_plan(
        args.output_root,
        plan,
        contracts,
        assignments,
    )

    print(
        json.dumps(
            {
                "plan_id": plan["plan_id"],
                "source_batch_id": (
                    plan["source_batch_id"]
                ),
                "repository_count": (
                    plan["repository_count"]
                ),
                "source_profile_group_count": (
                    plan[
                        "source_profile_group_count"
                    ]
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
                "status": plan["status"],
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
            "Consolidate AI scan profiles into "
            "approved central scanner contracts."
        )
    )
    parser.add_argument(
        "--batch",
        default="",
    )
    parser.add_argument(
        "--output-root",
        default=default_output_root(),
    )
    parser.add_argument(
        "--minimum-confidence",
        type=float,
        default=0.8,
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
