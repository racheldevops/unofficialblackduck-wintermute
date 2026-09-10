from __future__ import annotations

from pathlib import Path

import pytest

from wintermute.ai.batch_artifacts import (
    LoadedProfileBatch,
)
from wintermute.scm.onboarding.consolidation import (
    consolidate_batch,
)
from wintermute.scm.onboarding.templates import (
    template_contract,
)


def profile(
    external_id: str,
    *,
    confidence: float = 0.9,
    layout: str = "single-project",
    conflicts: list[str] | None = None,
) -> dict:
    return {
        "repository": {
            "provider": "gitlab",
            "provider_instance": (
                "gitlab.example"
            ),
            "repository_id": external_id,
            "external_id": external_id,
            "name_with_owner": (
                f"group/{external_id}"
            ),
            "canonical_url": (
                "https://gitlab.example/"
                f"group/{external_id}"
            ),
        },
        "analysis_id": (
            f"analysis-{external_id}"
        ),
        "analysis_digest": (
            "sha256:" + "a" * 64
        ),
        "profile_group_key": (
            "sha256:" + external_id * 64
        )[:71],
        "scan_profile": {
            "languages": ["python"],
            "build_systems": ["python"],
            "package_managers": ["pip"],
            "layout": layout,
            "scan_mode": "detector",
            "central_template": "python",
            "parameters": {
                "buildless": True,
                "detector_search_depth": 2,
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
    }


def batch(
    *profiles: dict,
    deferred: int = 0,
) -> LoadedProfileBatch:
    return LoadedProfileBatch(
        directory=Path("/batch"),
        batch_id="batch-one",
        registry={
            "profile_count": len(profiles),
            "profile_group_count": (
                len(profiles)
            ),
            "profiles": list(profiles),
            "groups": [],
        },
        failures=(),
        summary={
            "selected_repository_count": (
                len(profiles) + deferred
            ),
            "profile_count": len(profiles),
            "failure_count": 0,
            "deferred_repository_count": (
                deferred
            ),
        },
        digest="sha256:" + "b" * 64,
    )


def test_same_execution_contract_is_consolidated() -> None:
    plan, contracts, assignments = (
        consolidate_batch(
            batch(
                profile("one"),
                profile("two"),
            )
        )
    )

    assert plan[
        "source_profile_group_count"
    ] == 2
    assert plan[
        "scan_contract_count"
    ] == 1
    assert contracts[
        "scan_contract_count"
    ] == 1
    assert {
        value["scan_contract_id"]
        for value
        in assignments["assignments"]
    } == {
        contracts["contracts"][0][
            "scan_contract_id"
        ]
    }


def test_monorepo_uses_deeper_scan() -> None:
    contract, reasons = (
        template_contract(
            profile(
                "one",
                layout="monorepo",
            )["scan_profile"]
        )
    )

    assert reasons == ()
    assert contract is not None
    assert contract[
        "runtime_parameters"
    ][
        "detector_search_depth"
    ] == 10


def test_conflict_requires_review() -> None:
    plan, _, assignments = (
        consolidate_batch(
            batch(
                profile(
                    "one",
                    conflicts=[
                        "ambiguous build"
                    ],
                )
            )
        )
    )

    assert plan["required_count"] == 0
    assert plan["review_count"] == 1
    assert assignments[
        "assignments"
    ][0][
        "onboarding_policy"
    ] == "review"


def test_incomplete_batch_is_rejected() -> None:
    with pytest.raises(
        ValueError,
        match="deferred",
    ):
        consolidate_batch(
            batch(
                profile("one"),
                deferred=1,
            )
        )
