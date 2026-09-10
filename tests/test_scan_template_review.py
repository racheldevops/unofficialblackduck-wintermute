from __future__ import annotations

from pathlib import Path

import pytest

from wintermute.scm.onboarding.template_artifacts import (
    LoadedTemplatePlan,
    load_verified_template_plan,
)
from wintermute.scm.onboarding.template_review import (
    APPROVAL_CONFIRMATION,
    review_template_plan,
    write_reviewed_template_plan,
)


REPOSITORY_ID = "repository-one"
ANALYSIS_DIGEST = (
    "sha256:" + "a" * 64
)
CONTRACT_ID = "scan-python"


def source_plan(
    tmp_path: Path,
    *,
    confidence: float = 0.74,
    review_reasons: list[str] | None = None,
    blocking_issues: list[str] | None = None,
) -> LoadedTemplatePlan:
    return LoadedTemplatePlan(
        directory=tmp_path,
        plan={
            "schema_version": 1,
            "plan_id": "source-plan",
            "created_at": (
                "2026-09-07T00:00:00Z"
            ),
            "status": "review-required",
            "mutation_allowed": False,
            "source_batch_id": "batch-one",
            "source_batch_digest": (
                "sha256:" + "b" * 64
            ),
            "minimum_confidence": 0.8,
            "repository_count": 1,
            "source_profile_group_count": 1,
            "scan_contract_count": 1,
            "required_count": 0,
            "review_count": 1,
        },
        catalog={
            "schema_version": 1,
            "templates": [],
        },
        contracts={
            "schema_version": 1,
            "source_batch_id": "batch-one",
            "scan_contract_count": 1,
            "contracts": [
                {
                    "scan_contract_id": (
                        CONTRACT_ID
                    ),
                    "contract": {
                        "schema_version": 1,
                        "engine": "bridge",
                    },
                }
            ],
        },
        assignments={
            "schema_version": 1,
            "source_batch_id": "batch-one",
            "assignment_count": 1,
            "assignments": [
                {
                    "repository_external_id": (
                        REPOSITORY_ID
                    ),
                    "provider": "gitlab",
                    "provider_instance": (
                        "gitlab.example"
                    ),
                    "repository_id": "10682",
                    "name_with_owner": (
                        "rhorner/service"
                    ),
                    "analysis_id": (
                        "analysis-one"
                    ),
                    "analysis_digest": (
                        ANALYSIS_DIGEST
                    ),
                    "source_profile_group_key": (
                        "sha256:" + "c" * 64
                    ),
                    "scan_contract_id": (
                        CONTRACT_ID
                    ),
                    "onboarding_policy": (
                        "review"
                    ),
                    "review_reasons": (
                        review_reasons
                        if review_reasons
                        is not None
                        else [
                            (
                                "confidence-"
                                "below-threshold"
                            )
                        ]
                    ),
                    "blocking_issues": (
                        blocking_issues or []
                    ),
                    "advisory_issues": [
                        "Package manager uncertain"
                    ],
                    "confidence": confidence,
                }
            ],
        },
        digest=(
            "sha256:" + "d" * 64
        ),
    )


def approve(
    source: LoadedTemplatePlan,
):
    return review_template_plan(
        source,
        repository_external_id=(
            REPOSITORY_ID
        ),
        expected_analysis_digest=(
            ANALYSIS_DIGEST
        ),
        expected_contract_id=(
            CONTRACT_ID
        ),
        reviewer="reviewer",
        justification=(
            "No blocking issues; advisory "
            "uncertainty is accepted."
        ),
        confirmation=(
            APPROVAL_CONFIRMATION
        ),
        minimum_reviewed_confidence=0.7,
    )


def test_review_promotes_only_selected_assignment(
    tmp_path: Path,
) -> None:
    plan, _, _, assignments = approve(
        source_plan(tmp_path)
    )
    assignment = assignments[
        "assignments"
    ][0]

    assert plan["required_count"] == 1
    assert plan["review_count"] == 0
    assert plan["mutation_allowed"] is False
    assert (
        assignment["onboarding_policy"]
        == "required"
    )
    assert assignment["review_reasons"] == []
    assert assignment[
        "original_review_reasons"
    ] == [
        "confidence-below-threshold"
    ]
    assert assignment[
        "review_resolution"
    ]["decision"] == "approve"


def test_review_plan_round_trip(
    tmp_path: Path,
) -> None:
    values = approve(
        source_plan(tmp_path)
    )
    directory = write_reviewed_template_plan(
        tmp_path / "plans",
        *values,
    )
    loaded = load_verified_template_plan(
        directory
    )

    assert loaded.plan[
        "required_count"
    ] == 1
    assert loaded.plan[
        "reviewed_approval_count"
    ] == 1
    assert loaded.assignments[
        "assignments"
    ][0][
        "review_resolution"
    ]["reviewer"] == "reviewer"


def test_review_cannot_override_blocker(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        ValueError,
        match="blocking issues",
    ):
        approve(
            source_plan(
                tmp_path,
                blocking_issues=[
                    "Ambiguous scan target"
                ],
            )
        )


def test_review_cannot_override_unknown_reason(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        ValueError,
        match="unsupported review reasons",
    ):
        approve(
            source_plan(
                tmp_path,
                review_reasons=[
                    "unresolved-questions"
                ],
            )
        )


def test_review_enforces_confidence_floor(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        ValueError,
        match="confidence is below",
    ):
        approve(
            source_plan(
                tmp_path,
                confidence=0.69,
            )
        )


def test_review_requires_exact_confirmation(
    tmp_path: Path,
) -> None:
    source = source_plan(tmp_path)

    with pytest.raises(
        ValueError,
        match="confirmation",
    ):
        review_template_plan(
            source,
            repository_external_id=(
                REPOSITORY_ID
            ),
            expected_analysis_digest=(
                ANALYSIS_DIGEST
            ),
            expected_contract_id=(
                CONTRACT_ID
            ),
            reviewer="reviewer",
            justification="Reviewed",
            confirmation="APPROVE",
        )


def test_review_is_bound_to_analysis_digest(
    tmp_path: Path,
) -> None:
    source = source_plan(tmp_path)

    with pytest.raises(
        ValueError,
        match="analysis digest",
    ):
        review_template_plan(
            source,
            repository_external_id=(
                REPOSITORY_ID
            ),
            expected_analysis_digest=(
                "sha256:" + "e" * 64
            ),
            expected_contract_id=(
                CONTRACT_ID
            ),
            reviewer="reviewer",
            justification="Reviewed",
            confirmation=(
                APPROVAL_CONFIRMATION
            ),
        )
