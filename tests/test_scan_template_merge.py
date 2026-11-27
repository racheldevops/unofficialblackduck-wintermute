from __future__ import annotations

from pathlib import Path

import pytest

from wintermute.ai.models import stable_digest
from wintermute.scm.onboarding.template_artifacts import (
    LoadedTemplatePlan,
    load_verified_template_plan,
)
from wintermute.scm.onboarding.template_merge import (
    merge_template_plans,
    write_merged_template_plan,
)


def contract(
    *,
    mode: str = "detector",
) -> dict:
    value = {
        "schema_version": 1,
        "template_id": "python-security-scan",
        "template_version": 1,
        "engine": "bridge",
        "products": ["blackduck-sca"],
        "scan_mode": mode,
        "resource_class": "medium",
        "timeout_seconds": 3600,
        "runtime_parameters": {
            "binary_scan": False,
            "buildless": True,
            "detector_search_depth": 3,
            "project_name_strategy": (
                "provider-id"
            ),
        },
    }
    value["contract_digest"] = (
        stable_digest(value)
    )

    return value


def source(
    tmp_path: Path,
    plan_id: str,
    repository_id: str,
    repository_external_id: str,
    *,
    contract_id: str = "scan-python",
    contract_value: dict | None = None,
    policy: str = "required",
) -> LoadedTemplatePlan:
    selected_contract = (
        contract_value or contract()
    )

    return LoadedTemplatePlan(
        directory=tmp_path / plan_id,
        plan={
            "schema_version": 1,
            "plan_id": plan_id,
            "created_at": (
                "2026-09-07T00:00:00Z"
            ),
            "status": "review-required",
            "mutation_allowed": False,
            "source_batch_id": (
                f"batch-{plan_id}"
            ),
            "source_profile_group_count": 1,
            "repository_count": 1,
            "scan_contract_count": 1,
            "required_count": (
                1 if policy == "required" else 0
            ),
            "review_count": (
                1 if policy == "review" else 0
            ),
        },
        catalog={
            "schema_version": 1,
            "templates": [
                {
                    "template_id": (
                        "python-security-scan"
                    ),
                    "template_version": 1,
                    "engine": "bridge",
                    "products": [
                        "blackduck-sca"
                    ],
                    "central_template": "python",
                    "supported_modes": [
                        "detector",
                        "hybrid",
                    ],
                    "resource_class": "medium",
                    "timeout_seconds": 3600,
                }
            ],
        },
        contracts={
            "schema_version": 1,
            "scan_contract_count": 1,
            "contracts": [
                {
                    "scan_contract_id": (
                        contract_id
                    ),
                    "contract": (
                        selected_contract
                    ),
                }
            ],
        },
        assignments={
            "schema_version": 1,
            "assignment_count": 1,
            "assignments": [
                {
                    "repository_external_id": (
                        repository_external_id
                    ),
                    "provider": "gitlab",
                    "provider_instance": (
                        "gitlab.example"
                    ),
                    "repository_id": (
                        repository_id
                    ),
                    "name_with_owner": (
                        f"group/service-{repository_id}"
                    ),
                    "analysis_id": (
                        f"analysis-{repository_id}"
                    ),
                    "analysis_digest": (
                        "sha256:" + repository_id * 64
                    )[:71],
                    "source_profile_group_key": (
                        "sha256:" + "b" * 64
                    ),
                    "scan_contract_id": (
                        contract_id
                    ),
                    "onboarding_policy": policy,
                    "review_reasons": (
                        []
                        if policy == "required"
                        else [
                            "confidence-below-threshold"
                        ]
                    ),
                    "blocking_issues": [],
                    "advisory_issues": [],
                    "confidence": 0.9,
                }
            ],
        },
        digest=(
            "sha256:"
            + stable_digest(
                {"plan_id": plan_id}
            ).split(":", 1)[1]
        ),
    )


def test_merge_deduplicates_identical_contracts(
    tmp_path: Path,
) -> None:
    plan, _, contracts, assignments = (
        merge_template_plans(
            [
                source(
                    tmp_path,
                    "plan-one",
                    "101",
                    "external-one",
                ),
                source(
                    tmp_path,
                    "plan-two",
                    "202",
                    "external-two",
                ),
            ]
        )
    )

    assert plan["repository_count"] == 2
    assert plan["required_count"] == 2
    assert plan["review_count"] == 0
    assert plan["scan_contract_count"] == 1
    assert contracts[
        "scan_contract_count"
    ] == 1
    assert assignments[
        "assignment_count"
    ] == 2


def test_merge_rewrites_duplicate_contract_alias(
    tmp_path: Path,
) -> None:
    _, _, contracts, assignments = (
        merge_template_plans(
            [
                source(
                    tmp_path,
                    "plan-one",
                    "101",
                    "external-one",
                    contract_id="scan-a",
                ),
                source(
                    tmp_path,
                    "plan-two",
                    "202",
                    "external-two",
                    contract_id="scan-b",
                ),
            ]
        )
    )

    assert contracts[
        "contracts"
    ][0][
        "source_contract_ids"
    ] == [
        "scan-a",
        "scan-b",
    ]
    assert {
        value["scan_contract_id"]
        for value
        in assignments["assignments"]
    } == {"scan-a"}


def test_contract_id_collision_is_rejected(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        ValueError,
        match="contract ID collision",
    ):
        merge_template_plans(
            [
                source(
                    tmp_path,
                    "plan-one",
                    "101",
                    "external-one",
                    contract_id="scan-same",
                ),
                source(
                    tmp_path,
                    "plan-two",
                    "202",
                    "external-two",
                    contract_id="scan-same",
                    contract_value=contract(
                        mode="hybrid"
                    ),
                ),
            ]
        )


def test_conflicting_assignment_is_rejected(
    tmp_path: Path,
) -> None:
    first = source(
        tmp_path,
        "plan-one",
        "101",
        "external-one",
    )
    second = source(
        tmp_path,
        "plan-two",
        "101",
        "external-one",
        policy="review",
    )

    with pytest.raises(
        ValueError,
        match="Conflicting repository assignment",
    ):
        merge_template_plans(
            [first, second]
        )


def test_merged_plan_round_trip(
    tmp_path: Path,
) -> None:
    values = merge_template_plans(
        [
            source(
                tmp_path,
                "plan-one",
                "101",
                "external-one",
            ),
            source(
                tmp_path,
                "plan-two",
                "202",
                "external-two",
                policy="review",
            ),
        ]
    )
    directory = write_merged_template_plan(
        tmp_path / "plans",
        *values,
    )
    loaded = load_verified_template_plan(
        directory
    )

    assert loaded.plan[
        "source_template_plan_count"
    ] == 2
    assert loaded.plan[
        "repository_count"
    ] == 2
    assert loaded.plan[
        "required_count"
    ] == 1
    assert loaded.plan[
        "review_count"
    ] == 1
    assert loaded.contracts[
        "scan_contract_count"
    ] == 1


def test_merge_requires_distinct_sources(
    tmp_path: Path,
) -> None:
    selected = source(
        tmp_path,
        "plan-one",
        "101",
        "external-one",
    )

    with pytest.raises(
        ValueError,
        match="distinct source plans",
    ):
        merge_template_plans(
            [selected, selected]
        )
