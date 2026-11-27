from __future__ import annotations

import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from wintermute.ai.models import stable_digest
from wintermute.ai.storage import (
    atomic_write_json,
    sha256_file,
)
from wintermute.scm.onboarding.template_artifacts import (
    ARTIFACT_NAMES,
    LoadedTemplatePlan,
)


APPROVAL_CONFIRMATION = (
    "APPROVE_REVIEWED_SCAN_CONTRACT"
)
ALLOWED_REVIEW_REASONS = {
    "confidence-below-threshold",
}


def now_text() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def create_plan_id() -> str:
    return (
        datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ"
        )
        + "-reviewed-scan-template-plan-"
        + uuid.uuid4().hex[:12]
    )


def required_text(
    value: Any,
    field: str,
    *,
    maximum: int,
) -> str:
    selected = str(value or "").strip()

    if not selected:
        raise ValueError(
            f"{field} must not be empty"
        )

    if len(selected) > maximum:
        raise ValueError(
            f"{field} exceeds {maximum} characters"
        )

    return selected


def string_list(
    value: Any,
    field: str,
) -> list[str]:
    if (
        not isinstance(value, list)
        or not all(
            isinstance(item, str)
            and item.strip()
            for item in value
        )
    ):
        raise ValueError(
            f"{field} must be a list of "
            "nonempty strings"
        )

    return sorted(
        {
            item.strip()
            for item in value
        }
    )


def contract_ids(
    source: LoadedTemplatePlan,
) -> set[str]:
    values = source.contracts.get(
        "contracts"
    )

    if not isinstance(values, list):
        raise ValueError(
            "Source template plan has invalid contracts"
        )

    return {
        str(
            value.get("scan_contract_id")
            or ""
        )
        for value in values
        if isinstance(value, dict)
    }


def assignment_rows(
    source: LoadedTemplatePlan,
) -> list[dict[str, Any]]:
    values = source.assignments.get(
        "assignments"
    )

    if (
        not isinstance(values, list)
        or not all(
            isinstance(value, dict)
            for value in values
        )
    ):
        raise ValueError(
            "Source template plan has invalid assignments"
        )

    return [
        dict(value)
        for value in values
    ]


def approval_record(
    source: LoadedTemplatePlan,
    assignment: dict[str, Any],
    *,
    reviewer: str,
    justification: str,
    reviewed_at: str,
) -> dict[str, Any]:
    identity = {
        "source_template_plan_id": (
            source.plan["plan_id"]
        ),
        "source_template_plan_digest": (
            source.digest
        ),
        "repository_external_id": (
            assignment[
                "repository_external_id"
            ]
        ),
        "analysis_digest": (
            assignment["analysis_digest"]
        ),
        "scan_contract_id": (
            assignment["scan_contract_id"]
        ),
        "reviewer": reviewer,
        "justification": justification,
        "decision": "approve",
    }
    digest = stable_digest(identity)

    return {
        "schema_version": 1,
        "approval_id": (
            "review-"
            + digest.split(":", 1)[1][:16]
        ),
        "approval_digest": digest,
        "decision": "approve",
        "reviewed_at": reviewed_at,
        "reviewer": reviewer,
        "justification": justification,
        "source_template_plan_id": (
            source.plan["plan_id"]
        ),
        "source_template_plan_digest": (
            source.digest
        ),
        "repository_external_id": (
            assignment[
                "repository_external_id"
            ]
        ),
        "name_with_owner": (
            assignment["name_with_owner"]
        ),
        "analysis_id": (
            assignment["analysis_id"]
        ),
        "analysis_digest": (
            assignment["analysis_digest"]
        ),
        "scan_contract_id": (
            assignment["scan_contract_id"]
        ),
        "confidence": assignment["confidence"],
        "original_review_reasons": list(
            assignment["review_reasons"]
        ),
        "blocking_issues": list(
            assignment["blocking_issues"]
        ),
        "advisory_issues": list(
            assignment.get(
                "advisory_issues",
                [],
            )
        ),
    }


def review_template_plan(
    source: LoadedTemplatePlan,
    *,
    repository_external_id: str,
    expected_analysis_digest: str,
    expected_contract_id: str,
    reviewer: str,
    justification: str,
    confirmation: str,
    minimum_reviewed_confidence: float = 0.7,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    repository_id = required_text(
        repository_external_id,
        "repository_external_id",
        maximum=200,
    )
    analysis_digest = required_text(
        expected_analysis_digest,
        "expected_analysis_digest",
        maximum=200,
    )
    expected_contract = required_text(
        expected_contract_id,
        "expected_contract_id",
        maximum=200,
    )
    selected_reviewer = required_text(
        reviewer,
        "reviewer",
        maximum=200,
    )
    selected_justification = required_text(
        justification,
        "justification",
        maximum=2000,
    )

    if confirmation != APPROVAL_CONFIRMATION:
        raise ValueError(
            "Review confirmation must exactly equal "
            f"{APPROVAL_CONFIRMATION}"
        )

    if not 0 <= minimum_reviewed_confidence <= 1:
        raise ValueError(
            "minimum_reviewed_confidence must be "
            "between 0 and 1"
        )

    assignments = assignment_rows(source)
    matches = [
        value
        for value in assignments
        if str(
            value.get(
                "repository_external_id"
            )
            or ""
        )
        == repository_id
    ]

    if len(matches) != 1:
        raise ValueError(
            "Reviewed repository must match exactly "
            "one assignment"
        )

    selected = matches[0]

    if (
        selected.get("onboarding_policy")
        != "review"
    ):
        raise ValueError(
            "Repository assignment is not awaiting review"
        )

    if (
        selected.get("analysis_digest")
        != analysis_digest
    ):
        raise ValueError(
            "Expected analysis digest does not match "
            "the reviewed assignment"
        )

    if (
        selected.get("scan_contract_id")
        != expected_contract
    ):
        raise ValueError(
            "Expected scan contract does not match "
            "the reviewed assignment"
        )

    if expected_contract not in contract_ids(
        source
    ):
        raise ValueError(
            "Reviewed assignment references an "
            "unknown scan contract"
        )

    blocking = string_list(
        selected.get(
            "blocking_issues",
            [],
        ),
        "blocking_issues",
    )

    if blocking:
        raise ValueError(
            "A reviewed approval cannot override "
            "blocking issues"
        )

    review_reasons = string_list(
        selected.get(
            "review_reasons",
            [],
        ),
        "review_reasons",
    )

    if not review_reasons:
        raise ValueError(
            "Reviewed assignment has no review reason"
        )

    unsupported_reasons = (
        set(review_reasons)
        - ALLOWED_REVIEW_REASONS
    )

    if unsupported_reasons:
        raise ValueError(
            "Reviewed approval cannot override "
            "unsupported review reasons: "
            + ", ".join(
                sorted(unsupported_reasons)
            )
        )

    try:
        confidence = float(
            selected.get("confidence")
        )
    except (
        TypeError,
        ValueError,
    ) as error:
        raise ValueError(
            "Reviewed assignment confidence is invalid"
        ) from error

    if not 0 <= confidence <= 1:
        raise ValueError(
            "Reviewed assignment confidence is invalid"
        )

    if confidence < minimum_reviewed_confidence:
        raise ValueError(
            "Reviewed assignment confidence is below "
            "the explicit reviewed-confidence floor"
        )

    reviewed_at = now_text()
    selected["blocking_issues"] = blocking
    selected["review_reasons"] = review_reasons
    record = approval_record(
        source,
        selected,
        reviewer=selected_reviewer,
        justification=selected_justification,
        reviewed_at=reviewed_at,
    )
    selected["original_onboarding_policy"] = (
        "review"
    )
    selected["original_review_reasons"] = list(
        review_reasons
    )
    selected["onboarding_policy"] = (
        "required"
    )
    selected["review_reasons"] = []
    selected["review_resolution"] = record

    updated_assignments = [
        selected
        if value.get(
            "repository_external_id"
        )
        == repository_id
        else value
        for value in assignments
    ]
    updated_assignments.sort(
        key=lambda value: (
            str(value.get("provider") or ""),
            str(
                value.get(
                    "provider_instance"
                )
                or ""
            ),
            str(
                value.get(
                    "name_with_owner"
                )
                or ""
            ).casefold(),
            str(
                value.get("repository_id")
                or ""
            ),
        )
    )

    previous_approvals = source.plan.get(
        "review_approvals",
        [],
    )

    if not isinstance(
        previous_approvals,
        list,
    ):
        raise ValueError(
            "Source template review approvals are invalid"
        )

    plan = dict(source.plan)
    plan.update(
        {
            "schema_version": 1,
            "plan_id": create_plan_id(),
            "created_at": reviewed_at,
            "status": "review-required",
            "mutation_allowed": False,
            "source_template_plan_id": (
                source.plan["plan_id"]
            ),
            "source_template_plan_digest": (
                source.digest
            ),
            "repository_count": len(
                updated_assignments
            ),
            "required_count": sum(
                value.get(
                    "onboarding_policy"
                )
                == "required"
                for value
                in updated_assignments
            ),
            "review_count": sum(
                value.get(
                    "onboarding_policy"
                )
                == "review"
                for value
                in updated_assignments
            ),
            "reviewed_approval_count": (
                len(previous_approvals) + 1
            ),
            "review_approvals": [
                *previous_approvals,
                record,
            ],
            "review_requirements": [
                "review-template-contracts",
                "review-repository-assignments",
                "review-explicit-approval-records",
                "approve-central-enforcement",
            ],
        }
    )

    contracts = dict(source.contracts)
    assignments_payload = dict(
        source.assignments
    )
    assignments_payload.update(
        {
            "assignment_count": len(
                updated_assignments
            ),
            "assignments": (
                updated_assignments
            ),
            "source_template_plan_id": (
                source.plan["plan_id"]
            ),
            "source_template_plan_digest": (
                source.digest
            ),
        }
    )

    return (
        plan,
        dict(source.catalog),
        contracts,
        assignments_payload,
    )


def write_reviewed_template_plan(
    root: str | Path,
    plan: dict[str, Any],
    catalog: dict[str, Any],
    contracts: dict[str, Any],
    assignments: dict[str, Any],
) -> Path:
    root_path = Path(root)
    plan_id = str(
        plan.get("plan_id") or ""
    )

    if not plan_id:
        raise ValueError(
            "Reviewed template plan has no plan ID"
        )

    staging = (
        root_path / ".staging" / plan_id
    )
    destination = root_path / plan_id

    if destination.exists():
        raise RuntimeError(
            "Reviewed template plan already exists: "
            f"{destination}"
        )

    if staging.exists():
        shutil.rmtree(staging)

    staging.mkdir(
        parents=True,
        exist_ok=False,
    )

    try:
        atomic_write_json(
            staging / "plan.json",
            plan,
        )
        atomic_write_json(
            staging
            / "approved-template-catalog.json",
            catalog,
        )
        atomic_write_json(
            staging / "scan-contracts.json",
            contracts,
        )
        atomic_write_json(
            staging
            / "repository-assignments.json",
            assignments,
        )
        atomic_write_json(
            staging / "checksums.json",
            {
                "schema_version": 1,
                "sha256": {
                    name: sha256_file(
                        staging / name
                    )
                    for name in ARTIFACT_NAMES
                },
            },
        )
        root_path.mkdir(
            parents=True,
            exist_ok=True,
        )
        os.replace(
            staging,
            destination,
        )
        atomic_write_json(
            destination / "READY",
            {
                "schema_version": 1,
                "plan_id": plan_id,
                "ready_at": now_text(),
            },
        )

        return destination

    except BaseException:
        shutil.rmtree(
            staging,
            ignore_errors=True,
        )
        raise
