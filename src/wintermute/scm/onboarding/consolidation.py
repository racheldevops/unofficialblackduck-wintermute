from __future__ import annotations

import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from wintermute.ai.batch_artifacts import (
    LoadedProfileBatch,
)
from wintermute.ai.storage import (
    atomic_write_json,
    sha256_file,
)
from wintermute.scm.onboarding.review_policy import (
    classify_profile_issues,
)
from wintermute.scm.onboarding.templates import (
    approved_catalog,
    template_contract,
)


def now_text() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def create_plan_id() -> str:
    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")

    return (
        f"{timestamp}-scan-template-plan-"
        f"{uuid.uuid4().hex[:12]}"
    )


def ensure_complete_batch(
    batch: LoadedProfileBatch,
) -> None:
    summary = batch.summary
    deferred = int(
        summary.get(
            "deferred_repository_count"
        )
        or 0
    )
    selected = int(
        summary.get(
            "selected_repository_count"
        )
        or 0
    )
    profiles = int(
        summary.get("profile_count")
        or 0
    )
    failures = int(
        summary.get("failure_count")
        or 0
    )

    if deferred:
        raise ValueError(
            "AI batch is incomplete: "
            f"{deferred} repositories are deferred"
        )

    if failures:
        raise ValueError(
            "AI batch contains failures"
        )

    if selected < 1:
        raise ValueError(
            "AI batch selected no repositories"
        )

    if profiles != selected:
        raise ValueError(
            "AI batch profile count does not "
            "match the selected repository count"
        )


def policy_decision(
    profile: dict[str, Any],
    contract: dict[str, Any] | None,
    template_reasons: tuple[str, ...],
    *,
    minimum_confidence: float,
) -> tuple[
    str,
    tuple[str, ...],
    dict[str, list[str]],
]:
    reasons = list(template_reasons)
    issues = classify_profile_issues(
        profile
    )

    try:
        confidence = float(
            profile.get("confidence")
            or 0
        )
    except (
        TypeError,
        ValueError,
    ):
        confidence = 0

    if confidence < minimum_confidence:
        reasons.append(
            "confidence-below-threshold"
        )

    if contract is None:
        reasons.append(
            "template-contract-unavailable"
        )

    if issues["blocking_conflicts"]:
        reasons.append(
            "profile-conflicts"
        )

    if issues["blocking_questions"]:
        reasons.append(
            "unresolved-questions"
        )

    return (
        (
            "required"
            if not reasons
            else "review"
        ),
        tuple(sorted(set(reasons))),
        issues,
    )


def consolidate_batch(
    batch: LoadedProfileBatch,
    *,
    minimum_confidence: float = 0.8,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    if not 0 <= minimum_confidence <= 1:
        raise ValueError(
            "minimum_confidence must be "
            "between 0 and 1"
        )

    ensure_complete_batch(batch)
    contracts: dict[
        str,
        dict[str, Any],
    ] = {}
    assignments: list[
        dict[str, Any]
    ] = []

    for entry in batch.registry[
        "profiles"
    ]:
        repository = entry.get(
            "repository"
        )
        profile = entry.get(
            "scan_profile"
        )

        if not isinstance(repository, dict):
            raise ValueError(
                "AI batch repository is invalid"
            )

        if not isinstance(profile, dict):
            raise ValueError(
                "AI batch scan profile is invalid"
            )

        contract, template_reasons = (
            template_contract(profile)
        )
        (
            policy,
            review_reasons,
            issues,
        ) = policy_decision(
            profile,
            contract,
            template_reasons,
            minimum_confidence=(
                minimum_confidence
            ),
        )
        contract_id = ""

        if contract is not None:
            contract_id = (
                "scan-"
                + contract[
                    "contract_digest"
                ].split(":", 1)[1][:16]
            )
            existing = contracts.get(
                contract_id
            )

            if (
                existing is not None
                and existing["contract"]
                != contract
            ):
                raise ValueError(
                    "Scan contract identity collision"
                )

            contracts.setdefault(
                contract_id,
                {
                    "scan_contract_id": (
                        contract_id
                    ),
                    "contract": contract,
                },
            )

        assignments.append(
            {
                "repository_external_id": (
                    repository[
                        "external_id"
                    ]
                ),
                "provider": repository[
                    "provider"
                ],
                "provider_instance": (
                    repository[
                        "provider_instance"
                    ]
                ),
                "repository_id": (
                    repository[
                        "repository_id"
                    ]
                ),
                "name_with_owner": (
                    repository[
                        "name_with_owner"
                    ]
                ),
                "analysis_id": (
                    entry["analysis_id"]
                ),
                "analysis_digest": (
                    entry[
                        "analysis_digest"
                    ]
                ),
                "source_profile_group_key": (
                    entry[
                        "profile_group_key"
                    ]
                ),
                "scan_contract_id": (
                    contract_id
                ),
                "onboarding_policy": (
                    policy
                ),
                "review_reasons": list(
                    review_reasons
                ),
                "blocking_issues": sorted(
                    issues[
                        "blocking_conflicts"
                    ]
                    + issues[
                        "blocking_questions"
                    ]
                ),
                "advisory_issues": sorted(
                    issues[
                        "advisory_conflicts"
                    ]
                    + issues[
                        "advisory_questions"
                    ]
                ),
                "confidence": float(
                    profile.get(
                        "confidence"
                    )
                    or 0
                ),
            }
        )

    ordered_assignments = sorted(
        assignments,
        key=lambda value: (
            value["provider"],
            value["provider_instance"],
            value["name_with_owner"]
            .casefold(),
            value["repository_id"],
        ),
    )
    contract_rows = [
        contracts[key]
        for key in sorted(contracts)
    ]
    plan = {
        "schema_version": 1,
        "plan_id": create_plan_id(),
        "created_at": now_text(),
        "status": "review-required",
        "mutation_allowed": False,
        "source_batch_id": (
            batch.batch_id
        ),
        "source_batch_digest": (
            batch.digest
        ),
        "minimum_confidence": (
            minimum_confidence
        ),
        "repository_count": len(
            ordered_assignments
        ),
        "source_profile_group_count": (
            batch.registry[
                "profile_group_count"
            ]
        ),
        "scan_contract_count": len(
            contract_rows
        ),
        "required_count": sum(
            value["onboarding_policy"]
            == "required"
            for value in ordered_assignments
        ),
        "review_count": sum(
            value["onboarding_policy"]
            == "review"
            for value in ordered_assignments
        ),
        "advisory_repository_count": sum(
            bool(value["advisory_issues"])
            for value in ordered_assignments
        ),
        "review_requirements": [
            "review-template-contracts",
            "review-repository-assignments",
            "review-low-confidence-profiles",
            "review-blocking-profile-issues",
            "approve-central-enforcement",
        ],
    }
    contract_registry = {
        "schema_version": 1,
        "source_batch_id": (
            batch.batch_id
        ),
        "scan_contract_count": len(
            contract_rows
        ),
        "contracts": contract_rows,
    }
    assignment_registry = {
        "schema_version": 1,
        "source_batch_id": (
            batch.batch_id
        ),
        "assignment_count": len(
            ordered_assignments
        ),
        "assignments": (
            ordered_assignments
        ),
    }

    return (
        plan,
        contract_registry,
        assignment_registry,
    )


def write_consolidation_plan(
    root: str | Path,
    plan: dict[str, Any],
    contract_registry: dict[str, Any],
    assignment_registry: dict[str, Any],
) -> Path:
    root_path = Path(root)
    plan_id = str(
        plan.get("plan_id") or ""
    )

    if not plan_id:
        raise ValueError(
            "Template plan has no plan ID"
        )

    staging = (
        root_path / ".staging" / plan_id
    )
    destination = root_path / plan_id

    if destination.exists():
        raise RuntimeError(
            f"Template plan already exists: "
            f"{destination}"
        )

    if staging.exists():
        shutil.rmtree(staging)

    staging.mkdir(
        parents=True,
        exist_ok=False,
    )
    artifact_names = (
        "plan.json",
        "approved-template-catalog.json",
        "scan-contracts.json",
        "repository-assignments.json",
    )

    try:
        atomic_write_json(
            staging / "plan.json",
            plan,
        )
        atomic_write_json(
            staging
            / "approved-template-catalog.json",
            approved_catalog(),
        )
        atomic_write_json(
            staging / "scan-contracts.json",
            contract_registry,
        )
        atomic_write_json(
            staging
            / "repository-assignments.json",
            assignment_registry,
        )
        atomic_write_json(
            staging / "checksums.json",
            {
                "schema_version": 1,
                "sha256": {
                    name: sha256_file(
                        staging / name
                    )
                    for name in artifact_names
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
