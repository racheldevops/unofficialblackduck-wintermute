from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wintermute.ai.models import stable_digest
from wintermute.ai.storage import sha256_file


ARTIFACT_NAMES = (
    "plan.json",
    "approved-template-catalog.json",
    "scan-contracts.json",
    "repository-assignments.json",
)


class TemplatePlanError(RuntimeError):
    pass


@dataclass(frozen=True)
class LoadedTemplatePlan:
    directory: Path
    plan: dict[str, Any]
    catalog: dict[str, Any]
    contracts: dict[str, Any]
    assignments: dict[str, Any]
    digest: str


def read_object(
    path: Path,
) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8")
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        raise TemplatePlanError(
            f"Could not read template-plan "
            f"artifact {path}: {error}"
        ) from error

    if not isinstance(value, dict):
        raise TemplatePlanError(
            f"Template-plan artifact is not "
            f"an object: {path}"
        )

    return value


def load_verified_template_plan(
    directory: str | Path,
) -> LoadedTemplatePlan:
    root = Path(directory).expanduser()

    if not root.is_dir():
        raise TemplatePlanError(
            f"Template plan does not exist: {root}"
        )

    ready = read_object(root / "READY")
    checksums = read_object(
        root / "checksums.json"
    ).get("sha256")

    if not isinstance(checksums, dict):
        raise TemplatePlanError(
            "Template-plan checksums are invalid"
        )

    for name in ARTIFACT_NAMES:
        expected = str(
            checksums.get(name) or ""
        )

        if not expected:
            raise TemplatePlanError(
                f"Missing checksum for {name}"
            )

        try:
            actual = sha256_file(root / name)
        except OSError as error:
            raise TemplatePlanError(
                f"Could not read {name}: {error}"
            ) from error

        if actual != expected:
            raise TemplatePlanError(
                f"Checksum mismatch for {name}"
            )

    plan = read_object(root / "plan.json")
    catalog = read_object(
        root / "approved-template-catalog.json"
    )
    contracts = read_object(
        root / "scan-contracts.json"
    )
    assignments = read_object(
        root / "repository-assignments.json"
    )
    plan_id = str(
        plan.get("plan_id") or ""
    )

    if not plan_id:
        raise TemplatePlanError(
            "Template plan has no plan ID"
        )

    if ready.get("plan_id") != plan_id:
        raise TemplatePlanError(
            "READY marker does not match "
            "the template plan"
        )

    if plan.get("status") != "review-required":
        raise TemplatePlanError(
            "Template plan is not reviewable"
        )

    if plan.get("mutation_allowed") is not False:
        raise TemplatePlanError(
            "Template plan unexpectedly "
            "allows mutation"
        )

    contract_rows = contracts.get("contracts")
    assignment_rows = assignments.get(
        "assignments"
    )

    if (
        not isinstance(contract_rows, list)
        or not all(
            isinstance(value, dict)
            for value in contract_rows
        )
    ):
        raise TemplatePlanError(
            "Scan contracts are invalid"
        )

    if (
        not isinstance(assignment_rows, list)
        or not all(
            isinstance(value, dict)
            for value in assignment_rows
        )
    ):
        raise TemplatePlanError(
            "Repository assignments are invalid"
        )

    contract_ids = {
        str(
            value.get("scan_contract_id")
            or ""
        )
        for value in contract_rows
    }

    if (
        "" in contract_ids
        or len(contract_ids)
        != len(contract_rows)
    ):
        raise TemplatePlanError(
            "Scan contract identities are invalid"
        )

    repository_ids: set[str] = set()
    required_count = 0
    review_count = 0

    for assignment in assignment_rows:
        external_id = str(
            assignment.get(
                "repository_external_id"
            )
            or ""
        )
        policy = str(
            assignment.get(
                "onboarding_policy"
            )
            or ""
        )
        contract_id = str(
            assignment.get(
                "scan_contract_id"
            )
            or ""
        )

        if (
            not external_id
            or external_id in repository_ids
        ):
            raise TemplatePlanError(
                "Repository assignment identities "
                "are invalid"
            )

        if policy not in {
            "required",
            "review",
        }:
            raise TemplatePlanError(
                "Repository onboarding policy "
                "is invalid"
            )

        if (
            policy == "required"
            and contract_id not in contract_ids
        ):
            raise TemplatePlanError(
                "Required repository has no valid "
                "scan contract"
            )

        repository_ids.add(external_id)
        required_count += (
            policy == "required"
        )
        review_count += (
            policy == "review"
        )

    if plan.get("repository_count") != len(
        assignment_rows
    ):
        raise TemplatePlanError(
            "Repository count does not match "
            "the assignments"
        )

    if plan.get("required_count") != (
        required_count
    ):
        raise TemplatePlanError(
            "Required count does not match"
        )

    if plan.get("review_count") != review_count:
        raise TemplatePlanError(
            "Review count does not match"
        )

    if plan.get("scan_contract_count") != len(
        contract_rows
    ):
        raise TemplatePlanError(
            "Scan-contract count does not match"
        )

    digest = stable_digest(
        {
            "plan": plan,
            "catalog": catalog,
            "contracts": contracts,
            "assignments": assignments,
        }
    )

    return LoadedTemplatePlan(
        directory=root,
        plan=plan,
        catalog=catalog,
        contracts=contracts,
        assignments=assignments,
        digest=digest,
    )
