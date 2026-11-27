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
from wintermute.scm.models import (
    normalize_provider,
    normalize_provider_instance,
)
from wintermute.scm.onboarding.template_artifacts import (
    ARTIFACT_NAMES,
    LoadedTemplatePlan,
)


def now_text() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def create_plan_id(
    source_references: list[
        dict[str, str]
    ],
) -> str:
    source_digest = stable_digest(
        source_references
    ).split(":", 1)[1][:12]

    return (
        datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ"
        )
        + "-merged-scan-template-plan-"
        + source_digest
        + "-"
        + uuid.uuid4().hex[:8]
    )


def required_text(
    value: Any,
    field: str,
) -> str:
    selected = str(value or "").strip()

    if not selected:
        raise ValueError(
            f"{field} must not be empty"
        )

    return selected


def source_reference(
    source: LoadedTemplatePlan,
) -> dict[str, str]:
    return {
        "plan_id": required_text(
            source.plan.get("plan_id"),
            "source plan ID",
        ),
        "plan_digest": required_text(
            source.digest,
            "source plan digest",
        ),
        "source_batch_id": str(
            source.plan.get(
                "source_batch_id"
            )
            or ""
        ).strip(),
    }


def normalized_sources(
    sources: list[LoadedTemplatePlan]
    | tuple[LoadedTemplatePlan, ...],
) -> tuple[
    tuple[LoadedTemplatePlan, ...],
    list[dict[str, str]],
]:
    if len(sources) < 2:
        raise ValueError(
            "Template merge requires at least "
            "two verified source plans"
        )

    by_plan_id: dict[
        str,
        LoadedTemplatePlan,
    ] = {}
    by_digest: dict[
        str,
        LoadedTemplatePlan,
    ] = {}

    for source in sources:
        plan_id = required_text(
            source.plan.get("plan_id"),
            "source plan ID",
        )
        digest = required_text(
            source.digest,
            "source plan digest",
        )
        existing_id = by_plan_id.get(
            plan_id
        )

        if (
            existing_id is not None
            and existing_id.digest != digest
        ):
            raise ValueError(
                "Source template plan ID collision: "
                f"{plan_id}"
            )

        if digest in by_digest:
            continue

        by_plan_id[plan_id] = source
        by_digest[digest] = source

    if len(by_digest) < 2:
        raise ValueError(
            "Template merge requires at least "
            "two distinct source plans"
        )

    ordered = tuple(
        sorted(
            by_digest.values(),
            key=lambda source: (
                str(
                    source.plan.get(
                        "plan_id"
                    )
                    or ""
                ),
                source.digest,
            ),
        )
    )
    references = [
        source_reference(source)
        for source in ordered
    ]

    return ordered, references


def verified_contract(
    value: dict[str, Any],
) -> tuple[str, str, dict[str, Any]]:
    contract_id = required_text(
        value.get("scan_contract_id"),
        "scan contract ID",
    )
    raw_contract = value.get("contract")

    if not isinstance(raw_contract, dict):
        raise ValueError(
            f"Scan contract {contract_id} "
            "must be an object"
        )

    contract = dict(raw_contract)
    claimed_digest = required_text(
        contract.get("contract_digest"),
        (
            f"scan contract {contract_id} "
            "digest"
        ),
    )
    unsigned = dict(contract)
    unsigned.pop(
        "contract_digest",
        None,
    )
    calculated_digest = stable_digest(
        unsigned
    )

    if claimed_digest != calculated_digest:
        raise ValueError(
            f"Scan contract {contract_id} "
            "digest does not match its content"
        )

    return (
        contract_id,
        claimed_digest,
        contract,
    )


def merge_catalogs(
    sources: tuple[
        LoadedTemplatePlan,
        ...
    ],
) -> dict[str, Any]:
    templates: dict[
        str,
        dict[str, Any],
    ] = {}

    for source in sources:
        values = source.catalog.get(
            "templates"
        )

        if (
            not isinstance(values, list)
            or not all(
                isinstance(value, dict)
                for value in values
            )
        ):
            raise ValueError(
                "Source approved-template catalog "
                "is invalid"
            )

        for raw_template in values:
            template = dict(raw_template)
            template_id = required_text(
                template.get("template_id"),
                "approved template ID",
            )
            existing = templates.get(
                template_id
            )

            if (
                existing is not None
                and existing != template
            ):
                raise ValueError(
                    "Approved template ID collision: "
                    f"{template_id}"
                )

            templates[
                template_id
            ] = template

    return {
        "schema_version": 1,
        "templates": [
            templates[template_id]
            for template_id
            in sorted(templates)
        ],
    }


def merge_contracts(
    sources: tuple[
        LoadedTemplatePlan,
        ...
    ],
    references: list[
        dict[str, str]
    ],
) -> tuple[
    dict[str, Any],
    dict[str, str],
]:
    contracts_by_id: dict[
        str,
        tuple[str, dict[str, Any]],
    ] = {}
    contracts_by_digest: dict[
        str,
        dict[str, Any],
    ] = {}
    ids_by_digest: dict[
        str,
        set[str],
    ] = {}
    sources_by_digest: dict[
        str,
        list[dict[str, str]],
    ] = {}

    references_by_digest = {
        source.digest: reference
        for source, reference
        in zip(
            sources,
            references,
            strict=True,
        )
    }

    for source in sources:
        values = source.contracts.get(
            "contracts"
        )

        if (
            not isinstance(values, list)
            or not all(
                isinstance(value, dict)
                for value in values
            )
        ):
            raise ValueError(
                "Source scan-contract registry "
                "is invalid"
            )

        source_reference_value = (
            references_by_digest[
                source.digest
            ]
        )

        for raw_value in values:
            (
                contract_id,
                contract_digest,
                contract,
            ) = verified_contract(
                raw_value
            )
            existing_id = contracts_by_id.get(
                contract_id
            )

            if (
                existing_id is not None
                and (
                    existing_id[0]
                    != contract_digest
                    or existing_id[1]
                    != contract
                )
            ):
                raise ValueError(
                    "Scan contract ID collision: "
                    f"{contract_id}"
                )

            existing_digest = (
                contracts_by_digest.get(
                    contract_digest
                )
            )

            if (
                existing_digest is not None
                and existing_digest != contract
            ):
                raise ValueError(
                    "Scan contract digest collision: "
                    f"{contract_digest}"
                )

            contracts_by_id[
                contract_id
            ] = (
                contract_digest,
                contract,
            )
            contracts_by_digest[
                contract_digest
            ] = contract
            ids_by_digest.setdefault(
                contract_digest,
                set(),
            ).add(contract_id)
            source_values = (
                sources_by_digest.setdefault(
                    contract_digest,
                    [],
                )
            )

            if (
                source_reference_value
                not in source_values
            ):
                source_values.append(
                    source_reference_value
                )

    canonical_by_id: dict[str, str] = {}
    merged_rows: list[
        dict[str, Any]
    ] = []

    for contract_digest in sorted(
        contracts_by_digest
    ):
        contract_ids = sorted(
            ids_by_digest[
                contract_digest
            ]
        )
        canonical_id = contract_ids[0]

        for contract_id in contract_ids:
            canonical_by_id[
                contract_id
            ] = canonical_id

        merged_rows.append(
            {
                "scan_contract_id": (
                    canonical_id
                ),
                "contract": (
                    contracts_by_digest[
                        contract_digest
                    ]
                ),
                "source_contract_ids": (
                    contract_ids
                ),
                "source_template_plans": (
                    sorted(
                        sources_by_digest[
                            contract_digest
                        ],
                        key=lambda value: (
                            value["plan_id"],
                            value[
                                "plan_digest"
                            ],
                        ),
                    )
                ),
            }
        )

    return (
        {
            "schema_version": 1,
            "source_template_plans": (
                references
            ),
            "scan_contract_count": len(
                merged_rows
            ),
            "contracts": sorted(
                merged_rows,
                key=lambda value: (
                    value[
                        "scan_contract_id"
                    ]
                ),
            ),
        },
        canonical_by_id,
    )


def assignment_key(
    value: dict[str, Any],
) -> tuple[str, str, str]:
    return (
        normalize_provider(
            value.get("provider")
        ),
        normalize_provider_instance(
            value.get(
                "provider_instance"
            )
        ),
        required_text(
            value.get("repository_id"),
            "repository ID",
        ),
    )


def semantic_assignment(
    raw_value: dict[str, Any],
    canonical_by_id: dict[str, str],
) -> dict[str, Any]:
    value = dict(raw_value)
    value.pop(
        "source_template_plan_id",
        None,
    )
    value.pop(
        "source_template_plan_digest",
        None,
    )
    value.pop(
        "source_template_plans",
        None,
    )

    provider, instance, repository_id = (
        assignment_key(value)
    )
    value["provider"] = provider
    value[
        "provider_instance"
    ] = instance
    value["repository_id"] = (
        repository_id
    )
    contract_id = str(
        value.get("scan_contract_id")
        or ""
    ).strip()

    if contract_id:
        canonical_id = (
            canonical_by_id.get(
                contract_id
            )
        )

        if canonical_id is None:
            raise ValueError(
                "Repository assignment references "
                "an unknown scan contract: "
                f"{contract_id}"
            )

        value["scan_contract_id"] = (
            canonical_id
        )

    policy = required_text(
        value.get("onboarding_policy"),
        "onboarding policy",
    )

    if policy not in {
        "required",
        "review",
    }:
        raise ValueError(
            "Repository onboarding policy "
            "must be required or review"
        )

    if (
        policy == "required"
        and not contract_id
    ):
        raise ValueError(
            "Required repository assignment "
            "has no scan contract"
        )

    return value


def merge_assignments(
    sources: tuple[
        LoadedTemplatePlan,
        ...
    ],
    references: list[
        dict[str, str]
    ],
    canonical_by_id: dict[str, str],
) -> dict[str, Any]:
    assignments: dict[
        tuple[str, str, str],
        dict[str, Any],
    ] = {}
    source_values: dict[
        tuple[str, str, str],
        list[dict[str, str]],
    ] = {}
    external_id_keys: dict[
        str,
        tuple[str, str, str],
    ] = {}
    references_by_digest = {
        source.digest: reference
        for source, reference
        in zip(
            sources,
            references,
            strict=True,
        )
    }

    for source in sources:
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
                "Source repository-assignment "
                "registry is invalid"
            )

        source_reference_value = (
            references_by_digest[
                source.digest
            ]
        )

        for raw_value in values:
            value = semantic_assignment(
                raw_value,
                canonical_by_id,
            )
            key = assignment_key(value)
            external_id = required_text(
                value.get(
                    "repository_external_id"
                ),
                "repository external ID",
            )
            existing_external_key = (
                external_id_keys.get(
                    external_id
                )
            )

            if (
                existing_external_key is not None
                and existing_external_key != key
            ):
                raise ValueError(
                    "Repository external ID maps to "
                    "multiple provider-native identities: "
                    f"{external_id}"
                )

            external_id_keys[
                external_id
            ] = key
            existing = assignments.get(key)

            if (
                existing is not None
                and existing != value
            ):
                raise ValueError(
                    "Conflicting repository assignment "
                    "for provider-native identity: "
                    + "/".join(key)
                )

            assignments[key] = value
            references_for_assignment = (
                source_values.setdefault(
                    key,
                    [],
                )
            )

            if (
                source_reference_value
                not in references_for_assignment
            ):
                references_for_assignment.append(
                    source_reference_value
                )

    rows: list[dict[str, Any]] = []

    for key in sorted(assignments):
        value = dict(
            assignments[key]
        )
        value[
            "source_template_plans"
        ] = sorted(
            source_values[key],
            key=lambda reference: (
                reference["plan_id"],
                reference["plan_digest"],
            ),
        )
        rows.append(value)

    return {
        "schema_version": 1,
        "source_template_plans": (
            references
        ),
        "assignment_count": len(rows),
        "assignments": rows,
    }


def merge_approval_records(
    sources: tuple[
        LoadedTemplatePlan,
        ...
    ],
) -> list[dict[str, Any]]:
    approvals: dict[
        str,
        dict[str, Any],
    ] = {}

    for source in sources:
        values = source.plan.get(
            "review_approvals",
            [],
        )

        if (
            not isinstance(values, list)
            or not all(
                isinstance(value, dict)
                for value in values
            )
        ):
            raise ValueError(
                "Source review approvals are invalid"
            )

        for raw_value in values:
            value = dict(raw_value)
            approval_id = required_text(
                value.get("approval_id"),
                "review approval ID",
            )
            existing = approvals.get(
                approval_id
            )

            if (
                existing is not None
                and existing != value
            ):
                raise ValueError(
                    "Review approval ID collision: "
                    f"{approval_id}"
                )

            approvals[
                approval_id
            ] = value

    return [
        approvals[approval_id]
        for approval_id
        in sorted(approvals)
    ]


def merge_template_plans(
    sources: list[LoadedTemplatePlan]
    | tuple[LoadedTemplatePlan, ...],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    (
        ordered_sources,
        references,
    ) = normalized_sources(
        sources
    )
    catalog = merge_catalogs(
        ordered_sources
    )
    (
        contracts,
        canonical_by_id,
    ) = merge_contracts(
        ordered_sources,
        references,
    )
    assignments = merge_assignments(
        ordered_sources,
        references,
        canonical_by_id,
    )
    rows = assignments[
        "assignments"
    ]
    approvals = merge_approval_records(
        ordered_sources
    )
    plan = {
        "schema_version": 1,
        "plan_id": create_plan_id(
            references
        ),
        "created_at": now_text(),
        "status": "review-required",
        "mutation_allowed": False,
        "merge_mode": (
            "verified-template-plan-merge"
        ),
        "source_template_plan_count": (
            len(references)
        ),
        "source_template_plans": (
            references
        ),
        "repository_count": len(rows),
        "source_profile_group_count": sum(
            int(
                source.plan.get(
                    "source_profile_group_count"
                )
                or 0
            )
            for source in ordered_sources
        ),
        "scan_contract_count": (
            contracts[
                "scan_contract_count"
            ]
        ),
        "required_count": sum(
            value[
                "onboarding_policy"
            ]
            == "required"
            for value in rows
        ),
        "review_count": sum(
            value[
                "onboarding_policy"
            ]
            == "review"
            for value in rows
        ),
        "advisory_repository_count": sum(
            bool(
                value.get(
                    "advisory_issues",
                    []
                )
            )
            for value in rows
        ),
        "reviewed_approval_count": (
            len(approvals)
        ),
        "review_approvals": approvals,
        "review_requirements": [
            "review-source-template-plans",
            "review-merged-scan-contracts",
            "review-merged-repository-assignments",
            "review-explicit-approval-records",
            "approve-central-bundle-upgrade",
        ],
    }

    return (
        plan,
        catalog,
        contracts,
        assignments,
    )


def write_merged_template_plan(
    root: str | Path,
    plan: dict[str, Any],
    catalog: dict[str, Any],
    contracts: dict[str, Any],
    assignments: dict[str, Any],
) -> Path:
    root_path = Path(root)
    plan_id = required_text(
        plan.get("plan_id"),
        "merged template plan ID",
    )
    staging = (
        root_path / ".staging" / plan_id
    )
    destination = root_path / plan_id

    if destination.exists():
        raise RuntimeError(
            "Merged template plan already exists: "
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
