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
from wintermute.ai.models import stable_digest
from wintermute.ai.storage import (
    atomic_write_json,
    sha256_file,
)
from wintermute.scm.onboarding.planning import (
    GitHubPolicyConfiguration,
    GitLabPolicyConfiguration,
    github_ruleset,
    gitlab_policy,
)


MAX_GITHUB_PROFILE_VALUES = 200


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
        f"{timestamp}-central-scan-onboarding-"
        f"{uuid.uuid4().hex[:12]}"
    )


def profile_identifier(
    group_key: str,
) -> str:
    return (
        "profile-"
        + stable_digest(
            {
                "group_key": group_key,
            }
        ).split(":", 1)[1][:16]
    )


def automation_decision(
    profile: dict[str, Any],
    *,
    minimum_confidence: float,
) -> tuple[str, tuple[str, ...]]:
    reasons: list[str] = []
    scan_profile = profile.get(
        "scan_profile"
    )

    if not isinstance(scan_profile, dict):
        return (
            "review",
            ("invalid-scan-profile",),
        )

    try:
        confidence = float(
            scan_profile.get(
                "confidence"
            )
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

    if scan_profile.get(
        "central_template"
    ) in {
        None,
        "",
        "unknown",
    }:
        reasons.append(
            "central-template-unknown"
        )

    if scan_profile.get(
        "scan_mode"
    ) in {
        None,
        "",
        "unknown",
    }:
        reasons.append(
            "scan-mode-unknown"
        )

    conflicts = scan_profile.get(
        "conflicts"
    )
    unresolved = scan_profile.get(
        "unresolved_questions"
    )

    if isinstance(conflicts, list) and conflicts:
        reasons.append(
            "profile-conflicts"
        )

    if isinstance(
        unresolved,
        list,
    ) and unresolved:
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
    )


def normalized_profile(
    value: dict[str, Any],
) -> dict[str, Any]:
    parameters = value.get(
        "parameters"
    )

    if not isinstance(parameters, dict):
        parameters = {}

    return {
        "schema_version": 1,
        "languages": sorted(
            {
                str(item)
                for item in value.get(
                    "languages",
                    [],
                )
                if str(item)
            }
        ),
        "build_systems": sorted(
            {
                str(item)
                for item in value.get(
                    "build_systems",
                    [],
                )
                if str(item)
            }
        ),
        "package_managers": sorted(
            {
                str(item)
                for item in value.get(
                    "package_managers",
                    [],
                )
                if str(item)
            }
        ),
        "layout": str(
            value.get("layout")
            or "unknown"
        ),
        "scan_mode": str(
            value.get("scan_mode")
            or "unknown"
        ),
        "central_template": str(
            value.get(
                "central_template"
            )
            or "unknown"
        ),
        "parameters": dict(
            sorted(parameters.items())
        ),
        "confidence": float(
            value.get("confidence")
            or 0
        ),
        "evidence_ids": sorted(
            {
                str(item)
                for item in value.get(
                    "evidence_ids",
                    [],
                )
                if str(item)
            }
        ),
        "conflicts": sorted(
            {
                str(item)
                for item in value.get(
                    "conflicts",
                    [],
                )
                if str(item)
            }
        ),
        "unresolved_questions": sorted(
            {
                str(item)
                for item in value.get(
                    "unresolved_questions",
                    [],
                )
                if str(item)
            }
        ),
    }


def executable_profile(
    value: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "central_template": (
            value["central_template"]
        ),
        "scan_mode": value["scan_mode"],
        "build_systems": list(
            value["build_systems"]
        ),
        "package_managers": list(
            value["package_managers"]
        ),
        "parameters": dict(
            value["parameters"]
        ),
    }


def central_registry(
    batch: LoadedProfileBatch,
    *,
    minimum_confidence: float,
) -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
]:
    definitions: dict[
        str,
        dict[str, Any],
    ] = {}
    assignments: list[
        dict[str, Any]
    ] = []

    for entry in batch.registry[
        "profiles"
    ]:
        repository = entry[
            "repository"
        ]
        full_profile = normalized_profile(
            entry["scan_profile"]
        )
        central_profile = (
            executable_profile(
                full_profile
            )
        )
        group_key = str(
            entry["profile_group_key"]
        )
        profile_id = profile_identifier(
            group_key
        )
        policy, reasons = (
            automation_decision(
                entry,
                minimum_confidence=(
                    minimum_confidence
                ),
            )
        )
        existing = definitions.get(
            profile_id
        )

        if (
            existing is not None
            and existing["scan_profile"]
            != central_profile
        ):
            raise ValueError(
                "AI profile group contains "
                "different executable profiles"
            )

        definitions.setdefault(
            profile_id,
            {
                "profile_id": profile_id,
                "profile_group_key": (
                    group_key
                ),
                "scan_profile": (
                    central_profile
                ),
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
                "canonical_url": (
                    repository[
                        "canonical_url"
                    ]
                ),
                "profile_id": profile_id,
                "policy": policy,
                "review_reasons": list(
                    reasons
                ),
                "analysis_id": (
                    entry["analysis_id"]
                ),
                "analysis_digest": (
                    entry[
                        "analysis_digest"
                    ]
                ),
                "confidence": (
                    full_profile["confidence"]
                ),
                "evidence_ids": list(
                    full_profile[
                        "evidence_ids"
                    ]
                ),
                "conflicts": list(
                    full_profile["conflicts"]
                ),
                "unresolved_questions": (
                    list(
                        full_profile[
                            "unresolved_questions"
                        ]
                    )
                ),
            }
        )

    registry = {
        "schema_version": 1,
        "source_batch_id": (
            batch.batch_id
        ),
        "source_batch_digest": (
            batch.digest
        ),
        "minimum_confidence": (
            minimum_confidence
        ),
        "profile_count": len(
            definitions
        ),
        "assignment_count": len(
            assignments
        ),
        "required_count": sum(
            value["policy"]
            == "required"
            for value in assignments
        ),
        "review_count": sum(
            value["policy"]
            == "review"
            for value in assignments
        ),
        "profiles": [
            definitions[key]
            for key in sorted(
                definitions
            )
        ],
        "assignments": sorted(
            assignments,
            key=lambda value: (
                value["provider"],
                value[
                    "provider_instance"
                ],
                value[
                    "name_with_owner"
                ].casefold(),
                value["repository_id"],
            ),
        ),
    }

    return registry, assignments


def github_plan(
    assignments: list[dict[str, Any]],
    registry: dict[str, Any],
    configuration: (
        GitHubPolicyConfiguration
    ),
) -> tuple[
    dict[str, Any],
    dict[str, Any],
]:
    del registry
    selected = [
        value
        for value in assignments
        if value["provider"] == "github"
    ]
    profile_ids = sorted(
        {
            value["profile_id"]
            for value in selected
        }
    )

    if (
        len(profile_ids)
        > MAX_GITHUB_PROFILE_VALUES
    ):
        raise ValueError(
            "GitHub scan-profile property "
            "exceeds the allowed-value limit"
        )

    policy = github_ruleset(
        configuration
    )

    return (
        {
            "schema_version": 1,
            "provider": "github",
            "organization": (
                configuration.organization
            ),
            "repository_count": len(
                selected
            ),
            "required_repository_count": sum(
                value["policy"]
                == "required"
                for value in selected
            ),
            "review_repository_count": sum(
                value["policy"]
                == "review"
                for value in selected
            ),
            "property_definitions": [
                {
                    "property_name": (
                        configuration
                        .property_name
                    ),
                    "value_type": (
                        "single_select"
                    ),
                    "required": False,
                    "default_value": None,
                    "description": (
                        "Wintermute Black Duck "
                        "onboarding policy"
                    ),
                    "allowed_values": [
                        "excluded",
                        "required",
                        "review",
                    ],
                },
                {
                    "property_name": (
                        "blackduck_scan_profile"
                    ),
                    "value_type": (
                        "single_select"
                    ),
                    "required": False,
                    "default_value": None,
                    "description": (
                        "Wintermute approved "
                        "central scan profile"
                    ),
                    "allowed_values": (
                        profile_ids
                    ),
                },
            ],
            "assignments": [
                {
                    "repository_id": (
                        value[
                            "repository_id"
                        ]
                    ),
                    "name_with_owner": (
                        value[
                            "name_with_owner"
                        ]
                    ),
                    "values": {
                        configuration
                        .property_name: (
                            value["policy"]
                        ),
                        "blackduck_scan_profile": (
                            value[
                                "profile_id"
                            ]
                        ),
                    },
                }
                for value in selected
            ],
            "workflow": {
                "repository_id": (
                    configuration
                    .workflow_repository_id
                ),
                "path": (
                    configuration
                    .workflow_path
                ),
                "ref": (
                    configuration
                    .workflow_ref
                ),
            },
            "ruleset": policy,
            "stage": "evaluate",
            "mutation_allowed": False,
        },
        policy,
    )


def gitlab_plan(
    assignments: list[dict[str, Any]],
    configuration: (
        GitLabPolicyConfiguration
    ),
) -> tuple[
    dict[str, Any],
    str,
]:
    selected = [
        value
        for value in assignments
        if value["provider"] == "gitlab"
    ]
    policy = gitlab_policy(
        configuration
    )

    return (
        {
            "schema_version": 1,
            "provider": "gitlab",
            "group": configuration.group,
            "repository_count": len(
                selected
            ),
            "required_repository_count": sum(
                value["policy"]
                == "required"
                for value in selected
            ),
            "review_repository_count": sum(
                value["policy"]
                == "review"
                for value in selected
            ),
            "assignments": [
                {
                    "repository_id": (
                        value[
                            "repository_id"
                        ]
                    ),
                    "name_with_owner": (
                        value[
                            "name_with_owner"
                        ]
                    ),
                    "profile_id": (
                        value["profile_id"]
                    ),
                    "policy": (
                        value["policy"]
                    ),
                }
                for value in selected
            ],
            "policy_project": (
                configuration
                .policy_project
            ),
            "policy_file": (
                configuration.policy_file
            ),
            "template_project": (
                configuration
                .template_project
            ),
            "template_file": (
                configuration
                .template_file
            ),
            "template_ref": (
                configuration
                .template_ref
            ),
            "stage": "disabled",
            "mutation_allowed": False,
        },
        policy,
    )


def build_batch_plan(
    batch: LoadedProfileBatch,
    *,
    minimum_confidence: float,
    github: (
        GitHubPolicyConfiguration | None
    ) = None,
    gitlab: (
        GitLabPolicyConfiguration | None
    ) = None,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any] | None,
    dict[str, Any] | None,
    dict[str, Any] | None,
    str | None,
]:
    if not 0 <= minimum_confidence <= 1:
        raise ValueError(
            "minimum_confidence must be "
            "between 0 and 1"
        )

    registry, assignments = (
        central_registry(
            batch,
            minimum_confidence=(
                minimum_confidence
            ),
        )
    )
    providers = {
        value["provider"]
        for value in assignments
    }
    github_payload = None
    github_policy_payload = None
    gitlab_payload = None
    gitlab_policy_payload = None

    if "github" in providers:
        if github is None:
            raise ValueError(
                "GitHub profiles require GitHub "
                "central policy configuration"
            )

        github_payload, (
            github_policy_payload
        ) = github_plan(
            assignments,
            registry,
            github,
        )

    if "gitlab" in providers:
        if gitlab is None:
            raise ValueError(
                "GitLab profiles require GitLab "
                "central policy configuration"
            )

        gitlab_payload, (
            gitlab_policy_payload
        ) = gitlab_plan(
            assignments,
            gitlab,
        )

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
        "providers": sorted(
            providers
        ),
        "repository_count": len(
            assignments
        ),
        "profile_count": registry[
            "profile_count"
        ],
        "required_count": registry[
            "required_count"
        ],
        "review_count": registry[
            "review_count"
        ],
        "review_requirements": [
            "review-profile-groups",
            "review-repository-assignments",
            "review-central-workflows",
            "review-provider-capabilities",
            "approve-staged-enforcement",
        ],
    }

    return (
        plan,
        registry,
        github_payload,
        github_policy_payload,
        gitlab_payload,
        gitlab_policy_payload,
    )


def write_batch_plan(
    root: str | Path,
    plan: dict[str, Any],
    registry: dict[str, Any],
    github_payload: (
        dict[str, Any] | None
    ),
    github_policy_payload: (
        dict[str, Any] | None
    ),
    gitlab_payload: (
        dict[str, Any] | None
    ),
    gitlab_policy_payload: (
        str | None
    ),
) -> Path:
    root_path = Path(root)
    plan_id = str(
        plan.get("plan_id") or ""
    )

    if not plan_id:
        raise ValueError(
            "Central onboarding plan has "
            "no plan ID"
        )

    staging = (
        root_path / ".staging" / plan_id
    )
    destination = root_path / plan_id

    if destination.exists():
        raise RuntimeError(
            "Central onboarding plan "
            f"already exists: {destination}"
        )

    if staging.exists():
        shutil.rmtree(staging)

    staging.mkdir(
        parents=True,
        exist_ok=False,
    )
    artifact_names = [
        "plan.json",
        "scan-profile-registry.json",
    ]

    try:
        atomic_write_json(
            staging / "plan.json",
            plan,
        )
        atomic_write_json(
            staging
            / "scan-profile-registry.json",
            registry,
        )

        if github_payload is not None:
            atomic_write_json(
                staging / "github-plan.json",
                github_payload,
            )
            artifact_names.append(
                "github-plan.json"
            )

        if (
            github_policy_payload
            is not None
        ):
            atomic_write_json(
                staging
                / "github-ruleset.json",
                github_policy_payload,
            )
            artifact_names.append(
                "github-ruleset.json"
            )

        if gitlab_payload is not None:
            atomic_write_json(
                staging / "gitlab-plan.json",
                gitlab_payload,
            )
            artifact_names.append(
                "gitlab-plan.json"
            )

        if (
            gitlab_policy_payload
            is not None
        ):
            (
                staging
                / "gitlab-policy.yml"
            ).write_text(
                gitlab_policy_payload,
                encoding="utf-8",
            )
            artifact_names.append(
                "gitlab-policy.yml"
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
