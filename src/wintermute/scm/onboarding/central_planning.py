from __future__ import annotations

import json
import os
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from wintermute.ai.storage import (
    atomic_write_json,
    sha256_file,
)
from wintermute.scm.onboarding.template_artifacts import (
    LoadedTemplatePlan,
)


@dataclass(frozen=True)
class GitHubCentralConfiguration:
    organization: str
    workflow_repository_id: int
    workflow_path: str
    workflow_ref: str
    ruleset_name: str
    policy_property: str = (
        "blackduck_sca_policy"
    )
    profile_property: str = (
        "blackduck_scan_profile"
    )

    def validate(self) -> None:
        if (
            not self.organization
            or "/" in self.organization
        ):
            raise ValueError(
                "GitHub organization is invalid"
            )

        if (
            type(self.workflow_repository_id)
            is not int
            or self.workflow_repository_id < 1
        ):
            raise ValueError(
                "GitHub workflow repository ID "
                "must be positive"
            )

        path = Path(self.workflow_path)

        if (
            path.is_absolute()
            or ".." in path.parts
            or len(path.parts) < 3
            or path.parts[:2]
            != (".github", "workflows")
            or path.suffix.casefold()
            not in {".yml", ".yaml"}
        ):
            raise ValueError(
                "GitHub workflow path is invalid"
            )

        if (
            not self.workflow_ref.startswith(
                "refs/heads/"
            )
            or self.workflow_ref
            == "refs/heads/"
        ):
            raise ValueError(
                "GitHub workflow ref is invalid"
            )

        if not self.ruleset_name:
            raise ValueError(
                "GitHub ruleset name is required"
            )


@dataclass(frozen=True)
class GitLabCentralConfiguration:
    group: str
    policy_project: str
    policy_file: str
    template_project: str
    template_file: str
    template_ref: str
    policy_name: str

    def validate(self) -> None:
        for name in (
            "group",
            "policy_project",
            "template_project",
            "template_file",
            "template_ref",
            "policy_name",
        ):
            if not str(
                getattr(self, name)
            ).strip():
                raise ValueError(
                    f"GitLab {name} is required"
                )

        policy_path = Path(
            self.policy_file
        )

        if (
            policy_path.is_absolute()
            or ".." in policy_path.parts
            or policy_path.suffix.casefold()
            not in {".yml", ".yaml"}
        ):
            raise ValueError(
                "GitLab policy file is invalid"
            )


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
        + "-central-provider-plan-"
        + uuid.uuid4().hex[:12]
    )


def required_assignments(
    template_plan: LoadedTemplatePlan,
) -> list[dict[str, Any]]:
    return [
        dict(value)
        for value
        in template_plan.assignments[
            "assignments"
        ]
        if value["onboarding_policy"]
        == "required"
    ]


def used_contracts(
    template_plan: LoadedTemplatePlan,
    assignments: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    selected_ids = {
        value["scan_contract_id"]
        for value in assignments
    }

    return [
        dict(value)
        for value
        in template_plan.contracts[
            "contracts"
        ]
        if value["scan_contract_id"]
        in selected_ids
    ]


def github_plan(
    assignments: list[dict[str, Any]],
    contracts: list[dict[str, Any]],
    configuration: GitHubCentralConfiguration,
) -> dict[str, Any]:
    configuration.validate()
    selected = [
        value
        for value in assignments
        if value["provider"] == "github"
    ]
    profile_ids = sorted(
        {
            value["scan_contract_id"]
            for value in selected
        }
    )

    return {
        "schema_version": 1,
        "provider": "github",
        "organization": (
            configuration.organization
        ),
        "repository_count": len(selected),
        "property_definitions": [
            {
                "property_name": (
                    configuration.policy_property
                ),
                "value_type": "single_select",
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
                    configuration.profile_property
                ),
                "value_type": "single_select",
                "required": False,
                "default_value": None,
                "description": (
                    "Wintermute approved "
                    "scan contract"
                ),
                "allowed_values": profile_ids,
            },
        ],
        "assignments": [
            {
                "repository_id": (
                    value["repository_id"]
                ),
                "name_with_owner": (
                    value["name_with_owner"]
                ),
                "values": {
                    configuration.policy_property: (
                        "required"
                    ),
                    configuration.profile_property: (
                        value[
                            "scan_contract_id"
                        ]
                    ),
                },
            }
            for value in selected
        ],
        "contracts": [
            value
            for value in contracts
            if value["scan_contract_id"]
            in set(profile_ids)
        ],
        "workflow": {
            "repository_id": (
                configuration
                .workflow_repository_id
            ),
            "path": (
                configuration.workflow_path
            ),
            "ref": (
                configuration.workflow_ref
            ),
        },
        "ruleset": {
            "name": (
                configuration.ruleset_name
            ),
            "target": "branch",
            "enforcement": "evaluate",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {
                    "include": [
                        "~DEFAULT_BRANCH"
                    ],
                    "exclude": [],
                },
                "repository_property": {
                    "include": [
                        {
                            "name": (
                                configuration
                                .policy_property
                            ),
                            "property_values": [
                                "required"
                            ],
                        }
                    ],
                    "exclude": [],
                },
            },
            "rules": [
                {
                    "type": "workflows",
                    "parameters": {
                        "do_not_enforce_on_create": (
                            True
                        ),
                        "workflows": [
                            {
                                "path": (
                                    configuration
                                    .workflow_path
                                ),
                                "ref": (
                                    configuration
                                    .workflow_ref
                                ),
                                "repository_id": (
                                    configuration
                                    .workflow_repository_id
                                ),
                            }
                        ],
                    },
                }
            ],
        },
        "stage": "evaluate",
        "mutation_allowed": False,
    }


def gitlab_policy(
    assignments: list[dict[str, Any]],
    configuration: GitLabCentralConfiguration,
) -> str:
    configuration.validate()
    selected = [
        value
        for value in assignments
        if value["provider"] == "gitlab"
    ]

    if not selected:
        return ""

    lines = [
        "pipeline_execution_policy:",
        (
            "  - name: "
            + json.dumps(
                configuration.policy_name
            )
        ),
        (
            "    description: "
            + json.dumps(
                "Wintermute central "
                "Black Duck scan policy"
            )
        ),
        "    enabled: false",
        "    pipeline_config_strategy: inject_policy",
        "    policy_scope:",
        "      projects:",
        "        including:",
    ]

    for value in selected:
        project_id = str(
            value["repository_id"]
        )

        if not project_id.isdigit():
            raise ValueError(
                "GitLab repository ID must be "
                "numeric for policy scope"
            )

        lines.append(
            f"          - id: {project_id}"
        )

    lines.extend(
        [
            "    content:",
            "      include:",
            (
                "        - project: "
                + json.dumps(
                    configuration
                    .template_project
                )
            ),
            (
                "          file: "
                + json.dumps(
                    configuration
                    .template_file
                )
            ),
            (
                "          ref: "
                + json.dumps(
                    configuration
                    .template_ref
                )
            ),
            "    suffix: on_conflict",
            "",
        ]
    )

    return "\n".join(lines)


def gitlab_plan(
    assignments: list[dict[str, Any]],
    contracts: list[dict[str, Any]],
    configuration: GitLabCentralConfiguration,
) -> tuple[dict[str, Any], str]:
    configuration.validate()
    selected = [
        value
        for value in assignments
        if value["provider"] == "gitlab"
    ]
    contract_ids = {
        value["scan_contract_id"]
        for value in selected
    }

    return (
        {
            "schema_version": 1,
            "provider": "gitlab",
            "group": configuration.group,
            "repository_count": len(
                selected
            ),
            "assignments": [
                {
                    "repository_id": (
                        value["repository_id"]
                    ),
                    "name_with_owner": (
                        value[
                            "name_with_owner"
                        ]
                    ),
                    "scan_contract_id": (
                        value[
                            "scan_contract_id"
                        ]
                    ),
                }
                for value in selected
            ],
            "contracts": [
                value
                for value in contracts
                if value[
                    "scan_contract_id"
                ] in contract_ids
            ],
            "policy_project": (
                configuration.policy_project
            ),
            "policy_file": (
                configuration.policy_file
            ),
            "template_project": (
                configuration.template_project
            ),
            "template_file": (
                configuration.template_file
            ),
            "template_ref": (
                configuration.template_ref
            ),
            "stage": "disabled",
            "mutation_allowed": False,
        },
        gitlab_policy(
            assignments,
            configuration,
        ),
    )


def build_provider_plan(
    template_plan: LoadedTemplatePlan,
    *,
    github: (
        GitHubCentralConfiguration | None
    ) = None,
    gitlab: (
        GitLabCentralConfiguration | None
    ) = None,
) -> tuple[
    dict[str, Any],
    dict[str, Any] | None,
    dict[str, Any] | None,
    str | None,
]:
    assignments = required_assignments(
        template_plan
    )
    contracts = used_contracts(
        template_plan,
        assignments,
    )
    providers = {
        value["provider"]
        for value in assignments
    }
    github_payload = None
    gitlab_payload = None
    gitlab_yaml = None

    if "github" in providers:
        if github is None:
            raise ValueError(
                "Approved GitHub assignments "
                "require GitHub configuration"
            )

        github_payload = github_plan(
            assignments,
            contracts,
            github,
        )

    if "gitlab" in providers:
        if gitlab is None:
            raise ValueError(
                "Approved GitLab assignments "
                "require GitLab configuration"
            )

        (
            gitlab_payload,
            gitlab_yaml,
        ) = gitlab_plan(
            assignments,
            contracts,
            gitlab,
        )

    plan = {
        "schema_version": 1,
        "plan_id": create_plan_id(),
        "created_at": now_text(),
        "status": "review-required",
        "mutation_allowed": False,
        "source_template_plan_id": (
            template_plan.plan["plan_id"]
        ),
        "source_template_plan_digest": (
            template_plan.digest
        ),
        "providers": sorted(providers),
        "repository_count": len(
            assignments
        ),
        "scan_contract_count": len(
            contracts
        ),
        "review_repository_count": (
            template_plan.plan[
                "review_count"
            ]
        ),
        "review_requirements": [
            "review-approved-repositories",
            "review-central-workflows",
            "review-provider-capabilities",
            "approve-staged-enforcement",
        ],
    }

    return (
        plan,
        github_payload,
        gitlab_payload,
        gitlab_yaml,
    )


def write_provider_plan(
    root: str | Path,
    plan: dict[str, Any],
    github_payload: (
        dict[str, Any] | None
    ),
    gitlab_payload: (
        dict[str, Any] | None
    ),
    gitlab_yaml: str | None,
) -> Path:
    root_path = Path(root)
    plan_id = str(
        plan.get("plan_id") or ""
    )
    staging = (
        root_path / ".staging" / plan_id
    )
    destination = root_path / plan_id

    if not plan_id:
        raise ValueError(
            "Provider plan has no plan ID"
        )

    if destination.exists():
        raise RuntimeError(
            f"Provider plan already exists: "
            f"{destination}"
        )

    if staging.exists():
        shutil.rmtree(staging)

    staging.mkdir(
        parents=True,
        exist_ok=False,
    )
    names = ["plan.json"]

    try:
        atomic_write_json(
            staging / "plan.json",
            plan,
        )

        if github_payload is not None:
            atomic_write_json(
                staging / "github-plan.json",
                github_payload,
            )
            names.append(
                "github-plan.json"
            )

        if gitlab_payload is not None:
            atomic_write_json(
                staging / "gitlab-plan.json",
                gitlab_payload,
            )
            names.append(
                "gitlab-plan.json"
            )

        if gitlab_yaml is not None:
            (
                staging / "gitlab-policy.yml"
            ).write_text(
                gitlab_yaml,
                encoding="utf-8",
            )
            names.append(
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
                    for name in names
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
