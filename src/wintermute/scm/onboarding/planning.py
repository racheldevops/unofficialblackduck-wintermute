from __future__ import annotations

import json
import os
import re
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from wintermute.ai.artifacts import (
    LoadedAnalysis,
)
from wintermute.ai.models import (
    stable_digest,
)
from wintermute.ai.scan_profile import (
    BUILD_SYSTEMS,
    CENTRAL_TEMPLATES,
    LAYOUTS,
    SCAN_MODES,
)
from wintermute.ai.storage import (
    atomic_write_json,
    sha256_file,
)


PROPERTY_PATTERN = re.compile(
    r"^[A-Za-z0-9_-]{1,75}$"
)
COMMIT_PATTERN = re.compile(
    r"^[0-9a-f]{40}$"
)
PROJECT_PATH_PATTERN = re.compile(
    r"^[A-Za-z0-9_.-]+"
    r"(?:/[A-Za-z0-9_.-]+)+$"
)


def provider_host_matches(
    provider: str,
    provider_instance: str,
    repository_host: str,
) -> bool:
    selected_instance = str(
        provider_instance or ""
    ).strip().casefold()
    selected_host = str(
        repository_host or ""
    ).strip().casefold()

    if selected_instance == selected_host:
        return True

    return (
        provider == "github"
        and selected_instance.startswith("api.")
        and selected_instance[4:] == selected_host
    )


@dataclass(frozen=True)
class RepositoryTarget:
    provider: str
    provider_instance: str
    repository_id: str
    name_with_owner: str
    canonical_url: str

    def validate(self) -> None:
        if self.provider not in {
            "github",
            "gitlab",
        }:
            raise ValueError(
                "Repository provider must be "
                "github or gitlab"
            )

        if not self.provider_instance.strip():
            raise ValueError(
                "Provider instance is required"
            )

        if not self.repository_id.strip():
            raise ValueError(
                "Repository ID is required"
            )

        if (
            PROJECT_PATH_PATTERN.fullmatch(
                self.name_with_owner
            )
            is None
        ):
            raise ValueError(
                "Repository name must use "
                "namespace/repository"
            )

        parsed = urlsplit(
            self.canonical_url
        )

        if (
            parsed.scheme.casefold() != "https"
            or not provider_host_matches(
                self.provider,
                self.provider_instance,
                parsed.netloc,
            )
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "Repository URL is invalid or belongs "
                "to another provider instance"
            )

    @property
    def key(self) -> str:
        return stable_digest(
            {
                "provider": self.provider,
                "provider_instance": (
                    self.provider_instance
                ),
                "repository_id": (
                    self.repository_id
                ),
            }
        )

    def as_dict(self) -> dict[str, str]:
        return {
            "provider": self.provider,
            "provider_instance": (
                self.provider_instance
            ),
            "repository_id": (
                self.repository_id
            ),
            "name_with_owner": (
                self.name_with_owner
            ),
            "canonical_url": (
                self.canonical_url
            ),
            "repository_key": self.key,
        }


@dataclass(frozen=True)
class GitHubPolicyConfiguration:
    organization: str
    workflow_repository_id: int
    workflow_path: str
    workflow_ref: str
    ruleset_name: str
    property_name: str = (
        "blackduck_sca_policy"
    )
    property_value: str = "required"

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
                "GitHub workflow path must be under "
                ".github/workflows"
            )

        if (
            not self.workflow_ref.startswith(
                "refs/heads/"
            )
            or self.workflow_ref
            == "refs/heads/"
        ):
            raise ValueError(
                "GitHub workflow ref must name "
                "a branch"
            )

        if not self.ruleset_name.strip():
            raise ValueError(
                "GitHub ruleset name is required"
            )

        if (
            PROPERTY_PATTERN.fullmatch(
                self.property_name
            )
            is None
        ):
            raise ValueError(
                "GitHub property name is invalid"
            )

        if not self.property_value.strip():
            raise ValueError(
                "GitHub property value is required"
            )


@dataclass(frozen=True)
class GitLabPolicyConfiguration:
    group: str
    policy_project: str
    policy_file: str
    template_project: str
    template_file: str
    template_ref: str
    policy_name: str

    def validate(self) -> None:
        for field_name in (
            "group",
            "policy_project",
            "template_project",
        ):
            value = getattr(
                self,
                field_name,
            )

            if (
                PROJECT_PATH_PATTERN.fullmatch(
                    value
                )
                is None
                and (
                    field_name != "group"
                    or not value
                    or value.startswith("/")
                    or value.endswith("/")
                )
            ):
                raise ValueError(
                    f"GitLab {field_name} is invalid"
                )

        for field_name in (
            "policy_file",
            "template_file",
        ):
            value = getattr(
                self,
                field_name,
            )
            path = Path(value)

            if (
                not value
                or path.is_absolute()
                or ".." in path.parts
                or path.suffix.casefold()
                not in {".yml", ".yaml"}
            ):
                raise ValueError(
                    f"GitLab {field_name} is invalid"
                )

        if (
            not self.template_ref
            or any(
                character.isspace()
                for character
                in self.template_ref
            )
        ):
            raise ValueError(
                "GitLab template ref is invalid"
            )

        if not self.policy_name.strip():
            raise ValueError(
                "GitLab policy name is required"
            )


def now_text() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def safe_yaml_string(value: str) -> str:
    return json.dumps(
        str(value),
        ensure_ascii=False,
    )


def validate_scan_profile(
    analysis: LoadedAnalysis,
) -> dict[str, Any]:
    profile = analysis.analysis.get(
        "result"
    )

    if not isinstance(profile, dict):
        raise ValueError(
            "AI scan profile is invalid"
        )

    build_systems = profile.get(
        "build_systems"
    )
    package_managers = profile.get(
        "package_managers"
    )
    languages = profile.get("languages")
    evidence_ids = profile.get(
        "evidence_ids"
    )

    for field_name, value in (
        ("build_systems", build_systems),
        (
            "package_managers",
            package_managers,
        ),
        ("languages", languages),
        ("evidence_ids", evidence_ids),
    ):
        if (
            not isinstance(value, list)
            or not all(
                isinstance(item, str)
                and item.strip()
                for item in value
            )
        ):
            raise ValueError(
                f"Scan profile {field_name} "
                "is invalid"
            )

    if not set(build_systems).issubset(
        BUILD_SYSTEMS
    ):
        raise ValueError(
            "Scan profile has unsupported "
            "build systems"
        )

    if (
        profile.get("layout")
        not in LAYOUTS
    ):
        raise ValueError(
            "Scan profile layout is invalid"
        )

    if (
        profile.get("scan_mode")
        not in SCAN_MODES
    ):
        raise ValueError(
            "Scan profile scan mode is invalid"
        )

    if (
        profile.get("central_template")
        not in CENTRAL_TEMPLATES
    ):
        raise ValueError(
            "Scan profile central template "
            "is invalid"
        )

    parameters = profile.get("parameters")

    if not isinstance(parameters, dict):
        raise ValueError(
            "Scan profile parameters are invalid"
        )

    allowed_parameters = {
        "binary_scan",
        "buildless",
        "detector_search_depth",
        "package_manager",
        "project_name_strategy",
    }

    if not set(parameters).issubset(
        allowed_parameters
    ):
        raise ValueError(
            "Scan profile contains unsupported "
            "parameters"
        )

    if (
        "binary_scan" in parameters
        and type(
            parameters["binary_scan"]
        )
        is not bool
    ):
        raise ValueError(
            "binary_scan must be boolean"
        )

    if (
        "buildless" in parameters
        and type(
            parameters["buildless"]
        )
        is not bool
    ):
        raise ValueError(
            "buildless must be boolean"
        )

    if "detector_search_depth" in parameters:
        depth = parameters[
            "detector_search_depth"
        ]

        if (
            type(depth) is not int
            or not 0 <= depth <= 20
        ):
            raise ValueError(
                "detector_search_depth must be "
                "between 0 and 20"
            )

    if "project_name_strategy" in parameters:
        if parameters[
            "project_name_strategy"
        ] not in {
            "provider-id",
            "repository",
            "repository-path",
        }:
            raise ValueError(
                "project_name_strategy is invalid"
            )

    confidence = profile.get(
        "confidence"
    )

    if (
        type(confidence) not in {
            int,
            float,
        }
        or not 0 <= float(confidence) <= 1
    ):
        raise ValueError(
            "Scan profile confidence is invalid"
        )

    known_evidence = {
        str(
            value.get("evidence_id") or ""
        )
        for value
        in analysis.evidence_catalog
    }

    if not set(evidence_ids).issubset(
        known_evidence
    ):
        raise ValueError(
            "Scan profile cites unknown evidence"
        )

    return {
        "schema_version": 1,
        "languages": sorted(
            set(languages)
        ),
        "build_systems": sorted(
            set(build_systems)
        ),
        "package_managers": sorted(
            set(package_managers)
        ),
        "layout": profile["layout"],
        "scan_mode": profile["scan_mode"],
        "central_template": (
            profile["central_template"]
        ),
        "parameters": dict(
            sorted(parameters.items())
        ),
        "confidence": float(confidence),
        "evidence_ids": sorted(
            set(evidence_ids)
        ),
        "conflicts": sorted(
            set(
                str(value)
                for value
                in profile.get(
                    "conflicts",
                    [],
                )
            )
        ),
        "unresolved_questions": sorted(
            set(
                str(value)
                for value
                in profile.get(
                    "unresolved_questions",
                    [],
                )
            )
        ),
    }


def github_ruleset(
    configuration: GitHubPolicyConfiguration,
) -> dict[str, Any]:
    configuration.validate()

    return {
        "name": configuration.ruleset_name,
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
                            .property_name
                        ),
                        "property_values": [
                            configuration
                            .property_value
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
    }


def gitlab_policy(
    configuration: GitLabPolicyConfiguration,
) -> str:
    configuration.validate()

    return "\n".join(
        [
            "pipeline_execution_policy:",
            (
                "  - name: "
                + safe_yaml_string(
                    configuration.policy_name
                )
            ),
            (
                "    description: "
                + safe_yaml_string(
                    "Wintermute central Black Duck "
                    "scan policy"
                )
            ),
            "    enabled: false",
            (
                "    pipeline_config_strategy: "
                "inject_policy"
            ),
            "    content:",
            "      include:",
            (
                "        - project: "
                + safe_yaml_string(
                    configuration
                    .template_project
                )
            ),
            (
                "          file: "
                + safe_yaml_string(
                    configuration
                    .template_file
                )
            ),
            (
                "          ref: "
                + safe_yaml_string(
                    configuration
                    .template_ref
                )
            ),
            "    suffix: on_conflict",
            "",
        ]
    )


def create_plan_id(
    provider: str,
) -> str:
    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")

    return (
        f"{timestamp}-scan-onboarding-"
        f"{provider}-"
        f"{uuid.uuid4().hex[:12]}"
    )


def build_plan(
    analysis: LoadedAnalysis,
    repository: RepositoryTarget,
    *,
    github: (
        GitHubPolicyConfiguration | None
    ) = None,
    gitlab: (
        GitLabPolicyConfiguration | None
    ) = None,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any] | str,
]:
    repository.validate()
    profile = validate_scan_profile(
        analysis
    )

    if repository.provider == "github":
        if (
            github is None
            or gitlab is not None
        ):
            raise ValueError(
                "GitHub repository requires exactly "
                "one GitHub policy configuration"
            )

        provider_policy: (
            dict[str, Any] | str
        ) = github_ruleset(github)
        provider_plan = {
            "provider": "github",
            "mechanism": (
                "organization-required-workflow-"
                "ruleset"
            ),
            "organization": (
                github.organization
            ),
            "stage": "evaluate",
            "activation_requires_confirmation": (
                True
            ),
            "policy_artifact": (
                "provider-policy.json"
            ),
        }
    else:
        if (
            gitlab is None
            or github is not None
        ):
            raise ValueError(
                "GitLab repository requires exactly "
                "one GitLab policy configuration"
            )

        provider_policy = gitlab_policy(
            gitlab
        )
        provider_plan = {
            "provider": "gitlab",
            "mechanism": (
                "pipeline-execution-policy"
            ),
            "group": gitlab.group,
            "policy_project": (
                gitlab.policy_project
            ),
            "policy_file": (
                gitlab.policy_file
            ),
            "stage": "disabled",
            "capability_probe_required": True,
            "activation_requires_confirmation": (
                True
            ),
            "policy_artifact": (
                "provider-policy.yml"
            ),
        }

    registry_entry = {
        "schema_version": 1,
        "repository": repository.as_dict(),
        "analysis": {
            "analysis_id": (
                analysis.analysis[
                    "analysis_id"
                ]
            ),
            "analysis_digest": (
                analysis.digest
            ),
            "model_provider": (
                analysis.analysis[
                    "provider"
                ]
            ),
            "model": (
                analysis.analysis["model"]
            ),
        },
        "scan_profile": profile,
    }
    plan_id = create_plan_id(
        repository.provider
    )
    plan = {
        "schema_version": 1,
        "plan_id": plan_id,
        "created_at": now_text(),
        "status": "review-required",
        "mutation_allowed": False,
        "analysis_id": (
            analysis.analysis["analysis_id"]
        ),
        "analysis_digest": (
            analysis.digest
        ),
        "repository": repository.as_dict(),
        "scan_profile_digest": (
            stable_digest(profile)
        ),
        "provider_plan": provider_plan,
        "review_requirements": [
            "review-scan-profile",
            "review-provider-capability",
            "review-central-template",
            "approve-staged-enforcement",
        ],
    }

    return (
        plan,
        registry_entry,
        provider_policy,
    )


def write_plan(
    root: str | Path,
    plan: dict[str, Any],
    registry_entry: dict[str, Any],
    provider_policy: dict[str, Any] | str,
) -> Path:
    root_path = Path(root)
    plan_id = str(
        plan.get("plan_id") or ""
    )

    if not plan_id:
        raise ValueError(
            "Onboarding plan has no plan ID"
        )

    staging = (
        root_path / ".staging" / plan_id
    )
    destination = root_path / plan_id

    if destination.exists():
        raise RuntimeError(
            f"Onboarding plan already exists: "
            f"{destination}"
        )

    if staging.exists():
        shutil.rmtree(staging)

    staging.mkdir(
        parents=True,
        exist_ok=False,
    )

    if isinstance(
        provider_policy,
        dict,
    ):
        policy_name = (
            "provider-policy.json"
        )
    else:
        policy_name = (
            "provider-policy.yml"
        )

    artifact_names = (
        "plan.json",
        "profile-registry.json",
        policy_name,
    )

    try:
        atomic_write_json(
            staging / "plan.json",
            plan,
        )
        atomic_write_json(
            staging
            / "profile-registry.json",
            registry_entry,
        )

        if isinstance(
            provider_policy,
            dict,
        ):
            atomic_write_json(
                staging / policy_name,
                provider_policy,
            )
        else:
            policy_path = (
                staging / policy_name
            )
            policy_path.write_text(
                provider_policy,
                encoding="utf-8",
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
