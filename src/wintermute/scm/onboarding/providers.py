from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import quote

from wintermute.scm.onboarding.artifacts import (
    LoadedOnboardingPlan,
)
from wintermute.scm.onboarding.http import (
    OnboardingHttpClient,
)


def selected_fields(
    value: dict[str, Any],
    names: tuple[str, ...],
) -> dict[str, Any]:
    return {
        name: value.get(name)
        for name in names
    }


def normalize_ruleset(
    value: dict[str, Any],
) -> dict[str, Any]:
    return selected_fields(
        value,
        (
            "name",
            "target",
            "enforcement",
            "bypass_actors",
            "conditions",
            "rules",
        ),
    )


def repository_parts(
    value: str,
) -> tuple[str, str]:
    selected = str(value or "")

    if (
        selected.count("/") != 1
        or selected.startswith("/")
        or selected.endswith("/")
    ):
        raise ValueError(
            "GitHub repository must use "
            "owner/name"
        )

    return tuple(
        selected.split("/", 1)
    )


class GitHubOnboardingAdapter:
    provider = "github"

    def __init__(
        self,
        client: OnboardingHttpClient,
    ) -> None:
        self.client = client

    def probe(
        self,
        bundle: LoadedOnboardingPlan,
    ) -> dict[str, Any]:
        plan = bundle.plan
        repository = plan["repository"]
        provider_plan = plan["provider_plan"]
        policy = bundle.provider_policy

        if not isinstance(policy, dict):
            raise ValueError(
                "GitHub policy must be JSON"
            )

        organization = str(
            provider_plan.get("organization")
            or ""
        )
        owner, repository_name = (
            repository_parts(
                repository["name_with_owner"]
            )
        )

        if owner.casefold() != (
            organization.casefold()
        ):
            return {
                "status": "blocked",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "Target repository is outside "
                    "the configured organization"
                ),
            }

        encoded_org = quote(
            organization,
            safe="",
        )
        encoded_owner = quote(
            owner,
            safe="",
        )
        encoded_repository = quote(
            repository_name,
            safe="",
        )
        property_condition = (
            policy["conditions"]
            ["repository_property"]
            ["include"][0]
        )
        property_name = str(
            property_condition["name"]
        )
        property_value = str(
            property_condition[
                "property_values"
            ][0]
        )
        schema = self.client.get_json(
            (
                f"/orgs/{encoded_org}/"
                "properties/schema"
            )
        ).payload

        if not isinstance(schema, list):
            raise ValueError(
                "GitHub property schema is invalid"
            )

        definition = next(
            (
                value
                for value in schema
                if (
                    isinstance(value, dict)
                    and value.get(
                        "property_name"
                    )
                    == property_name
                )
            ),
            None,
        )

        if definition is None:
            return {
                "status": "blocked",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "Required GitHub custom property "
                    "does not exist"
                ),
            }

        allowed_values = definition.get(
            "allowed_values"
        )

        if (
            not isinstance(
                allowed_values,
                list,
            )
            or property_value
            not in allowed_values
        ):
            return {
                "status": "blocked",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "Required GitHub custom property "
                    "value is unavailable"
                ),
            }

        assignments = self.client.get_json(
            (
                f"/repos/{encoded_owner}/"
                f"{encoded_repository}/"
                "properties/values"
            )
        ).payload

        if not isinstance(assignments, list):
            raise ValueError(
                "GitHub repository properties "
                "are invalid"
            )

        current_property = next(
            (
                value.get("value")
                for value in assignments
                if (
                    isinstance(value, dict)
                    and value.get(
                        "property_name"
                    )
                    == property_name
                )
            ),
            None,
        )
        workflow = policy["rules"][0][
            "parameters"
        ]["workflows"][0]
        workflow_repository_id = int(
            workflow["repository_id"]
        )
        workflow_repository = (
            self.client.get_json(
                (
                    f"/repositories/"
                    f"{workflow_repository_id}"
                )
            ).payload
        )

        if not isinstance(
            workflow_repository,
            dict,
        ):
            raise ValueError(
                "GitHub workflow repository "
                "is invalid"
            )

        workflow_full_name = str(
            workflow_repository.get(
                "full_name"
            )
            or ""
        )
        workflow_owner, workflow_name = (
            repository_parts(
                workflow_full_name
            )
        )
        workflow_path = str(
            workflow["path"]
        )
        workflow_branch = str(
            workflow["ref"]
        ).removeprefix("refs/heads/")
        content_result = (
            self.client.get_json(
                (
                    f"/repos/"
                    f"{quote(workflow_owner, safe='')}/"
                    f"{quote(workflow_name, safe='')}/"
                    "contents/"
                    + "/".join(
                        quote(part, safe="")
                        for part
                        in workflow_path.split("/")
                    )
                ),
                params={
                    "ref": workflow_branch,
                },
                allow_not_found=True,
            )
        )

        if content_result.status_code == 404:
            return {
                "status": "blocked",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "Required central GitHub workflow "
                    "does not exist"
                ),
            }

        content = content_result.payload

        if (
            not isinstance(content, dict)
            or content.get("type") != "file"
        ):
            return {
                "status": "blocked",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "Required central GitHub workflow "
                    "is not a file"
                ),
            }

        rulesets = self.client.paged_list(
            f"/orgs/{encoded_org}/rulesets",
            params={
                "includes_parents": "false",
            },
        )
        matching = [
            value
            for value in rulesets
            if value.get("name")
            == policy["name"]
        ]

        if len(matching) > 1:
            return {
                "status": "conflict",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "Multiple GitHub rulesets use "
                    "the managed name"
                ),
            }

        existing_ruleset = None

        if matching:
            ruleset_id = int(
                matching[0]["id"]
            )
            existing_ruleset = (
                self.client.get_json(
                    (
                        f"/orgs/{encoded_org}/"
                        f"rulesets/{ruleset_id}"
                    )
                ).payload
            )

            if not isinstance(
                existing_ruleset,
                dict,
            ):
                raise ValueError(
                    "GitHub ruleset detail is invalid"
                )

            normalized_existing = (
                normalize_ruleset(
                    existing_ruleset
                )
            )
            normalized_desired = (
                normalize_ruleset(policy)
            )

            if (
                normalized_existing
                != normalized_desired
                and not (
                    normalized_existing.get(
                        "enforcement"
                    )
                    == "active"
                    and {
                        **normalized_existing,
                        "enforcement": "evaluate",
                    }
                    == normalized_desired
                )
            ):
                return {
                    "status": "conflict",
                    "provider": self.provider,
                    "actions": [],
                    "reason": (
                        "Existing GitHub ruleset differs "
                        "from the reviewed policy"
                    ),
                }

        actions: list[dict[str, Any]] = []

        if current_property != property_value:
            actions.append(
                {
                    "kind": (
                        "github.repository-property.set"
                    ),
                    "repository": (
                        repository["name_with_owner"]
                    ),
                    "property_name": (
                        property_name
                    ),
                    "property_value": (
                        property_value
                    ),
                }
            )

        if existing_ruleset is None:
            actions.append(
                {
                    "kind": (
                        "github.organization-ruleset.create"
                    ),
                    "organization": organization,
                    "name": policy["name"],
                }
            )

        return {
            "status": "ready",
            "provider": self.provider,
            "actions": actions,
            "reason": "",
            "details": {
                "workflow_repository": (
                    workflow_full_name
                ),
                "workflow_path": (
                    workflow_path
                ),
                "workflow_branch": (
                    workflow_branch
                ),
                "ruleset_exists": (
                    existing_ruleset
                    is not None
                ),
                "property_assigned": (
                    current_property
                    == property_value
                ),
            },
        }

    def apply(
        self,
        bundle: LoadedOnboardingPlan,
        actions: list[dict[str, Any]],
    ) -> int:
        policy = bundle.provider_policy
        provider_plan = bundle.plan[
            "provider_plan"
        ]

        if not isinstance(policy, dict):
            raise ValueError(
                "GitHub policy must be JSON"
            )

        organization = str(
            provider_plan["organization"]
        )
        encoded_org = quote(
            organization,
            safe="",
        )
        writes = 0

        for action in actions:
            kind = action["kind"]

            if kind == (
                "github.repository-property.set"
            ):
                _, repository_name = (
                    repository_parts(
                        action["repository"]
                    )
                )
                self.client.mutate_json(
                    "PATCH",
                    (
                        f"/orgs/{encoded_org}/"
                        "properties/values"
                    ),
                    {
                        "repository_names": [
                            repository_name
                        ],
                        "properties": [
                            {
                                "property_name": (
                                    action[
                                        "property_name"
                                    ]
                                ),
                                "value": (
                                    action[
                                        "property_value"
                                    ]
                                ),
                            }
                        ],
                    },
                    expected_statuses={204},
                )
                writes += 1
            elif kind == (
                "github.organization-ruleset.create"
            ):
                self.client.mutate_json(
                    "POST",
                    (
                        f"/orgs/{encoded_org}/"
                        "rulesets"
                    ),
                    policy,
                    expected_statuses={201},
                )
                writes += 1
            else:
                raise ValueError(
                    f"Unsupported GitHub action: "
                    f"{kind}"
                )

        return writes


def nested_project(
    payload: Any,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    nested = payload.get(
        "security_policy_project"
    )

    if isinstance(nested, dict):
        return nested

    return payload


class GitLabOnboardingAdapter:
    provider = "gitlab"

    def __init__(
        self,
        client: OnboardingHttpClient,
    ) -> None:
        self.client = client
        self._branch = ""

    def probe(
        self,
        bundle: LoadedOnboardingPlan,
    ) -> dict[str, Any]:
        provider_plan = bundle.plan[
            "provider_plan"
        ]
        group = str(
            provider_plan["group"]
        )
        policy_project = str(
            provider_plan["policy_project"]
        )
        policy_file = str(
            provider_plan["policy_file"]
        )
        linked_result = (
            self.client.get_json(
                (
                    f"/groups/"
                    f"{quote(group, safe='')}/"
                    "security_policy_project"
                ),
                allow_not_found=True,
            )
        )

        if linked_result.status_code == 404:
            return {
                "status": "blocked",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "GitLab group has no linked "
                    "security-policy project"
                ),
            }

        linked = nested_project(
            linked_result.payload
        )
        project_result = (
            self.client.get_json(
                (
                    f"/projects/"
                    f"{quote(policy_project, safe='')}"
                )
            )
        )
        project = project_result.payload

        if not isinstance(project, dict):
            raise ValueError(
                "GitLab policy project is invalid"
            )

        linked_id = str(
            linked.get("id") or ""
        )
        project_id = str(
            project.get("id") or ""
        )

        if (
            not linked_id
            or linked_id != project_id
        ):
            return {
                "status": "blocked",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "Configured GitLab policy project "
                    "is not linked to the group"
                ),
            }

        branch = str(
            project.get("default_branch")
            or ""
        )

        if not branch:
            return {
                "status": "blocked",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "GitLab policy project has no "
                    "default branch"
                ),
            }

        self._branch = branch
        file_path = (
            f"/projects/"
            f"{quote(policy_project, safe='')}/"
            "repository/files/"
            f"{quote(policy_file, safe='')}"
        )
        raw_result = (
            self.client.get_bytes(
                f"{file_path}/raw",
                params={"ref": branch},
                allow_not_found=True,
            )
        )
        desired = bundle.provider_policy

        if not isinstance(desired, str):
            raise ValueError(
                "GitLab policy must be YAML text"
            )

        if raw_result.status_code == 404:
            actions = [
                {
                    "kind": (
                        "gitlab.disabled-policy-file.create"
                    ),
                    "policy_project": (
                        policy_project
                    ),
                    "policy_file": policy_file,
                    "branch": branch,
                }
            ]
        else:
            content = bytes(
                raw_result.payload
            ).decode(
                "utf-8",
                errors="replace",
            )

            if content != desired:
                return {
                    "status": "conflict",
                    "provider": self.provider,
                    "actions": [],
                    "reason": (
                        "Existing GitLab policy file "
                        "differs from the reviewed policy"
                    ),
                }

            actions = []

        return {
            "status": "ready",
            "provider": self.provider,
            "actions": actions,
            "reason": "",
            "details": {
                "policy_project": (
                    policy_project
                ),
                "policy_file": policy_file,
                "branch": branch,
                "policy_linked": True,
                "policy_enabled": False,
            },
        }

    def apply(
        self,
        bundle: LoadedOnboardingPlan,
        actions: list[dict[str, Any]],
    ) -> int:
        policy = bundle.provider_policy

        if not isinstance(policy, str):
            raise ValueError(
                "GitLab policy must be YAML text"
            )

        writes = 0

        for action in actions:
            if action["kind"] != (
                "gitlab.disabled-policy-file.create"
            ):
                raise ValueError(
                    "Unsupported GitLab onboarding "
                    "action"
                )

            project = str(
                action["policy_project"]
            )
            policy_file = str(
                action["policy_file"]
            )
            self.client.mutate_json(
                "POST",
                (
                    f"/projects/"
                    f"{quote(project, safe='')}/"
                    "repository/files/"
                    f"{quote(policy_file, safe='')}"
                ),
                {
                    "branch": action["branch"],
                    "content": policy,
                    "commit_message": (
                        "Add disabled Wintermute "
                        "Black Duck policy"
                    ),
                },
                expected_statuses={201},
            )
            writes += 1

        return writes
