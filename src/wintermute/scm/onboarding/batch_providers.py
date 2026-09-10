from __future__ import annotations

import json
from collections import defaultdict
from typing import Any
from urllib.parse import quote

from wintermute.scm.onboarding.batch_artifacts import (
    LoadedBatchOnboardingPlan,
)
from wintermute.scm.onboarding.http import (
    OnboardingHttpClient,
)


MAX_PROPERTY_VALUES = 200
MAX_ASSIGNMENT_BATCH = 30


def normalize_ruleset(
    value: dict[str, Any],
) -> dict[str, Any]:
    return {
        name: value.get(name)
        for name in (
            "name",
            "target",
            "enforcement",
            "bypass_actors",
            "conditions",
            "rules",
        )
    }


def property_values(
    value: Any,
) -> dict[str, Any]:
    if not isinstance(value, list):
        return {}

    result: dict[str, Any] = {}

    for item in value:
        if not isinstance(item, dict):
            continue

        name = str(
            item.get("property_name")
            or ""
        )

        if name:
            result[name] = item.get(
                "value"
            )

    return result


def assignment_values(
    value: dict[str, Any],
) -> dict[str, Any]:
    properties = value.get("properties")

    return property_values(properties)


def definition_body(
    value: dict[str, Any],
) -> dict[str, Any]:
    body = {
        "value_type": value["value_type"],
        "required": bool(
            value.get("required", False)
        ),
        "default_value": value.get(
            "default_value"
        ),
        "description": str(
            value.get("description")
            or ""
        ),
    }

    if value["value_type"] in {
        "single_select",
        "multi_select",
    }:
        body["allowed_values"] = list(
            value["allowed_values"]
        )

    return body


def grouped_assignment_writes(
    actions: list[dict[str, Any]],
) -> int:
    grouped: dict[str, int] = defaultdict(
        int
    )

    for action in actions:
        if action["kind"] != (
            "github.repository-properties.set"
        ):
            continue

        key = json.dumps(
            action["values"],
            sort_keys=True,
            separators=(",", ":"),
        )
        grouped[key] += 1

    return sum(
        (count + MAX_ASSIGNMENT_BATCH - 1)
        // MAX_ASSIGNMENT_BATCH
        for count in grouped.values()
    )


class GitHubBatchOnboardingAdapter:
    provider = "github"

    def __init__(
        self,
        client: OnboardingHttpClient,
    ) -> None:
        self.client = client

    def estimated_writes(
        self,
        actions: list[dict[str, Any]],
    ) -> int:
        direct = sum(
            action["kind"]
            in {
                "github.property-definition.put",
                "github.organization-ruleset.create",
            }
            for action in actions
        )

        return (
            direct
            + grouped_assignment_writes(
                actions
            )
        )

    def probe(
        self,
        bundle: LoadedBatchOnboardingPlan,
    ) -> dict[str, Any]:
        plan = bundle.github_plan
        ruleset = bundle.github_ruleset

        if (
            plan is None
            or ruleset is None
        ):
            raise ValueError(
                "GitHub batch plan is unavailable"
            )

        organization = str(
            plan.get("organization") or ""
        )

        if not organization:
            raise ValueError(
                "GitHub organization is missing"
            )

        encoded_org = quote(
            organization,
            safe="",
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

        existing_definitions = {
            str(
                value.get("property_name")
                or ""
            ): value
            for value in schema
            if (
                isinstance(value, dict)
                and value.get(
                    "property_name"
                )
            )
        }
        actions: list[dict[str, Any]] = []

        for desired in plan[
            "property_definitions"
        ]:
            name = str(
                desired["property_name"]
            )
            existing = (
                existing_definitions.get(name)
            )

            if existing is None:
                actions.append(
                    {
                        "kind": (
                            "github.property-definition.put"
                        ),
                        "definition": desired,
                    }
                )
                continue

            if (
                existing.get("value_type")
                != desired["value_type"]
            ):
                return {
                    "status": "conflict",
                    "provider": self.provider,
                    "actions": [],
                    "reason": (
                        f"GitHub property {name} "
                        "has a different type"
                    ),
                }

            desired_allowed = desired.get(
                "allowed_values"
            )
            current_allowed = existing.get(
                "allowed_values"
            )

            if not isinstance(
                desired_allowed,
                list,
            ):
                return {
                    "status": "conflict",
                    "provider": self.provider,
                    "actions": [],
                    "reason": (
                        f"GitHub property {name} "
                        "has invalid desired values"
                    ),
                }

            if not isinstance(
                current_allowed,
                list,
            ):
                return {
                    "status": "conflict",
                    "provider": self.provider,
                    "actions": [],
                    "reason": (
                        f"GitHub property {name} "
                        "has invalid current values"
                    ),
                }

            merged = sorted(
                set(
                    str(value)
                    for value
                    in current_allowed
                )
                | set(
                    str(value)
                    for value
                    in desired_allowed
                )
            )

            if len(merged) > MAX_PROPERTY_VALUES:
                return {
                    "status": "blocked",
                    "provider": self.provider,
                    "actions": [],
                    "reason": (
                        f"GitHub property {name} "
                        "exceeds the allowed-value limit"
                    ),
                }

            if merged != sorted(
                str(value)
                for value in current_allowed
            ):
                actions.append(
                    {
                        "kind": (
                            "github.property-definition.put"
                        ),
                        "definition": {
                            "property_name": name,
                            "value_type": (
                                existing[
                                    "value_type"
                                ]
                            ),
                            "required": bool(
                                existing.get(
                                    "required",
                                    False,
                                )
                            ),
                            "default_value": (
                                existing.get(
                                    "default_value"
                                )
                            ),
                            "description": str(
                                existing.get(
                                    "description"
                                )
                                or desired.get(
                                    "description"
                                )
                                or ""
                            ),
                            "allowed_values": (
                                merged
                            ),
                        },
                    }
                )

        workflow = plan["workflow"]
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

        workflow_name = str(
            workflow_repository.get(
                "full_name"
            )
            or ""
        )

        if workflow_name.count("/") != 1:
            return {
                "status": "blocked",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "GitHub workflow repository "
                    "has an invalid name"
                ),
            }

        workflow_owner, repository_name = (
            workflow_name.split("/", 1)
        )
        workflow_path = str(
            workflow["path"]
        )
        workflow_branch = str(
            workflow["ref"]
        ).removeprefix("refs/heads/")
        content_path = "/".join(
            quote(part, safe="")
            for part in workflow_path.split("/")
        )
        workflow_result = (
            self.client.get_json(
                (
                    f"/repos/"
                    f"{quote(workflow_owner, safe='')}/"
                    f"{quote(repository_name, safe='')}/"
                    f"contents/{content_path}"
                ),
                params={
                    "ref": workflow_branch,
                },
                allow_not_found=True,
            )
        )

        if workflow_result.status_code == 404:
            return {
                "status": "blocked",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "Central GitHub workflow "
                    "does not exist"
                ),
            }

        assignments = self.client.paged_list(
            (
                f"/orgs/{encoded_org}/"
                "properties/values"
            )
        )
        current_by_name = {
            str(
                value.get(
                    "repository_full_name"
                )
                or ""
            ).casefold(): (
                assignment_values(value)
            )
            for value in assignments
            if value.get(
                "repository_full_name"
            )
        }

        for desired in plan["assignments"]:
            name = str(
                desired["name_with_owner"]
            )
            current = current_by_name.get(
                name.casefold(),
                {},
            )
            wanted = desired["values"]

            if any(
                current.get(key) != value
                for key, value
                in wanted.items()
            ):
                actions.append(
                    {
                        "kind": (
                            "github.repository-properties.set"
                        ),
                        "name_with_owner": name,
                        "values": wanted,
                    }
                )

        summaries = self.client.paged_list(
            f"/orgs/{encoded_org}/rulesets",
            params={
                "includes_parents": "false",
            },
        )
        matching = [
            value
            for value in summaries
            if value.get("name")
            == ruleset["name"]
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

        if matching:
            ruleset_id = int(
                matching[0]["id"]
            )
            existing = self.client.get_json(
                (
                    f"/orgs/{encoded_org}/"
                    f"rulesets/{ruleset_id}"
                )
            ).payload

            if not isinstance(existing, dict):
                raise ValueError(
                    "GitHub ruleset is invalid"
                )

            if (
                normalize_ruleset(existing)
                != normalize_ruleset(ruleset)
            ):
                return {
                    "status": "conflict",
                    "provider": self.provider,
                    "actions": [],
                    "reason": (
                        "Existing GitHub ruleset differs "
                        "from the evaluated plan"
                    ),
                }
        else:
            actions.append(
                {
                    "kind": (
                        "github.organization-ruleset.create"
                    ),
                    "organization": organization,
                    "name": ruleset["name"],
                }
            )

        return {
            "status": "ready",
            "provider": self.provider,
            "actions": actions,
            "estimated_writes": (
                self.estimated_writes(
                    actions
                )
            ),
            "reason": "",
        }

    def apply(
        self,
        bundle: LoadedBatchOnboardingPlan,
        actions: list[dict[str, Any]],
    ) -> int:
        plan = bundle.github_plan
        ruleset = bundle.github_ruleset

        if (
            plan is None
            or ruleset is None
        ):
            raise ValueError(
                "GitHub batch plan is unavailable"
            )

        organization = str(
            plan["organization"]
        )
        encoded_org = quote(
            organization,
            safe="",
        )
        writes = 0

        definitions = [
            value
            for value in actions
            if value["kind"]
            == "github.property-definition.put"
        ]

        for action in definitions:
            definition = action["definition"]
            name = str(
                definition["property_name"]
            )
            self.client.mutate_json(
                "PUT",
                (
                    f"/orgs/{encoded_org}/"
                    "properties/schema/"
                    f"{quote(name, safe='')}"
                ),
                definition_body(definition),
                expected_statuses={
                    200,
                    201,
                },
            )
            writes += 1

        assignments = [
            value
            for value in actions
            if value["kind"]
            == "github.repository-properties.set"
        ]
        grouped: dict[
            str,
            list[dict[str, Any]],
        ] = defaultdict(list)

        for action in assignments:
            key = json.dumps(
                action["values"],
                sort_keys=True,
                separators=(",", ":"),
            )
            grouped[key].append(action)

        for key in sorted(grouped):
            values = json.loads(key)
            group = grouped[key]

            for offset in range(
                0,
                len(group),
                MAX_ASSIGNMENT_BATCH,
            ):
                batch = group[
                    offset:
                    offset
                    + MAX_ASSIGNMENT_BATCH
                ]
                repository_names = [
                    value[
                        "name_with_owner"
                    ].split("/", 1)[1]
                    for value in batch
                ]
                properties = [
                    {
                        "property_name": name,
                        "value": value,
                    }
                    for name, value
                    in sorted(values.items())
                ]
                self.client.mutate_json(
                    "PATCH",
                    (
                        f"/orgs/{encoded_org}/"
                        "properties/values"
                    ),
                    {
                        "repository_names": (
                            repository_names
                        ),
                        "properties": properties,
                    },
                    expected_statuses={204},
                )
                writes += 1

        if any(
            value["kind"]
            == "github.organization-ruleset.create"
            for value in actions
        ):
            self.client.mutate_json(
                "POST",
                (
                    f"/orgs/{encoded_org}/"
                    "rulesets"
                ),
                ruleset,
                expected_statuses={201},
            )
            writes += 1

        return writes


def nested_policy_project(
    value: Any,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}

    nested = value.get(
        "security_policy_project"
    )

    return (
        nested
        if isinstance(nested, dict)
        else value
    )


class GitLabBatchOnboardingAdapter:
    provider = "gitlab"

    def __init__(
        self,
        client: OnboardingHttpClient,
    ) -> None:
        self.client = client

    def estimated_writes(
        self,
        actions: list[dict[str, Any]],
    ) -> int:
        return len(actions)

    def probe(
        self,
        bundle: LoadedBatchOnboardingPlan,
    ) -> dict[str, Any]:
        plan = bundle.gitlab_plan
        policy = bundle.gitlab_policy

        if (
            plan is None
            or policy is None
        ):
            raise ValueError(
                "GitLab batch plan is unavailable"
            )

        if "enabled: false" not in policy:
            return {
                "status": "blocked",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "GitLab policy is not disabled"
                ),
            }

        group = str(plan["group"])
        policy_project = str(
            plan["policy_project"]
        )
        template_project = str(
            plan["template_project"]
        )
        template_file = str(
            plan["template_file"]
        )
        template_ref = str(
            plan["template_ref"]
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

        linked = nested_policy_project(
            linked_result.payload
        )
        policy_project_result = (
            self.client.get_json(
                (
                    f"/projects/"
                    f"{quote(policy_project, safe='')}"
                )
            )
        )
        project = policy_project_result.payload

        if not isinstance(project, dict):
            raise ValueError(
                "GitLab policy project is invalid"
            )

        if str(
            linked.get("id") or ""
        ) != str(
            project.get("id") or ""
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

        template_result = (
            self.client.get_json(
                (
                    f"/projects/"
                    f"{quote(template_project, safe='')}"
                )
            )
        )

        if not isinstance(
            template_result.payload,
            dict,
        ):
            raise ValueError(
                "GitLab template project is invalid"
            )

        template_read = (
            self.client.get_bytes(
                (
                    f"/projects/"
                    f"{quote(template_project, safe='')}/"
                    "repository/files/"
                    f"{quote(template_file, safe='')}/"
                    "raw"
                ),
                params={
                    "ref": template_ref,
                },
                allow_not_found=True,
            )
        )

        if template_read.status_code == 404:
            return {
                "status": "blocked",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "GitLab central scan template "
                    "does not exist"
                ),
            }

        policy_file = str(
            plan["policy_file"]
        )
        policy_read = self.client.get_bytes(
            (
                f"/projects/"
                f"{quote(policy_project, safe='')}/"
                "repository/files/"
                f"{quote(policy_file, safe='')}/"
                "raw"
            ),
            params={"ref": branch},
            allow_not_found=True,
        )

        if policy_read.status_code == 404:
            actions = [
                {
                    "kind": (
                        "gitlab.disabled-policy-file.create"
                    ),
                    "policy_project": (
                        policy_project
                    ),
                    "policy_file": (
                        policy_file
                    ),
                    "branch": branch,
                }
            ]
        else:
            current = bytes(
                policy_read.payload
            ).decode(
                "utf-8",
                errors="replace",
            )

            if current != policy:
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
            "estimated_writes": len(actions),
            "reason": "",
        }

    def apply(
        self,
        bundle: LoadedBatchOnboardingPlan,
        actions: list[dict[str, Any]],
    ) -> int:
        policy = bundle.gitlab_policy

        if policy is None:
            raise ValueError(
                "GitLab policy is unavailable"
            )

        writes = 0

        for action in actions:
            if action["kind"] != (
                "gitlab.disabled-policy-file.create"
            ):
                raise ValueError(
                    "Unsupported GitLab batch action"
                )

            self.client.mutate_json(
                "POST",
                (
                    f"/projects/"
                    f"{quote(action['policy_project'], safe='')}/"
                    "repository/files/"
                    f"{quote(action['policy_file'], safe='')}"
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
