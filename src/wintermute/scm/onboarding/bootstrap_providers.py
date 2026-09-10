from __future__ import annotations

import base64
from typing import Any
from urllib.parse import quote

from wintermute.scm.onboarding.bootstrap import (
    LoadedBootstrapPlan,
)
from wintermute.scm.onboarding.http import (
    OnboardingHttpClient,
)


def github_content_path(
    owner: str,
    repository: str,
    path: str,
) -> str:
    encoded = "/".join(
        quote(part, safe="")
        for part in path.split("/")
    )

    return (
        f"/repos/{quote(owner, safe='')}/"
        f"{quote(repository, safe='')}/"
        f"contents/{encoded}"
    )


def decode_github_content(
    payload: Any,
) -> bytes:
    if (
        not isinstance(payload, dict)
        or payload.get("type") != "file"
        or payload.get("encoding") != "base64"
        or not isinstance(
            payload.get("content"),
            str,
        )
    ):
        raise ValueError(
            "GitHub file response is invalid"
        )

    try:
        return base64.b64decode(
            payload["content"].replace(
                "\n",
                "",
            ),
            validate=True,
        )
    except ValueError as error:
        raise ValueError(
            "GitHub file content is invalid"
        ) from error


class GitHubBootstrapAdapter:
    provider = "github"

    def __init__(
        self,
        client: OnboardingHttpClient,
    ) -> None:
        self.client = client

    def target(
        self,
        bundle: LoadedBootstrapPlan,
    ) -> dict[str, Any]:
        return next(
            value
            for value in bundle.plan[
                "repositories"
            ]
            if value["provider"]
            == self.provider
        )

    def probe(
        self,
        bundle: LoadedBootstrapPlan,
    ) -> dict[str, Any]:
        target = self.target(bundle)
        owner = target["namespace"]
        repository = target["repository"]
        branch = target["default_branch"]
        files = bundle.files[
            self.provider
        ]
        repository_result = (
            self.client.get_json(
                (
                    f"/repos/"
                    f"{quote(owner, safe='')}/"
                    f"{quote(repository, safe='')}"
                ),
                allow_not_found=True,
            )
        )

        if repository_result.status_code == 404:
            actions = [
                {
                    "kind": (
                        "github.repository.create"
                    ),
                },
                *[
                    {
                        "kind": (
                            "github.file.create"
                        ),
                        "path": path,
                    }
                    for path in sorted(files)
                ],
            ]

            return {
                "status": "ready",
                "provider": self.provider,
                "actions": actions,
                "estimated_writes": len(
                    actions
                ),
                "reason": "",
            }

        repository_payload = (
            repository_result.payload
        )

        if not isinstance(
            repository_payload,
            dict,
        ):
            raise ValueError(
                "GitHub repository response "
                "is invalid"
            )

        if (
            repository_payload.get(
                "visibility"
            )
            != "private"
        ):
            return {
                "status": "conflict",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "Existing GitHub central "
                    "repository is not private"
                ),
            }

        if (
            repository_payload.get(
                "default_branch"
            )
            != branch
        ):
            return {
                "status": "conflict",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "Existing GitHub central "
                    "repository uses another "
                    "default branch"
                ),
            }

        ownership_result = (
            self.client.get_json(
                github_content_path(
                    owner,
                    repository,
                    "wintermute-managed.json",
                ),
                params={"ref": branch},
                allow_not_found=True,
            )
        )

        if ownership_result.status_code == 404:
            return {
                "status": "conflict",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "Existing GitHub repository "
                    "has no Wintermute ownership "
                    "manifest"
                ),
            }

        if decode_github_content(
            ownership_result.payload
        ) != files[
            "wintermute-managed.json"
        ]:
            return {
                "status": "conflict",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "Existing GitHub ownership "
                    "manifest differs"
                ),
            }

        actions: list[
            dict[str, Any]
        ] = []

        for path, expected in sorted(
            files.items()
        ):
            result = self.client.get_json(
                github_content_path(
                    owner,
                    repository,
                    path,
                ),
                params={"ref": branch},
                allow_not_found=True,
            )

            if result.status_code == 404:
                actions.append(
                    {
                        "kind": (
                            "github.file.create"
                        ),
                        "path": path,
                    }
                )
                continue

            if (
                decode_github_content(
                    result.payload
                )
                != expected
            ):
                return {
                    "status": "conflict",
                    "provider": self.provider,
                    "actions": [],
                    "reason": (
                        "Customer-modified GitHub "
                        "file will not be overwritten: "
                        f"{path}"
                    ),
                }

        return {
            "status": "ready",
            "provider": self.provider,
            "actions": actions,
            "estimated_writes": len(
                actions
            ),
            "reason": "",
        }

    def apply(
        self,
        bundle: LoadedBootstrapPlan,
        actions: list[dict[str, Any]],
    ) -> int:
        target = self.target(bundle)
        owner = target["namespace"]
        repository = target["repository"]
        branch = target["default_branch"]
        files = bundle.files[
            self.provider
        ]
        writes = 0

        if any(
            action["kind"]
            == "github.repository.create"
            for action in actions
        ):
            created = (
                self.client.mutate_json(
                    "POST",
                    (
                        f"/orgs/"
                        f"{quote(owner, safe='')}/"
                        "repos"
                    ),
                    {
                        "name": repository,
                        "description": (
                            "Customer-owned central "
                            "Wintermute security scans"
                        ),
                        "private": True,
                        "auto_init": True,
                    },
                    expected_statuses={201},
                ).payload
            )
            writes += 1

            if (
                not isinstance(created, dict)
                or created.get(
                    "default_branch"
                )
                != branch
            ):
                raise RuntimeError(
                    "Created GitHub repository "
                    "uses an unexpected default "
                    "branch"
                )

        for action in actions:
            if action["kind"] != (
                "github.file.create"
            ):
                continue

            path = action["path"]
            self.client.mutate_json(
                "PUT",
                github_content_path(
                    owner,
                    repository,
                    path,
                ),
                {
                    "message": (
                        "Initialize Wintermute "
                        f"managed file {path}"
                    ),
                    "content": base64.b64encode(
                        files[path]
                    ).decode("ascii"),
                    "branch": branch,
                },
                expected_statuses={
                    200,
                    201,
                },
            )
            writes += 1

        return writes


class GitLabBootstrapAdapter:
    provider = "gitlab"

    def __init__(
        self,
        client: OnboardingHttpClient,
    ) -> None:
        self.client = client

    def target(
        self,
        bundle: LoadedBootstrapPlan,
    ) -> dict[str, Any]:
        return next(
            value
            for value in bundle.plan[
                "repositories"
            ]
            if value["provider"]
            == self.provider
        )

    def file_path(
        self,
        project: str,
        path: str,
        *,
        raw: bool,
    ) -> str:
        suffix = "/raw" if raw else ""

        return (
            f"/projects/"
            f"{quote(project, safe='')}/"
            "repository/files/"
            f"{quote(path, safe='')}"
            f"{suffix}"
        )

    def creation_namespace_id(
        self,
        target: dict[str, Any],
    ) -> int | None:
        namespace = str(
            target["namespace"]
        )
        namespace_type = str(
            target.get(
                "namespace_type"
            )
            or "group"
        )

        if namespace_type == "user":
            payload = self.client.get_json(
                "/user"
            ).payload

            if not isinstance(payload, dict):
                raise RuntimeError(
                    "GitLab user response "
                    "is invalid"
                )

            username = str(
                payload.get("username") or ""
            )

            if (
                username.casefold()
                != namespace.casefold()
            ):
                raise RuntimeError(
                    "GitLab action token belongs to "
                    f"{username or '<unknown>'}, not "
                    "the planned user namespace "
                    f"{namespace}"
                )

            return None

        if namespace_type != "group":
            raise RuntimeError(
                "GitLab namespace type is invalid"
            )

        payload = self.client.get_json(
            (
                f"/groups/"
                f"{quote(namespace, safe='')}"
            )
        ).payload

        if not isinstance(payload, dict):
            raise RuntimeError(
                "GitLab group response is invalid"
            )

        raw_namespace_id = payload.get("id")

        try:
            namespace_id = int(
                raw_namespace_id
            )
        except (
            TypeError,
            ValueError,
        ) as error:
            raise RuntimeError(
                "GitLab group has no numeric ID"
            ) from error

        if namespace_id < 1:
            raise RuntimeError(
                "GitLab group ID is invalid"
            )

        return namespace_id

    def probe(
        self,
        bundle: LoadedBootstrapPlan,
    ) -> dict[str, Any]:
        target = self.target(bundle)
        self.creation_namespace_id(
            target
        )
        project = target[
            "name_with_owner"
        ]
        branch = target["default_branch"]
        files = bundle.files[
            self.provider
        ]
        project_result = (
            self.client.get_json(
                (
                    f"/projects/"
                    f"{quote(project, safe='')}"
                ),
                allow_not_found=True,
            )
        )

        if project_result.status_code == 404:
            actions = [
                {
                    "kind": (
                        "gitlab.project.create"
                    ),
                },
                *[
                    {
                        "kind": (
                            "gitlab.file.create"
                        ),
                        "path": path,
                    }
                    for path in sorted(files)
                ],
            ]

            return {
                "status": "ready",
                "provider": self.provider,
                "namespace": (
                    target["namespace"]
                ),
                "namespace_type": (
                    target["namespace_type"]
                ),
                "actions": actions,
                "estimated_writes": len(
                    actions
                ),
                "reason": "",
            }

        project_payload = (
            project_result.payload
        )

        if not isinstance(
            project_payload,
            dict,
        ):
            raise ValueError(
                "GitLab project response "
                "is invalid"
            )

        if (
            str(
                project_payload.get(
                    "path_with_namespace"
                )
                or ""
            )
            != project
        ):
            return {
                "status": "conflict",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "GitLab returned another "
                    "project path"
                ),
            }

        if (
            project_payload.get("visibility")
            != "private"
        ):
            return {
                "status": "conflict",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "Existing GitLab central "
                    "project is not private"
                ),
            }

        if (
            project_payload.get(
                "default_branch"
            )
            != branch
        ):
            return {
                "status": "conflict",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "Existing GitLab central "
                    "project uses another "
                    "default branch"
                ),
            }

        ownership = (
            self.client.get_bytes(
                self.file_path(
                    project,
                    "wintermute-managed.json",
                    raw=True,
                ),
                params={"ref": branch},
                allow_not_found=True,
            )
        )

        if ownership.status_code == 404:
            return {
                "status": "conflict",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "Existing GitLab project has "
                    "no Wintermute ownership "
                    "manifest"
                ),
            }

        if bytes(
            ownership.payload
        ) != files[
            "wintermute-managed.json"
        ]:
            return {
                "status": "conflict",
                "provider": self.provider,
                "actions": [],
                "reason": (
                    "Existing GitLab ownership "
                    "manifest differs"
                ),
            }

        actions: list[
            dict[str, Any]
        ] = []

        for path, expected in sorted(
            files.items()
        ):
            result = self.client.get_bytes(
                self.file_path(
                    project,
                    path,
                    raw=True,
                ),
                params={"ref": branch},
                allow_not_found=True,
            )

            if result.status_code == 404:
                actions.append(
                    {
                        "kind": (
                            "gitlab.file.create"
                        ),
                        "path": path,
                    }
                )
                continue

            if bytes(
                result.payload
            ) != expected:
                return {
                    "status": "conflict",
                    "provider": self.provider,
                    "actions": [],
                    "reason": (
                        "Customer-modified GitLab "
                        "file will not be overwritten: "
                        f"{path}"
                    ),
                }

        return {
            "status": "ready",
            "provider": self.provider,
            "namespace": (
                target["namespace"]
            ),
            "namespace_type": (
                target["namespace_type"]
            ),
            "actions": actions,
            "estimated_writes": len(
                actions
            ),
            "reason": "",
        }

    def apply(
        self,
        bundle: LoadedBootstrapPlan,
        actions: list[dict[str, Any]],
    ) -> int:
        target = self.target(bundle)
        namespace_id = (
            self.creation_namespace_id(
                target
            )
        )
        project_name = target[
            "repository"
        ]
        project_path = target[
            "name_with_owner"
        ]
        branch = target["default_branch"]
        files = bundle.files[
            self.provider
        ]
        writes = 0

        if any(
            action["kind"]
            == "gitlab.project.create"
            for action in actions
        ):
            request_body: dict[
                str,
                Any,
            ] = {
                "name": project_name,
                "path": project_name,
                "visibility": "private",
                "initialize_with_readme": True,
                "default_branch": branch,
                "description": (
                    "Customer-owned central "
                    "Wintermute security scans"
                ),
            }

            if namespace_id is not None:
                request_body[
                    "namespace_id"
                ] = namespace_id

            created = (
                self.client.mutate_json(
                    "POST",
                    "/projects",
                    request_body,
                    expected_statuses={201},
                ).payload
            )
            writes += 1

            if (
                not isinstance(created, dict)
                or created.get(
                    "path_with_namespace"
                )
                != project_path
                or created.get(
                    "default_branch"
                )
                != branch
            ):
                raise RuntimeError(
                    "Created GitLab project "
                    "does not match the plan"
                )

        for action in actions:
            if action["kind"] != (
                "gitlab.file.create"
            ):
                continue

            path = action["path"]
            self.client.mutate_json(
                "POST",
                self.file_path(
                    project_path,
                    path,
                    raw=False,
                ),
                {
                    "branch": branch,
                    "content": files[
                        path
                    ].decode("utf-8"),
                    "commit_message": (
                        "Initialize Wintermute "
                        f"managed file {path}"
                    ),
                    "encoding": "text",
                },
                expected_statuses={201},
            )
            writes += 1

        return writes
