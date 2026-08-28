from __future__ import annotations

from typing import Any

from wintermute.scm.providers.gitlab.graphql import (
    GitLabGraphQLClient,
    GraphQLResult,
    normalize_graphql_url,
)


def test_normalize_graphql_url() -> None:
    assert normalize_graphql_url(
        "https://gitlab.example.invalid/api/v4"
    ) == (
        "https://gitlab.example.invalid/api/graphql"
    )


class Client(GitLabGraphQLClient):
    def __init__(self) -> None:
        super().__init__(
            "token",
            endpoint=(
                "https://gitlab.example.invalid/"
                "api/graphql"
            ),
            request_interval_seconds=0,
        )
        self.calls = 0

    def schema(self) -> dict[str, Any]:
        fields = lambda names: {
            "fields": [
                {
                    "name": name,
                    "args": (
                        [
                            {
                                "name": (
                                    "includeSubgroups"
                                )
                            }
                        ]
                        if name == "projects"
                        else []
                    ),
                    "type": {
                        "kind": "OBJECT",
                        "name": "",
                        "ofType": {
                            "kind": "OBJECT",
                            "name": (
                                "RepositoryLanguage"
                                if name == "languages"
                                else "ProjectConnection"
                            ),
                        },
                    },
                }
                for name in names
            ]
        }

        return {
            "project": fields(
                [
                    "id",
                    "fullPath",
                    "name",
                    "webUrl",
                    "visibility",
                    "archived",
                    "lastActivityAt",
                    "repository",
                    "languages",
                ]
            ),
            "group": fields(["projects"]),
            "repository": fields(["rootRef"]),
            "pipeline": fields(
                [
                    "id",
                    "status",
                    "sha",
                    "ref",
                ]
            ),
            "repositoryLanguage": fields(
                ["name", "share"]
            ),
        }

    def execute(
        self,
        query: str,
        variables: dict[str, Any],
        *,
        operation: str,
    ) -> GraphQLResult:
        del query
        del operation
        self.calls += 1
        assert variables["group"] == (
            "group/subgroup"
        )

        return GraphQLResult(
            data={
                "group": {
                    "id": "gid://gitlab/Group/10",
                    "fullPath": "group/subgroup",
                    "projects": {
                        "pageInfo": {
                            "hasNextPage": False,
                            "endCursor": None,
                        },
                        "nodes": [
                            {
                                "id": (
                                    "gid://gitlab/Project/20"
                                ),
                                "fullPath": (
                                    "group/subgroup/service"
                                ),
                                "name": "service",
                                "webUrl": (
                                    "https://gitlab.example.invalid/"
                                    "group/subgroup/service"
                                ),
                                "visibility": "PRIVATE",
                                "archived": False,
                                "lastActivityAt": (
                                    "2026-08-01T00:00:00Z"
                                ),
                                "repository": {
                                    "rootRef": "main"
                                },
                                "languages": [
                                    {
                                        "name": "Python",
                                        "share": 100.0,
                                    }
                                ],
                            }
                        ],
                    },
                }
            },
            errors=(),
        )


def test_graphql_discovers_nested_projects() -> None:
    client = Client()
    projects = client.group_projects(
        "group/subgroup",
        page_size=100,
        pipeline_limit=3,
    )

    assert client.calls == 1
    assert projects[0]["id"] == "20"
    assert projects[0][
        "path_with_namespace"
    ] == "group/subgroup/service"
    assert projects[0][
        "_wintermute_languages"
    ] == {
        "Python": 100.0
    }
