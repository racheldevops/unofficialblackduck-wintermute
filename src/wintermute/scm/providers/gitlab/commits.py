from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote, urlencode

from wintermute.scm.providers.gitlab.client import (
    GitLabRepositoryRef,
    GitLabRestClient,
    GitLabRestError,
)


_COMMIT_RE = re.compile(
    r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$"
)
_ENCODED = r"[A-Za-z0-9._~%+-]+"
_MERGE_BASE_PATH = re.compile(
    rf"^/projects/{_ENCODED}/"
    r"repository/merge_base$"
)


def validate_commit(value: str) -> str:
    commit = str(value or "").strip().casefold()

    if not _COMMIT_RE.fullmatch(commit):
        raise ValueError(
            f"Invalid Git commit ID: {value!r}"
        )

    return commit


class GitLabCommitClient(GitLabRestClient):
    def merge_base(
        self,
        repository: GitLabRepositoryRef,
        refs: tuple[str, ...],
    ) -> str:
        if len(refs) < 2:
            raise ValueError(
                "At least two commits are required"
            )

        commits = tuple(
            validate_commit(value)
            for value in refs
        )
        project = quote(
            repository.project_path,
            safe="",
        )
        payload = self.get_json(
            (
                f"/projects/{project}/"
                "repository/merge_base"
            ),
            params={
                "refs[]": commits,
            },
        )

        if not isinstance(payload, dict):
            raise GitLabRestError(
                "invalid_response",
                "GitLab merge-base response "
                "must be an object",
                attempts=1,
            )

        commit = str(
            payload.get("id") or ""
        ).strip().casefold()

        if not _COMMIT_RE.fullmatch(commit):
            raise GitLabRestError(
                "invalid_response",
                "GitLab merge-base response has "
                "an invalid commit ID",
                attempts=1,
            )

        return commit

    def contains_commit(
        self,
        repository: GitLabRepositoryRef,
        ancestor: str,
    ) -> bool:
        selected_ancestor = validate_commit(
            ancestor
        )
        selected_descendant = validate_commit(
            repository.commit
        )

        if (
            selected_ancestor
            == selected_descendant
        ):
            return True

        return (
            self.merge_base(
                repository,
                (
                    selected_ancestor,
                    selected_descendant,
                ),
            )
            == selected_ancestor
        )

    def _validate_path(
        self,
        path: str,
    ) -> None:
        if _MERGE_BASE_PATH.fullmatch(path):
            return

        super()._validate_path(path)

    def _make_url(
        self,
        path: str,
        params: Mapping[str, Any] | None,
    ) -> str:
        url = f"{self.base_url}{path}"

        if not params:
            return url

        values: list[
            tuple[str, str]
        ] = []

        for key, value in params.items():
            if isinstance(
                value,
                (list, tuple),
            ):
                values.extend(
                    (
                        str(key),
                        str(item),
                    )
                    for item in value
                    if item is not None
                )
            elif value is not None:
                values.append(
                    (
                        str(key),
                        str(value),
                    )
                )

        query = urlencode(values)

        if not query:
            return url

        return f"{url}?{query}"


class BudgetedGitLabCommitClient(
    GitLabCommitClient
):
    def __init__(
        self,
        *args: Any,
        maximum_requests: int = 500,
        **kwargs: Any,
    ) -> None:
        if maximum_requests < 1:
            raise ValueError(
                "maximum_requests must be positive"
            )

        self.maximum_requests = (
            maximum_requests
        )
        super().__init__(*args, **kwargs)

    def _increment_request(self) -> None:
        with self._lock:
            if (
                self._requests
                >= self.maximum_requests
            ):
                raise GitLabRestError(
                    "request_budget_exceeded",
                    "GitLab request budget was "
                    "exhausted",
                    attempts=1,
                )

            self._requests += 1
