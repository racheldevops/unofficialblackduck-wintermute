from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from wintermute.scm import cli
from wintermute.scm.models import (
    Repository,
    RepositoryInventory,
    ScmTenant,
)
from wintermute.scm.providers.gitlab.client import (
    GitLabRestError,
)
from wintermute.scm.providers.gitlab.inventory import (
    GitLabClient,
)
from wintermute.scm.snapshots import (
    load_inventory_snapshot,
)


PROJECT_PATH = "rhorner/coverity-python-scan-test"
PROJECT_URL = (
    "https://gitlab.example.invalid/"
    "rhorner/coverity-python-scan-test"
)
COMMIT_SHA = "a" * 40


def project_payload(
    *,
    path: str = PROJECT_PATH,
) -> dict[str, Any]:
    return {
        "id": 10682,
        "name": "coverity-python-scan-test",
        "path_with_namespace": path,
        "web_url": PROJECT_URL,
        "visibility": "private",
        "archived": False,
        "default_branch": "main",
        "last_activity_at": (
            "2026-09-01T00:00:00Z"
        ),
        "forked_from_project": None,
        "ci_config_path": ".gitlab-ci.yml",
        "namespace": {
            "id": 501,
            "path": "rhorner",
            "full_path": "rhorner",
            "kind": "user",
        },
    }


class ExactProjectClient(GitLabClient):
    def __init__(
        self,
        *,
        returned_path: str = PROJECT_PATH,
    ) -> None:
        super().__init__(
            project=PROJECT_PATH,
            token="token",
            base_url=(
                "https://gitlab.example.invalid/api/v4"
            ),
            request_interval_seconds=0,
            clock=lambda: datetime(
                2026,
                9,
                7,
                tzinfo=timezone.utc,
            ),
        )
        self.returned_path = returned_path
        self.paths: list[str] = []

    def get_json(
        self,
        path: str,
        *,
        params=None,
    ) -> Any:
        del params
        self.paths.append(path)

        if path == (
            "/projects/rhorner%2F"
            "coverity-python-scan-test"
        ):
            return project_payload(
                path=self.returned_path
            )

        if path == (
            "/projects/rhorner%2F"
            "coverity-python-scan-test/"
            "repository/commits/main"
        ):
            return {
                "id": COMMIT_SHA,
            }

        if path == (
            "/projects/10682/languages"
        ):
            return {
                "Python": 95.0,
                "Shell": 5.0,
            }

        raise AssertionError(
            f"Unexpected GitLab request: {path}"
        )


def test_exact_project_inventory_uses_no_group_listing() -> None:
    client = ExactProjectClient()
    tenants = client.list_tenants()

    assert tenants == (
        ScmTenant(
            provider="gitlab",
            provider_instance=(
                "gitlab.example.invalid"
            ),
            tenant_id="501",
            namespace="rhorner",
        ),
    )

    inventory = client.inventory(
        tenants[0]
    )

    assert inventory.reconciled is True
    assert inventory.discovered_count == 1
    assert inventory.repository_count == 1
    assert inventory.exclusion_count == 0
    assert inventory.failure_count == 0

    repository = inventory.repositories[0]

    assert repository.repository_id == "10682"
    assert repository.name_with_owner == (
        PROJECT_PATH
    )
    assert repository.default_branch == "main"
    assert repository.head_sha == COMMIT_SHA
    assert repository.languages == ("python",)
    assert client.ci_config_path(
        repository.repository_id
    ) == ".gitlab-ci.yml"
    assert not any(
        path.startswith("/groups/")
        for path in client.paths
    )
    assert client.graphql_stats().requests == 0


def test_exact_project_payload_is_read_once() -> None:
    client = ExactProjectClient()

    first = client.list_tenants()[0]
    inventory = client.inventory(first)

    assert inventory.repository_count == 1
    assert client.paths.count(
        (
            "/projects/rhorner%2F"
            "coverity-python-scan-test"
        )
    ) == 1


def test_exact_project_rejects_different_path() -> None:
    client = ExactProjectClient(
        returned_path="rhorner/other-project"
    )

    with pytest.raises(
        GitLabRestError,
        match="different exact project",
    ):
        client.list_tenants()


def test_exact_project_requires_namespace_project_path() -> None:
    with pytest.raises(
        ValueError,
        match="project path",
    ):
        GitLabClient(
            project="single-segment",
            token="token",
        )


def test_exact_project_and_group_are_mutually_exclusive() -> None:
    with pytest.raises(
        ValueError,
        match="exactly one",
    ):
        GitLabClient(
            group="bd-releng",
            project=PROJECT_PATH,
            token="token",
        )


class StubStats:
    requests = 3
    retries = 0
    rate_remaining = None
    graphql_cost = 0


class StubGitLabClient:
    received: dict[str, Any] = {}
    provider_instance = (
        "gitlab.example.invalid"
    )

    def __init__(
        self,
        group: str,
        token: str,
        *,
        project: str,
        **options: Any,
    ) -> None:
        type(self).received = {
            "group": group,
            "project": project,
            "token": token,
            **options,
        }

    def list_tenants(
        self,
    ) -> tuple[ScmTenant, ...]:
        return (
            ScmTenant(
                provider="gitlab",
                provider_instance=(
                    self.provider_instance
                ),
                tenant_id="501",
                namespace="rhorner",
            ),
        )

    def inventory(
        self,
        tenant: ScmTenant,
    ) -> RepositoryInventory:
        return RepositoryInventory(
            repositories=(
                Repository(
                    provider="gitlab",
                    provider_instance=(
                        self.provider_instance
                    ),
                    tenant_id=tenant.tenant_id,
                    repository_id="10682",
                    namespace="rhorner",
                    name=(
                        "coverity-python-scan-test"
                    ),
                    canonical_url=PROJECT_URL,
                    default_branch="main",
                    head_sha=COMMIT_SHA,
                    visibility="private",
                    archived=False,
                    fork=False,
                    template=False,
                    pushed_at=(
                        "2026-09-01T00:00:00Z"
                    ),
                    activity_status="active",
                    languages=("python",),
                ),
            ),
            exclusions=(),
            failures=(),
            discovered_count=1,
        )

    def graphql_stats(self) -> StubStats:
        return StubStats()

    def stats(self) -> StubStats:
        return StubStats()


def test_cli_writes_exact_project_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    for name in (
        "SCM_URL",
        "GITLAB_GROUP",
        "GITLAB_PROJECT",
        "GITLAB_REST_URL",
        "GITLAB_URL",
    ):
        monkeypatch.delenv(
            name,
            raising=False,
        )

    monkeypatch.setenv(
        "GITLAB_TOKEN",
        "read-token",
    )
    monkeypatch.setattr(
        cli,
        "GitLabClient",
        StubGitLabClient,
    )

    code = cli.main(
        [
            "--scm-url",
            "https://gitlab.example.invalid",
            "--project",
            PROJECT_PATH,
            "--snapshot-root",
            str(tmp_path / "snapshots"),
            "--snapshot-id",
            "exact-project",
            "--skip-provider-evidence",
        ]
    )
    summary = json.loads(
        capsys.readouterr().out
    )
    snapshot = load_inventory_snapshot(
        summary["snapshot_directory"]
    )

    assert code == 0
    assert summary["status"] == "succeeded"
    assert summary["selection_mode"] == "project"
    assert summary["selected_project"] == (
        PROJECT_PATH
    )
    assert summary[
        "discovered_repository_count"
    ] == 1
    assert snapshot.tenant.namespace == "rhorner"
    assert (
        snapshot.inventory.repositories[0]
        .head_sha
        == COMMIT_SHA
    )
    assert StubGitLabClient.received["group"] == ""
    assert StubGitLabClient.received["project"] == (
        PROJECT_PATH
    )
    assert StubGitLabClient.received["token"] == (
        "read-token"
    )


def test_project_option_selects_gitlab_without_group() -> None:
    args = cli.parse_args(
        [
            "--project",
            PROJECT_PATH,
        ]
    )

    assert cli.provider_name(args) == "gitlab"


def test_exact_project_validation_ignores_group_environment_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "GITLAB_GROUP",
        "bd-releng",
    )
    args = cli.parse_args(
        [
            "--project",
            PROJECT_PATH,
        ]
    )

    cli.validate_args(args)

    assert args.group == "bd-releng"
    assert args.project == PROJECT_PATH
