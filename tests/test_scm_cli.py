from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any

import pytest

from wintermute.scm import cli
from wintermute.scm.models import (
    InventoryFailure,
    Repository,
    RepositoryInventory,
    ScmTenant,
)
from wintermute.scm.snapshots import (
    load_inventory_snapshot,
)


class StubStats:
    requests = 3
    retries = 0
    graphql_cost = 4
    rate_remaining = 4996


class StubGitHubClient:
    received: dict[str, Any] = {}
    result: RepositoryInventory

    def __init__(
        self,
        organization: str,
        token: str,
        **options: Any,
    ) -> None:
        type(self).received = {
            "organization": organization,
            "token": token,
            **options,
        }

    def list_tenants(
        self,
    ) -> tuple[ScmTenant, ...]:
        return (
            ScmTenant(
                provider="github",
                provider_instance="github.example",
                tenant_id="O_acme",
                namespace="acme",
            ),
        )

    def inventory(
        self,
        tenant: ScmTenant,
    ) -> RepositoryInventory:
        assert tenant.tenant_id == "O_acme"
        return type(self).result

    def stats(self) -> StubStats:
        return StubStats()


def repository() -> Repository:
    return Repository(
        provider="github",
        provider_instance="github.example",
        tenant_id="O_acme",
        repository_id="R_service",
        namespace="acme",
        name="service",
        canonical_url=(
            "https://github.example/acme/service"
        ),
        visibility="private",
        activity_status="active",
        languages=("python",),
    )


def test_inventory_cli_writes_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    StubGitHubClient.result = (
        RepositoryInventory(
            repositories=(repository(),),
            exclusions=(),
            failures=(),
            discovered_count=1,
        )
    )
    monkeypatch.setattr(
        cli,
        "GitHubClient",
        StubGitHubClient,
    )
    monkeypatch.setenv(
        "GITHUB_TOKEN",
        "test-token",
    )
    id_path = tmp_path / "snapshot-id"

    result = cli.main(
        [
            "--organization",
            "acme",
            "--graphql-endpoint",
            (
                "https://github.example/"
                "api/graphql"
            ),
            "--snapshot-root",
            str(tmp_path / "snapshots"),
            "--snapshot-id",
            "snapshot-1",
            "--snapshot-id-out",
            str(id_path),
        ]
    )
    summary = json.loads(
        capsys.readouterr().out
    )
    loaded = load_inventory_snapshot(
        summary["snapshot_directory"]
    )

    assert result == 0
    assert summary["status"] == "succeeded"
    assert loaded.inventory.repository_count == 1
    assert id_path.read_text(
        encoding="utf-8"
    ) == "snapshot-1\n"
    assert (
        StubGitHubClient.received["token"]
        == "test-token"
    )


def test_inventory_cli_returns_partial_status(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    failure = InventoryFailure(
        provider="github",
        provider_instance="github.example",
        tenant_id="O_acme",
        repository_id="R_failed",
        name_with_owner="acme/failed",
        stage="map-repository",
        error="invalid response",
    )
    StubGitHubClient.result = (
        RepositoryInventory(
            repositories=(repository(),),
            exclusions=(),
            failures=(failure,),
            discovered_count=2,
        )
    )
    monkeypatch.setattr(
        cli,
        "GitHubClient",
        StubGitHubClient,
    )
    monkeypatch.setenv(
        "GITHUB_TOKEN",
        "test-token",
    )

    result = cli.main(
        [
            "--organization",
            "acme",
            "--snapshot-root",
            str(tmp_path),
            "--snapshot-id",
            "partial",
        ]
    )
    summary = json.loads(
        capsys.readouterr().out
    )

    assert result == 1
    assert summary["status"] == "partial"
    assert summary["failure_count"] == 1


def test_inventory_cli_requires_token(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv(
        "GITHUB_TOKEN",
        raising=False,
    )

    result = cli.main(
        [
            "--organization",
            "acme",
            "--snapshot-root",
            str(tmp_path),
        ]
    )

    assert result == 2
    assert "GITHUB_TOKEN must be set" in (
        capsys.readouterr().err
    )


def test_inventory_cli_tls_options_are_exclusive() -> None:
    with pytest.raises(SystemExit):
        cli.parse_args(
            [
                "--insecure",
                "--ca-bundle",
                "/tmp/ca.pem",
            ]
        )


def test_pyproject_registers_scm_inventory() -> None:
    root = Path(__file__).resolve().parents[1]
    configuration = tomllib.loads(
        (root / "pyproject.toml").read_text(
            encoding="utf-8"
        )
    )

    assert configuration["project"]["scripts"][
        "blackduck-wintermute-scm-inventory"
    ] == "wintermute.scm.cli:main"


@pytest.fixture(autouse=True)
def stub_provider_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StubRestClient:
        provider_instance = "github.example"

        def __init__(
            self,
            *_args: object,
            **_kwargs: object,
        ) -> None:
            pass

        def stats(self) -> StubStats:
            return StubStats()

    class StubObservationProvider:
        def __init__(
            self,
            *_args: object,
            **_kwargs: object,
        ) -> None:
            pass

        def observe(
            self,
            tenant: ScmTenant,
            inventory: RepositoryInventory,
        ) -> object:
            del tenant, inventory

            from wintermute.scm.controls import (
                ControlInventory,
            )
            from wintermute.scm.evidence import (
                EvidenceInventory,
            )
            from wintermute.scm.observations import (
                ScmObservationResult,
            )

            return ScmObservationResult(
                evidence=EvidenceInventory(
                    observations=()
                ),
                controls=ControlInventory(
                    observations=()
                ),
            )

    monkeypatch.setattr(
        cli,
        "GitHubRestClient",
        StubRestClient,
    )
    monkeypatch.setattr(
        cli,
        "GitHubObservationProvider",
        StubObservationProvider,
    )
