from __future__ import annotations

from pathlib import Path

from wintermute.scm.controls import (
    ControlKind,
    ControlState,
)
from wintermute.scm.evidence import (
    EvidenceKind,
)
from wintermute.scm.models import (
    Repository,
    RepositoryInventory,
    ScmTenant,
)
from wintermute.scm.protocols import (
    ScmObservationProvider,
)
from wintermute.scm.providers.gitlab.observations import (
    GitLabObservationProvider,
)


class Client:
    provider_instance = (
        "gitlab.example.invalid"
    )

    def ci_config_path(
        self,
        project_id: str,
    ) -> str:
        assert project_id == "20"
        return ".gitlab-ci.yml"

    def try_read_repository_file(
        self,
        repository,
        path,
    ):
        del repository
        assert path == ".gitlab-ci.yml"

        return (
            b"scan:\n"
            b"  script: synopsys-detect\n"
        )

    def project_languages(
        self,
        project_id: str,
    ):
        assert project_id == "20"

        return {
            "Python": 100.0,
        }

    def recent_pipelines(
        self,
        project_id: str,
        *,
        limit: int,
    ):
        assert project_id == "20"
        assert limit == 3

        return (
            {
                "id": 100,
                "status": "success",
                "ref": "main",
                "sha": "a" * 40,
                "created_at": (
                    "2026-08-01T00:00:00Z"
                ),
                "updated_at": (
                    "2026-08-01T00:01:00Z"
                ),
                "web_url": (
                    "https://gitlab.example.invalid/"
                    "group/service/-/pipelines/100"
                ),
            },
        )

    def protected_branch(
        self,
        project_id: str,
        branch: str,
    ):
        assert project_id == "20"
        assert branch == "main"

        return {
            "name": "main",
        }


def tenant() -> ScmTenant:
    return ScmTenant(
        provider="gitlab",
        provider_instance=(
            "gitlab.example.invalid"
        ),
        tenant_id="10",
        namespace="group",
    )


def inventory() -> RepositoryInventory:
    repository = Repository(
        provider="gitlab",
        provider_instance=(
            "gitlab.example.invalid"
        ),
        tenant_id="10",
        repository_id="20",
        namespace="group",
        name="service",
        canonical_url=(
            "https://gitlab.example.invalid/"
            "group/service"
        ),
        default_branch="main",
        head_sha="a" * 40,
        visibility="private",
        activity_status="active",
        languages=("python",),
    )

    return RepositoryInventory(
        repositories=(repository,),
        exclusions=(),
        failures=(),
        discovered_count=1,
    )


def test_gitlab_observations_and_controls(
    tmp_path: Path,
) -> None:
    provider = GitLabObservationProvider(
        Client(),
        capability_cache_path=(
            tmp_path / "capabilities.json"
        ),
    )
    result = provider.observe(
        tenant(),
        inventory(),
    )
    kinds = {
        observation.kind
        for observation
        in result.evidence.observations
    }
    states = {
        observation.control: observation.state
        for observation
        in result.controls.observations
    }

    assert (
        EvidenceKind.REPOSITORY_LANGUAGE
        in kinds
    )
    assert (
        EvidenceKind
        .REPOSITORY_WORKFLOW_INVENTORY
        in kinds
    )
    assert (
        EvidenceKind.REPOSITORY_WORKFLOW
        in kinds
    )
    assert states[
        ControlKind.ONBOARDING_POLICY
    ] == ControlState.COMPLIANT
    assert states[
        ControlKind.REQUIRED_SCAN_WORKFLOW
    ] == ControlState.COMPLIANT
    assert states[
        ControlKind.PROTECTED_DEFAULT_BRANCH
    ] == ControlState.COMPLIANT
    assert result.failure_count == 0


def test_gitlab_observation_provider_contract(
    tmp_path: Path,
) -> None:
    assert isinstance(
        GitLabObservationProvider(
            Client(),
            capability_cache_path=(
                tmp_path / "capabilities.json"
            ),
        ),
        ScmObservationProvider,
    )
