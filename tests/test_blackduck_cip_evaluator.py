from __future__ import annotations

from wintermute.blackduck.actions.models import (
    ActionTarget,
    stable_digest,
)
from wintermute.blackduck.jobs.cip.evaluator import (
    CipFixRecord,
    assess_fix,
    build_remediation_action,
)
from wintermute.scm.providers.gitlab.client import (
    GitLabRepositoryRef,
)


BASE_URL = "https://blackduck.example.invalid"


class Client:
    def __init__(
        self,
        included: set[str],
    ) -> None:
        self.included = included

    def contains_commit(
        self,
        repository: GitLabRepositoryRef,
        ancestor: str,
    ) -> bool:
        del repository
        return ancestor in self.included


def record(
    commits: tuple[str, ...],
) -> CipFixRecord:
    return CipFixRecord(
        cve="CVE-2026-0001",
        branch="cip/6.1",
        fix_commits=commits,
        security_repository=(
            "https://gitlab.example.invalid/"
            "cip/cip-kernel-sec"
        ),
        security_revision="c" * 40,
        source_path=(
            "issues/CVE-2026-0001.yml"
        ),
        source_digest=stable_digest(
            {"cve": "CVE-2026-0001"}
        ),
    )


def repository() -> GitLabRepositoryRef:
    return GitLabRepositoryRef(
        repository_url=(
            "https://gitlab.example.invalid/"
            "cip/linux-cip"
        ),
        project_path="cip/linux-cip",
        revision="v6.1.173-cip56",
        commit="a" * 40,
    )


def target() -> ActionTarget:
    return ActionTarget(
        resource_type=(
            "vulnerability-remediation"
        ),
        resource_href=(
            f"{BASE_URL}/api/projects/p/"
            "versions/v/components/c/"
            "versions/cv/origins/o/"
            "vulnerabilities/x/remediation"
        ),
        project_version_href=(
            f"{BASE_URL}/api/projects/p/"
            "versions/v"
        ),
        identifiers={
            "vulnerability": "CVE-2026-0001",
        },
    )


def test_all_commits_are_required() -> None:
    first = "1" * 40
    second = "2" * 40
    assessment = assess_fix(
        Client({first}),
        repository(),
        tag="v6.1.173-cip56",
        record=record(
            (first, second)
        ),
    )

    assert (
        assessment.status
        == "fix-not-contained"
    )
    assert assessment.missing_commits == (
        second,
    )


def test_fixed_assessment_builds_action() -> None:
    commit = "1" * 40
    assessment = assess_fix(
        Client({commit}),
        repository(),
        tag="v6.1.173-cip56",
        record=record((commit,)),
    )
    action = build_remediation_action(
        assessment,
        blackduck_target=target(),
        observed_state={
            "remediation_status": "NEW",
            "comment": "",
            "owner": "",
        },
        desired_status="PATCHED",
        assessed_at=(
            "2026-08-26T12:00:00Z"
        ),
    )

    assert assessment.remediable is True
    assert action is not None
    assert (
        action.desired[
            "remediation_status"
        ]
        == "PATCHED"
    )


def test_missing_fix_does_not_build_action() -> None:
    commit = "1" * 40
    assessment = assess_fix(
        Client(set()),
        repository(),
        tag="v6.1.173-cip56",
        record=record((commit,)),
    )

    assert build_remediation_action(
        assessment,
        blackduck_target=target(),
        observed_state={
            "remediation_status": "NEW",
            "comment": "",
            "owner": "",
        },
        desired_status="PATCHED",
        assessed_at=(
            "2026-08-26T12:00:00Z"
        ),
    ) is None
