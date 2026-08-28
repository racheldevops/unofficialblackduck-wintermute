from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from wintermute.blackduck.actions.models import (
    ActionEvidence,
    ActionOwnership,
    ActionTarget,
    BlackDuckAction,
    json_copy,
    stable_digest,
)
from wintermute.scm.providers.gitlab.client import (
    GitLabRepositoryRef,
)
from wintermute.scm.providers.gitlab.commits import (
    GitLabCommitClient,
)


_CVE_RE = re.compile(
    r"^CVE-[0-9]{4}-[0-9]{4,}$",
    re.IGNORECASE,
)
_COMMIT_RE = re.compile(
    r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$"
)


@dataclass(frozen=True)
class CipFixRecord:
    cve: str
    branch: str
    fix_commits: tuple[str, ...]
    security_repository: str
    security_revision: str
    source_path: str
    source_digest: str

    def validate(self) -> None:
        if not _CVE_RE.fullmatch(self.cve):
            raise ValueError(
                f"Invalid CVE: {self.cve!r}"
            )

        if not self.branch.strip():
            raise ValueError(
                "CIP branch is required"
            )

        if not self.fix_commits:
            raise ValueError(
                "At least one fix commit is required"
            )

        for commit in self.fix_commits:
            if not _COMMIT_RE.fullmatch(
                commit.casefold()
            ):
                raise ValueError(
                    f"Invalid fix commit: {commit!r}"
                )

        if not self.security_repository.strip():
            raise ValueError(
                "Security repository is required"
            )

        if not _COMMIT_RE.fullmatch(
            self.security_revision.casefold()
        ):
            raise ValueError(
                "Security revision must be a commit"
            )

        if not self.source_path.strip():
            raise ValueError(
                "Security source path is required"
            )

        if not re.fullmatch(
            r"sha256:[a-f0-9]{64}",
            self.source_digest,
        ):
            raise ValueError(
                "Security source digest is invalid"
            )

    def as_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve.upper(),
            "branch": self.branch,
            "fix_commits": list(
                self.fix_commits
            ),
            "security_repository": (
                self.security_repository
            ),
            "security_revision": (
                self.security_revision
            ),
            "source_path": self.source_path,
            "source_digest": self.source_digest,
        }

    @classmethod
    def from_dict(
        cls,
        payload: dict[str, Any],
    ) -> CipFixRecord:
        raw_commits = payload.get(
            "fix_commits",
            [],
        )

        if not isinstance(raw_commits, list):
            raise ValueError(
                "fix_commits must be an array"
            )

        result = cls(
            cve=str(
                payload.get("cve") or ""
            ).upper(),
            branch=str(
                payload.get("branch") or ""
            ),
            fix_commits=tuple(
                str(commit).casefold()
                for commit in raw_commits
            ),
            security_repository=str(
                payload.get(
                    "security_repository"
                )
                or ""
            ),
            security_revision=str(
                payload.get(
                    "security_revision"
                )
                or ""
            ).casefold(),
            source_path=str(
                payload.get("source_path") or ""
            ),
            source_digest=str(
                payload.get("source_digest") or ""
            ),
        )
        result.validate()
        return result


@dataclass(frozen=True)
class CipAssessment:
    cve: str
    branch: str
    tag: str
    tag_commit: str
    status: str
    fix_commits: tuple[str, ...]
    included_commits: tuple[str, ...]
    missing_commits: tuple[str, ...]
    evidence: dict[str, Any]
    detail: str

    @property
    def remediable(self) -> bool:
        return self.status == "fixed-in-cip"

    def as_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "branch": self.branch,
            "tag": self.tag,
            "tag_commit": self.tag_commit,
            "status": self.status,
            "fix_commits": list(
                self.fix_commits
            ),
            "included_commits": list(
                self.included_commits
            ),
            "missing_commits": list(
                self.missing_commits
            ),
            "evidence": json_copy(
                self.evidence
            ),
            "detail": self.detail,
        }

    @classmethod
    def from_dict(
        cls,
        payload: dict[str, Any],
    ) -> CipAssessment:
        evidence = payload.get(
            "evidence",
            {},
        )

        if not isinstance(evidence, dict):
            raise ValueError(
                "Assessment evidence must be an object"
            )

        return cls(
            cve=str(payload.get("cve") or ""),
            branch=str(
                payload.get("branch") or ""
            ),
            tag=str(payload.get("tag") or ""),
            tag_commit=str(
                payload.get("tag_commit") or ""
            ),
            status=str(
                payload.get("status") or ""
            ),
            fix_commits=tuple(
                str(value)
                for value in (
                    payload.get("fix_commits")
                    or []
                )
            ),
            included_commits=tuple(
                str(value)
                for value in (
                    payload.get(
                        "included_commits"
                    )
                    or []
                )
            ),
            missing_commits=tuple(
                str(value)
                for value in (
                    payload.get(
                        "missing_commits"
                    )
                    or []
                )
            ),
            evidence=json_copy(evidence),
            detail=str(
                payload.get("detail") or ""
            ),
        )


def assess_fix(
    client: GitLabCommitClient,
    kernel_repository: GitLabRepositoryRef,
    *,
    tag: str,
    record: CipFixRecord,
) -> CipAssessment:
    record.validate()
    included: list[str] = []
    missing: list[str] = []

    try:
        for commit in record.fix_commits:
            if client.contains_commit(
                kernel_repository,
                commit,
            ):
                included.append(commit)
            else:
                missing.append(commit)
    except Exception as error:
        return CipAssessment(
            cve=record.cve,
            branch=record.branch,
            tag=tag,
            tag_commit=(
                kernel_repository.commit
            ),
            status="error",
            fix_commits=record.fix_commits,
            included_commits=tuple(included),
            missing_commits=tuple(missing),
            evidence=record.as_dict(),
            detail=str(error),
        )

    if missing:
        status = "fix-not-contained"
        detail = (
            "One or more required fix commits are "
            "not contained in the release tag"
        )
    else:
        status = "fixed-in-cip"
        detail = (
            "All required fix commits are contained "
            "in the release tag"
        )

    return CipAssessment(
        cve=record.cve,
        branch=record.branch,
        tag=tag,
        tag_commit=kernel_repository.commit,
        status=status,
        fix_commits=record.fix_commits,
        included_commits=tuple(included),
        missing_commits=tuple(missing),
        evidence=record.as_dict(),
        detail=detail,
    )


def build_remediation_action(
    assessment: CipAssessment,
    *,
    blackduck_target: ActionTarget,
    observed_state: dict[str, Any],
    desired_status: str,
    assessed_at: str,
    preserve_existing_decisions: bool = True,
) -> BlackDuckAction | None:
    if not assessment.remediable:
        return None

    evidence_details = assessment.as_dict()

    return BlackDuckAction.build(
        kind="vulnerability-remediation.set",
        target=blackduck_target,
        observed=observed_state,
        desired={
            "remediation_status": desired_status,
            "preserve_existing_decisions": (
                preserve_existing_decisions
            ),
            "comment": (
                f"CIP tag {assessment.tag} "
                f"({assessment.tag_commit}) contains "
                "the required fix commit(s): "
                + ", ".join(
                    assessment.fix_commits
                )
                + f". Evaluated at {assessed_at}."
            ),
        },
        ownership=ActionOwnership(
            producer="cip-remediation",
            marker="wintermute:cip:v1",
        ),
        evidence=ActionEvidence(
            provider="cip-kernel-sec",
            subject=assessment.cve,
            revision=str(
                assessment.evidence[
                    "security_revision"
                ]
            ),
            digest=stable_digest(
                evidence_details
            ),
            details=evidence_details,
        ),
        reason=assessment.detail,
    )
