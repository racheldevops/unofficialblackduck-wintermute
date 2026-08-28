from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from wintermute.blackduck.jobs.cip.evaluator import (
    CipFixRecord,
)
from wintermute.scm.providers.gitlab.client import (
    GitLabRepositoryRef,
    GitLabRestClient,
)


_COMMIT_RE = re.compile(
    r"\b[a-fA-F0-9]{40,64}\b"
)
_SERIES_RE = re.compile(
    r"(?<![0-9])([0-9]+\.[0-9]+)(?![0-9])"
)


@dataclass(frozen=True)
class CipSecurityLookup:
    cve: str
    requested_branch: str
    status: str
    record: CipFixRecord | None
    source_path: str
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "requested_branch": (
                self.requested_branch
            ),
            "status": self.status,
            "record": (
                self.record.as_dict()
                if self.record is not None
                else None
            ),
            "source_path": self.source_path,
            "detail": self.detail,
        }


def indentation(value: str) -> int:
    return len(value) - len(
        value.lstrip(" ")
    )


def unquote(value: str) -> str:
    selected = value.strip()

    if (
        len(selected) >= 2
        and selected[0] == selected[-1]
        and selected[0] in {"'", '"'}
    ):
        return selected[1:-1]

    return selected


def commits_in(value: str) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            commit.casefold()
            for commit in _COMMIT_RE.findall(
                value
            )
        )
    )


def parse_fixed_by(
    value: str,
) -> dict[str, tuple[str, ...]]:
    result: dict[str, list[str]] = {}
    root_indent: int | None = None
    current_key = ""

    for raw_line in value.splitlines():
        stripped = raw_line.strip()

        if (
            not stripped
            or stripped.startswith("#")
        ):
            continue

        current_indent = indentation(raw_line)

        if root_indent is None:
            if stripped == "fixed-by:":
                root_indent = current_indent

            continue

        if (
            current_indent <= root_indent
            and not stripped.startswith("-")
        ):
            break

        if (
            not stripped.startswith("-")
            and ":" in stripped
        ):
            key, remainder = stripped.split(
                ":",
                1,
            )
            current_key = unquote(key)

            if current_key:
                result.setdefault(
                    current_key,
                    [],
                )
                result[current_key].extend(
                    commits_in(remainder)
                )

            continue

        if current_key:
            result[current_key].extend(
                commits_in(stripped)
            )

    return {
        key: tuple(
            dict.fromkeys(commits)
        )
        for key, commits in result.items()
    }


def branch_candidates(
    branch: str,
) -> tuple[str, ...]:
    selected = str(branch or "").strip()
    match = _SERIES_RE.search(selected)
    values = [selected]

    if match:
        series = match.group(1)
        values.extend(
            [
                f"cip/{series}",
                f"stable/{series}",
                f"linux-{series}.y-cip",
                series,
            ]
        )

    values.append("mainline")

    return tuple(
        dict.fromkeys(
            value.casefold()
            for value in values
            if value
        )
    )


def issue_paths(cve: str) -> tuple[str, ...]:
    normalized = str(cve).upper()
    year = normalized.split("-", 2)[1]

    return (
        f"issues/{normalized}.yml",
        f"issues/{normalized}.yaml",
        f"issues/{year}/{normalized}.yml",
        f"issues/{year}/{normalized}.yaml",
    )


class CipSecurityData:
    def __init__(
        self,
        client: GitLabRestClient,
        repository: GitLabRepositoryRef,
    ) -> None:
        self.client = client
        self.repository = repository

    def lookup(
        self,
        cve: str,
        branch: str,
    ) -> CipSecurityLookup:
        normalized_cve = str(cve).upper()
        raw: bytes | None = None
        source_path = ""

        for path in issue_paths(
            normalized_cve
        ):
            raw = (
                self.client
                .try_read_repository_file(
                    self.repository,
                    path,
                )
            )

            if raw is not None:
                source_path = path
                break

        if raw is None:
            return CipSecurityLookup(
                cve=normalized_cve,
                requested_branch=branch,
                status="not-tracked",
                record=None,
                source_path="",
                detail=(
                    "CVE is not present in the "
                    "security repository"
                ),
            )

        text = raw.decode(
            "utf-8",
            errors="replace",
        )
        fixed_by = parse_fixed_by(text)
        by_name = {
            key.casefold(): (
                key,
                commits,
            )
            for key, commits
            in fixed_by.items()
        }
        selected_name = ""
        selected_commits: tuple[str, ...] = ()

        for candidate in branch_candidates(
            branch
        ):
            selected = by_name.get(candidate)

            if selected is None:
                continue

            selected_name = selected[0]
            selected_commits = selected[1]

            if selected_commits:
                break

        if not selected_name:
            return CipSecurityLookup(
                cve=normalized_cve,
                requested_branch=branch,
                status="no-branch-record",
                record=None,
                source_path=source_path,
                detail=(
                    "No applicable fixed-by branch "
                    "was found"
                ),
            )

        if not selected_commits:
            return CipSecurityLookup(
                cve=normalized_cve,
                requested_branch=branch,
                status="no-fix-commit",
                record=None,
                source_path=source_path,
                detail=(
                    f"Branch {selected_name} has no "
                    "fix commit"
                ),
            )

        source_digest = (
            "sha256:"
            + sha256(raw).hexdigest()
        )
        record = CipFixRecord(
            cve=normalized_cve,
            branch=selected_name,
            fix_commits=selected_commits,
            security_repository=(
                self.repository.repository_url
            ),
            security_revision=(
                self.repository.commit
            ),
            source_path=source_path,
            source_digest=source_digest,
        )
        record.validate()

        return CipSecurityLookup(
            cve=normalized_cve,
            requested_branch=branch,
            status="found",
            record=record,
            source_path=source_path,
            detail=(
                f"Using fixed-by branch "
                f"{selected_name}"
            ),
        )
