from __future__ import annotations

import os
import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlsplit

from wintermute.file_lock import FileLock


_COMMIT_RE = re.compile(
    r"^[a-f0-9]{40}|[a-f0-9]{64}$"
)


class GitRepositoryError(RuntimeError):
    pass


@dataclass(frozen=True)
class RepositorySnapshot:
    location: str
    repository_path: Path
    requested_revision: str
    commit: str


def validate_repository_location(
    value: str,
) -> str:
    location = str(value or "").strip()
    parsed = urlsplit(location)

    if (
        parsed.scheme.casefold() != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "Repository location must be an HTTPS URL "
            "without credentials, query, or fragment"
        )

    return location


def validate_revision(value: str) -> str:
    revision = str(value or "").strip()

    if (
        not revision
        or revision.startswith("-")
        or ".." in revision
        or "@{" in revision
        or ":" in revision
        or "\\" in revision
        or len(revision) > 200
    ):
        raise ValueError(
            f"Invalid Git revision: {value!r}"
        )

    allowed = set(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789._/-"
    )

    if any(
        character not in allowed
        for character in revision
    ):
        raise ValueError(
            f"Invalid Git revision: {value!r}"
        )

    return revision


class GitMirrorStore:
    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        git_command: str = "git",
        timeout_seconds: int = 300,
        stale_lock_seconds: int = 1800,
    ) -> None:
        if timeout_seconds < 1:
            raise ValueError(
                "timeout_seconds must be positive"
            )

        self.root = Path(root).expanduser()
        self.git_command = git_command
        self.timeout_seconds = timeout_seconds
        self.stale_lock_seconds = (
            stale_lock_seconds
        )

    def snapshot(
        self,
        location: str,
        revision: str,
        *,
        refresh: bool = True,
    ) -> RepositorySnapshot:
        location = validate_repository_location(
            location
        )
        revision = validate_revision(revision)
        repository = self._repository_path(
            location
        )
        lock_path = repository.with_suffix(
            ".lock"
        )

        with FileLock(
            lock_path,
            stale_seconds=(
                self.stale_lock_seconds
            ),
            wait_seconds=60,
        ):
            if not repository.is_dir():
                self._clone(
                    location,
                    repository,
                )
            else:
                current = self._run(
                    repository,
                    "remote",
                    "get-url",
                    "origin",
                ).strip()

                if current != location:
                    raise GitRepositoryError(
                        "Cached repository origin "
                        "does not match"
                    )

            if refresh:
                self._run(
                    repository,
                    "remote",
                    "update",
                    "--prune",
                )

            commit = self.resolve(
                repository,
                revision,
            )

        return RepositorySnapshot(
            location=location,
            repository_path=repository,
            requested_revision=revision,
            commit=commit,
        )

    def resolve(
        self,
        repository: Path,
        revision: str,
    ) -> str:
        revision = validate_revision(revision)
        commit = self._run(
            repository,
            "rev-parse",
            "--verify",
            f"{revision}^{{commit}}",
        ).strip().casefold()

        if not _COMMIT_RE.fullmatch(commit):
            raise GitRepositoryError(
                "Git returned an invalid commit ID"
            )

        return commit

    def contains(
        self,
        snapshot: RepositorySnapshot,
        ancestor: str,
    ) -> bool:
        ancestor = str(
            ancestor or ""
        ).strip().casefold()

        if not _COMMIT_RE.fullmatch(ancestor):
            raise ValueError(
                f"Invalid commit ID: {ancestor!r}"
            )

        completed = self._execute(
            snapshot.repository_path,
            "merge-base",
            "--is-ancestor",
            ancestor,
            snapshot.commit,
            accepted_statuses={0, 1},
        )

        return completed.returncode == 0

    def read_file(
        self,
        snapshot: RepositorySnapshot,
        path: str,
    ) -> bytes:
        relative = Path(path)

        if (
            relative.is_absolute()
            or ".." in relative.parts
            or not relative.parts
        ):
            raise ValueError(
                f"Invalid repository path: {path!r}"
            )

        completed = self._execute(
            snapshot.repository_path,
            "show",
            (
                f"{snapshot.commit}:"
                f"{relative.as_posix()}"
            ),
            text=False,
        )

        return bytes(completed.stdout)

    def list_files(
        self,
        snapshot: RepositorySnapshot,
        path: str = "",
    ) -> tuple[str, ...]:
        arguments = [
            "ls-tree",
            "-r",
            "--name-only",
            snapshot.commit,
        ]

        if path:
            relative = Path(path)

            if (
                relative.is_absolute()
                or ".." in relative.parts
            ):
                raise ValueError(
                    f"Invalid repository path: {path!r}"
                )

            arguments.extend(
                ["--", relative.as_posix()]
            )

        output = self._run(
            snapshot.repository_path,
            *arguments,
        )

        return tuple(
            line.strip()
            for line in output.splitlines()
            if line.strip()
        )

    def _repository_path(
        self,
        location: str,
    ) -> Path:
        identifier = sha256(
            location.encode("utf-8")
        ).hexdigest()[:24]

        return (
            self.root
            / "repositories"
            / f"{identifier}.git"
        )

    def _clone(
        self,
        location: str,
        destination: Path,
    ) -> None:
        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        temporary = destination.with_name(
            f"{destination.name}."
            f"{uuid.uuid4().hex}.tmp"
        )

        try:
            completed = subprocess.run(
                [
                    self.git_command,
                    "clone",
                    "--mirror",
                    location,
                    str(temporary),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                env=self._environment(),
            )

            if completed.returncode != 0:
                raise GitRepositoryError(
                    completed.stderr.strip()
                    or "Git clone failed"
                )

            os.replace(
                temporary,
                destination,
            )
        except FileNotFoundError as error:
            raise GitRepositoryError(
                f"Git executable was not found: "
                f"{self.git_command}"
            ) from error
        except subprocess.TimeoutExpired as error:
            raise GitRepositoryError(
                "Git clone timed out"
            ) from error
        finally:
            shutil.rmtree(
                temporary,
                ignore_errors=True,
            )

    def _run(
        self,
        repository: Path,
        *arguments: str,
    ) -> str:
        completed = self._execute(
            repository,
            *arguments,
        )
        return str(completed.stdout)

    def _execute(
        self,
        repository: Path,
        *arguments: str,
        text: bool = True,
        accepted_statuses: set[int] | None = None,
    ) -> subprocess.CompletedProcess:
        try:
            completed = subprocess.run(
                [
                    self.git_command,
                    "--git-dir",
                    str(repository),
                    *arguments,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=text,
                timeout=self.timeout_seconds,
                check=False,
                env=self._environment(),
            )
        except FileNotFoundError as error:
            raise GitRepositoryError(
                f"Git executable was not found: "
                f"{self.git_command}"
            ) from error
        except subprocess.TimeoutExpired as error:
            raise GitRepositoryError(
                "Git command timed out"
            ) from error

        allowed = accepted_statuses or {0}

        if completed.returncode not in allowed:
            error_value = completed.stderr

            if isinstance(error_value, bytes):
                error_text = error_value.decode(
                    "utf-8",
                    errors="replace",
                )
            else:
                error_text = str(error_value)

            raise GitRepositoryError(
                error_text.strip()
                or "Git command failed"
            )

        return completed

    @staticmethod
    def _environment() -> dict[str, str]:
        environment = dict(os.environ)
        environment["GIT_TERMINAL_PROMPT"] = "0"
        return environment
