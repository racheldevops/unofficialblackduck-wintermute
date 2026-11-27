from __future__ import annotations

import base64
import re
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any, Protocol
from urllib.parse import quote

from wintermute.ai.models import (
    EvidenceDescriptor,
    stable_digest,
)
from wintermute.ai.retrieval import (
    EvidenceCatalog,
    IndexedEvidence,
    eligible_file,
    evidence_kind,
    path_priority,
    tokenize,
)
from wintermute.ai.safety import Sanitizer
from wintermute.scm.models import Repository
from wintermute.scm.providers.github.rest import (
    DEFAULT_REST_BASE_URL as DEFAULT_GITHUB_REST_URL,
    GitHubRestClient,
    GitHubRestError,
)
from wintermute.scm.providers.gitlab.client import (
    GitLabRepositoryRef,
    GitLabRestClient,
)


_SEGMENT = r"[^/?#]+"
_GITHUB_TREE_PATH = re.compile(
    rf"^/repos/{_SEGMENT}/{_SEGMENT}/"
    rf"git/trees/{_SEGMENT}$"
)
_GITHUB_CONTENT_PATH = re.compile(
    rf"^/repos/{_SEGMENT}/{_SEGMENT}/"
    r"contents/.+$"
)

PUBLIC_KEYWORDS = {
    "azure",
    "cargo",
    "ci",
    "composer",
    "container",
    "detect",
    "docker",
    "dotnet",
    "github",
    "gitlab",
    "go",
    "gradle",
    "java",
    "javascript",
    "maven",
    "monorepo",
    "npm",
    "package",
    "pipeline",
    "python",
    "ruby",
    "rust",
    "scan",
    "shell",
    "typescript",
    "workflow",
}


@dataclass(frozen=True)
class RemoteFile:
    path: str
    size: int | None = None


@dataclass(frozen=True)
class RemoteCatalogResult:
    catalog: EvidenceCatalog
    listed_file_count: int
    selected_file_count: int
    retrieved_byte_count: int
    failures: tuple[str, ...]


class RemoteEvidenceSource(Protocol):
    provider: str
    repository: Repository

    @property
    def request_count(self) -> int:
        ...

    def list_files(self) -> tuple[
        RemoteFile,
        ...
    ]:
        ...

    def read_file(
        self,
        path: str,
    ) -> bytes:
        ...


def validate_remote_path(
    value: str,
) -> str:
    selected = str(value or "").strip()
    path = PurePosixPath(selected)

    if (
        not selected
        or selected.startswith("/")
        or ".." in path.parts
        or "\\" in selected
    ):
        raise ValueError(
            f"Invalid repository path: {value!r}"
        )

    return path.as_posix()


class GitHubEvidenceClient(
    GitHubRestClient
):
    def _validate_path(
        self,
        path: str,
    ) -> None:
        if (
            _GITHUB_TREE_PATH.fullmatch(path)
            or _GITHUB_CONTENT_PATH.fullmatch(
                path
            )
        ):
            return

        super()._validate_path(path)


class GitHubEvidenceSource:
    provider = "github"

    def __init__(
        self,
        repository: Repository,
        token: str,
        *,
        base_url: str = (
            DEFAULT_GITHUB_REST_URL
        ),
        timeout: float = 30,
        retries: int = 2,
        retry_delay: float = 1,
        insecure: bool = False,
        ca_bundle: str | None = None,
        deadline: float | None = None,
    ) -> None:
        if repository.provider != self.provider:
            raise ValueError(
                "Repository is not a GitHub repository"
            )

        if "/" in repository.namespace:
            raise ValueError(
                "GitHub namespace must be one segment"
            )

        self.repository = repository
        self.client = GitHubEvidenceClient(
            token,
            base_url=base_url,
            timeout=timeout,
            retries=retries,
            retry_delay=retry_delay,
            insecure=insecure,
            ca_bundle=ca_bundle,
            deadline=deadline,
        )

    @property
    def request_count(self) -> int:
        return self.client.stats().requests

    def list_files(self) -> tuple[
        RemoteFile,
        ...
    ]:
        reference = (
            self.repository.head_sha
            or self.repository.default_branch
        )

        if not reference:
            raise RuntimeError(
                "GitHub repository has no readable "
                "default-branch reference"
            )

        path = self.client.repository_path(
            self.repository.namespace,
            self.repository.name,
            (
                "git/trees/"
                f"{quote(reference, safe='')}"
            ),
        )
        payload = self.client.get_json(
            path,
            params={
                "recursive": "1",
            },
        )

        if not isinstance(payload, dict):
            raise GitHubRestError(
                "invalid_response",
                "GitHub tree response must be "
                "an object",
                attempts=1,
            )

        if payload.get("truncated") is True:
            raise GitHubRestError(
                "truncated_tree",
                "GitHub repository tree is truncated",
                attempts=1,
            )

        tree = payload.get("tree")

        if (
            not isinstance(tree, list)
            or not all(
                isinstance(value, dict)
                for value in tree
            )
        ):
            raise GitHubRestError(
                "invalid_response",
                "GitHub tree response is malformed",
                attempts=1,
            )

        files: list[RemoteFile] = []

        for value in tree:
            if value.get("type") != "blob":
                continue

            file_path = validate_remote_path(
                str(value.get("path") or "")
            )
            raw_size = value.get("size")
            size = (
                raw_size
                if type(raw_size) is int
                and raw_size >= 0
                else None
            )
            files.append(
                RemoteFile(
                    path=file_path,
                    size=size,
                )
            )

        return tuple(
            sorted(
                files,
                key=lambda value: (
                    value.path.casefold(),
                    value.path,
                ),
            )
        )

    def read_file(
        self,
        path: str,
    ) -> bytes:
        selected = validate_remote_path(path)
        encoded_path = "/".join(
            quote(part, safe="")
            for part in selected.split("/")
        )
        resource = self.client.repository_path(
            self.repository.namespace,
            self.repository.name,
            f"contents/{encoded_path}",
        )
        payload = self.client.get_json(
            resource,
            params={
                "ref": (
                    self.repository.head_sha
                    or self.repository.default_branch
                ),
            },
        )

        if not isinstance(payload, dict):
            raise GitHubRestError(
                "invalid_response",
                "GitHub content response must be "
                "an object",
                attempts=1,
            )

        if payload.get("type") != "file":
            raise GitHubRestError(
                "invalid_response",
                "GitHub content is not a file",
                attempts=1,
            )

        if payload.get("encoding") != "base64":
            raise GitHubRestError(
                "unsupported_content",
                "GitHub content is not base64",
                attempts=1,
            )

        content = payload.get("content")

        if not isinstance(content, str):
            raise GitHubRestError(
                "invalid_response",
                "GitHub file content is unavailable",
                attempts=1,
            )

        try:
            return base64.b64decode(
                content.replace("\n", ""),
                validate=True,
            )
        except ValueError as error:
            raise GitHubRestError(
                "invalid_response",
                "GitHub returned invalid base64",
                attempts=1,
            ) from error


class GitLabEvidenceSource:
    provider = "gitlab"

    def __init__(
        self,
        repository: Repository,
        token: str,
        *,
        base_url: str,
        timeout: float = 30,
        retries: int = 2,
        retry_delay: float = 1,
        insecure: bool = False,
        ca_bundle: str | None = None,
        deadline: float | None = None,
    ) -> None:
        if repository.provider != self.provider:
            raise ValueError(
                "Repository is not a GitLab repository"
            )

        self.repository = repository
        self.client = GitLabRestClient(
            token,
            base_url=base_url,
            timeout=timeout,
            retries=retries,
            retry_delay=retry_delay,
            insecure=insecure,
            ca_bundle=ca_bundle,
            deadline=deadline,
        )

        if repository.head_sha:
            self.reference = GitLabRepositoryRef(
                repository_url=(
                    repository.canonical_url
                ),
                project_path=(
                    repository.name_with_owner
                ),
                revision=(
                    repository.default_branch
                    or repository.head_sha
                ),
                commit=repository.head_sha,
            )
        elif repository.default_branch:
            self.reference = (
                self.client
                .resolve_repository_ref(
                    repository.canonical_url,
                    repository.default_branch,
                )
            )
        else:
            raise RuntimeError(
                "GitLab repository has no readable "
                "default-branch reference"
            )

    @property
    def request_count(self) -> int:
        return self.client.stats().requests

    def list_files(self) -> tuple[
        RemoteFile,
        ...
    ]:
        tree = self.client.repository_tree(
            self.reference,
            recursive=True,
        )
        files: list[RemoteFile] = []

        for value in tree:
            if value.get("type") != "blob":
                continue

            files.append(
                RemoteFile(
                    path=validate_remote_path(
                        str(
                            value.get("path")
                            or ""
                        )
                    ),
                )
            )

        return tuple(
            sorted(
                files,
                key=lambda value: (
                    value.path.casefold(),
                    value.path,
                ),
            )
        )

    def read_file(
        self,
        path: str,
    ) -> bytes:
        return self.client.read_repository_file(
            self.reference,
            validate_remote_path(path),
        )


def public_keywords(
    path: str,
    kind: str,
) -> tuple[str, ...]:
    terms = {
        term
        for term in tokenize(
            f"{path} {kind}"
        )
        if term in PUBLIC_KEYWORDS
    }

    terms.add(kind)

    return tuple(sorted(terms))


class LazyRemoteEvidenceCatalog:
    def __init__(
        self,
        source: RemoteEvidenceSource,
        sanitizer: Sanitizer,
        files: tuple[RemoteFile, ...],
        *,
        max_file_bytes: int,
        max_total_bytes: int,
    ) -> None:
        self.source = source
        self.sanitizer = sanitizer
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.listed_file_count = len(files)
        self.retrieved_byte_count = 0
        self.failures: list[str] = []
        self._files: dict[
            str,
            RemoteFile,
        ] = {}
        self._descriptors: dict[
            str,
            EvidenceDescriptor,
        ] = {}
        self._search_terms: dict[
            str,
            tuple[str, ...],
        ] = {}
        self._loaded: dict[
            str,
            IndexedEvidence,
        ] = {}
        repository_key = (
            source.repository.external_id
        )

        for remote_file in files:
            metadata_digest = stable_digest(
                {
                    "repository": repository_key,
                    "path": remote_file.path,
                    "size": remote_file.size,
                }
            )
            evidence_id = (
                "ev-"
                + metadata_digest.split(
                    ":",
                    1,
                )[1][:16]
            )
            kind = evidence_kind(
                Path(remote_file.path)
            )
            descriptor = EvidenceDescriptor(
                evidence_id=evidence_id,
                relative_path=remote_file.path,
                safe_path=(
                    sanitizer.anonymizer
                    .safe_path(
                        remote_file.path
                    )
                ),
                kind=kind,
                digest=metadata_digest,
                byte_count=(
                    remote_file.size or 0
                ),
                truncated=False,
                relevance=float(
                    path_priority(
                        Path(remote_file.path)
                    )
                ),
                keywords=public_keywords(
                    remote_file.path,
                    kind,
                ),
            )
            self._files[evidence_id] = (
                remote_file
            )
            self._descriptors[
                evidence_id
            ] = descriptor
            self._search_terms[
                evidence_id
            ] = tokenize(
                f"{remote_file.path} {kind}"
            )

        self.by_id = dict(self._files)

    @property
    def records(
        self,
    ) -> tuple[IndexedEvidence, ...]:
        return tuple(
            self._loaded[evidence_id]
            for evidence_id
            in self._ordered_ids()
            if evidence_id in self._loaded
        )

    @property
    def selected_file_count(self) -> int:
        return len(self._loaded)

    def descriptor_payload(
        self,
    ) -> list[dict[str, Any]]:
        return [
            self._descriptors[
                evidence_id
            ].as_dict()
            for evidence_id
            in self._ordered_ids()
        ]

    def private_descriptor_payload(
        self,
    ) -> list[dict[str, Any]]:
        payload: list[dict[str, Any]] = []

        for evidence_id in self._ordered_ids():
            value = self._descriptors[
                evidence_id
            ].as_dict(
                include_private_path=True,
            )
            value["retrieved"] = (
                evidence_id in self._loaded
            )
            payload.append(value)

        return payload

    def search(
        self,
        query: str,
        *,
        limit: int,
    ) -> tuple[str, ...]:
        query_terms = tokenize(query)
        document_count = len(
            self._search_terms
        )
        average_length = (
            sum(
                len(value)
                for value
                in self._search_terms.values()
            )
            / max(1, document_count)
        )
        wanted = set(query_terms)
        document_frequency = {
            term: sum(
                term in set(terms)
                for terms
                in self._search_terms.values()
            )
            for term in wanted
        }
        scored: list[
            tuple[float, str],
        ] = []

        for evidence_id, terms in (
            self._search_terms.items()
        ):
            descriptor = (
                self._descriptors[
                    evidence_id
                ]
            )
            frequencies = Counter(terms)
            score = (
                descriptor.relevance / 100
            )
            length = max(1, len(terms))

            for term in query_terms:
                frequency = frequencies.get(
                    term,
                    0,
                )

                if frequency == 0:
                    continue

                frequency_count = (
                    document_frequency.get(
                        term,
                        0,
                    )
                )
                inverse = __import__(
                    "math"
                ).log(
                    1
                    + (
                        document_count
                        - frequency_count
                        + 0.5
                    )
                    / (
                        frequency_count
                        + 0.5
                    )
                )
                denominator = (
                    frequency
                    + 1.5
                    * (
                        0.25
                        + 0.75
                        * length
                        / max(
                            1,
                            average_length,
                        )
                    )
                )
                score += (
                    inverse
                    * frequency
                    * 2.5
                    / denominator
                )

            scored.append(
                (
                    score,
                    evidence_id,
                )
            )

        scored.sort(
            key=lambda item: (
                -item[0],
                item[1],
            )
        )

        return tuple(
            evidence_id
            for _, evidence_id
            in scored[:limit]
        )

    def evidence_payload(
        self,
        evidence_ids: tuple[str, ...],
        *,
        max_bytes: int,
    ) -> tuple[
        list[dict[str, Any]],
        int,
    ]:
        selected: list[
            dict[str, Any]
        ] = []
        consumed = 0

        for evidence_id in evidence_ids:
            record = self._load(
                evidence_id
            )
            content = record.sanitized_text
            encoded = content.encode("utf-8")

            if consumed + len(encoded) > max_bytes:
                remaining = max_bytes - consumed

                if remaining < 256:
                    raise RuntimeError(
                        "AI prompt evidence byte "
                        "budget was exceeded"
                    )

                content = encoded[
                    :remaining
                ].decode(
                    "utf-8",
                    errors="ignore",
                )

            consumed += len(
                content.encode("utf-8")
            )
            selected.append(
                {
                    "evidence_id": evidence_id,
                    "safe_path": (
                        record.descriptor.safe_path
                    ),
                    "kind": (
                        record.descriptor.kind
                    ),
                    "digest": (
                        record.descriptor.digest
                    ),
                    "content": content,
                }
            )

        return selected, consumed

    def materialize_all(self) -> None:
        for evidence_id in self._ordered_ids():
            self._load(evidence_id)

    def _load(
        self,
        evidence_id: str,
    ) -> IndexedEvidence:
        existing = self._loaded.get(
            evidence_id
        )

        if existing is not None:
            return existing

        remote_file = self._files.get(
            evidence_id
        )

        if remote_file is None:
            raise ValueError(
                f"Unknown evidence ID: "
                f"{evidence_id}"
            )

        remaining = (
            self.max_total_bytes
            - self.retrieved_byte_count
        )

        if remaining < 256:
            raise RuntimeError(
                "Remote evidence retrieval byte "
                "budget was exhausted"
            )

        try:
            raw = self.source.read_file(
                remote_file.path
            )
        except Exception as error:
            message = (
                f"{remote_file.path}: {error}"
            )
            self.failures.append(message)
            raise RuntimeError(
                f"Could not retrieve evidence "
                f"{evidence_id}: {error}"
            ) from error

        if b"\0" in raw[:4096]:
            raise RuntimeError(
                f"Evidence {evidence_id} is binary"
            )

        selected_limit = min(
            self.max_file_bytes,
            remaining,
        )
        truncated = (
            len(raw) > selected_limit
        )
        selected = raw[:selected_limit]
        self.retrieved_byte_count += len(
            selected
        )
        text = selected.decode(
            "utf-8",
            errors="replace",
        )
        sanitized = (
            self.sanitizer.sanitize_text(
                text
            )
        )
        digest = stable_digest(
            {
                "path": remote_file.path,
                "content": sanitized,
            }
        )
        descriptor = replace(
            self._descriptors[
                evidence_id
            ],
            digest=digest,
            byte_count=len(raw),
            truncated=truncated,
        )
        record = IndexedEvidence(
            descriptor=descriptor,
            sanitized_text=sanitized,
            terms=tokenize(
                f"{remote_file.path} "
                f"{descriptor.kind} "
                f"{sanitized[:8192]}"
            ),
        )
        self._descriptors[
            evidence_id
        ] = descriptor
        self._loaded[evidence_id] = record
        return record

    def _ordered_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                self._descriptors,
                key=lambda evidence_id: (
                    -self._descriptors[
                        evidence_id
                    ].relevance,
                    self._descriptors[
                        evidence_id
                    ].safe_path.casefold(),
                    evidence_id,
                ),
            )
        )


def eligible_remote_files(
    files: tuple[RemoteFile, ...],
    *,
    max_catalog_files: int,
    max_file_bytes: int,
) -> tuple[RemoteFile, ...]:
    selected = [
        value
        for value in files
        if (
            eligible_file(Path(value.path))
            and (
                value.size is None
                or value.size
                <= max_file_bytes
            )
        )
    ]
    selected.sort(
        key=lambda value: (
            -path_priority(
                Path(value.path)
            ),
            value.path.casefold(),
            value.path,
        )
    )

    return tuple(
        selected[:max_catalog_files]
    )


def build_lazy_remote_catalog(
    source: RemoteEvidenceSource,
    sanitizer: Sanitizer,
    *,
    max_catalog_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> LazyRemoteEvidenceCatalog:
    if max_catalog_files < 1:
        raise ValueError(
            "max_catalog_files must be positive"
        )

    if max_file_bytes < 1:
        raise ValueError(
            "max_file_bytes must be positive"
        )

    if max_total_bytes < 1:
        raise ValueError(
            "max_total_bytes must be positive"
        )

    listed = source.list_files()
    selected = eligible_remote_files(
        listed,
        max_catalog_files=(
            max_catalog_files
        ),
        max_file_bytes=max_file_bytes,
    )

    if not selected:
        raise RuntimeError(
            "No eligible remote evidence "
            "files were found"
        )

    return LazyRemoteEvidenceCatalog(
        source,
        sanitizer,
        selected,
        max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes,
    )


def build_remote_catalog(
    source: RemoteEvidenceSource,
    sanitizer: Sanitizer,
    *,
    max_catalog_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> RemoteCatalogResult:
    listed = source.list_files()
    selected = eligible_remote_files(
        listed,
        max_catalog_files=(
            max_catalog_files
        ),
        max_file_bytes=max_file_bytes,
    )

    if not selected:
        raise RuntimeError(
            "No eligible remote evidence "
            "files were found"
        )

    lazy = LazyRemoteEvidenceCatalog(
        source,
        sanitizer,
        selected,
        max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes,
    )
    lazy.materialize_all()

    return RemoteCatalogResult(
        catalog=EvidenceCatalog(
            lazy.records
        ),
        listed_file_count=len(listed),
        selected_file_count=(
            lazy.selected_file_count
        ),
        retrieved_byte_count=(
            lazy.retrieved_byte_count
        ),
        failures=tuple(lazy.failures),
    )
