from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wintermute.ai.models import (
    EvidenceDescriptor,
    stable_digest,
)
from wintermute.ai.safety import (
    Sanitizer,
)


IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".tox",
    ".pytest_cache",
    "coverage",
}

REJECTED_NAMES = {
    ".env",
    ".npmrc",
    ".pypirc",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "credentials.json",
    "secrets.yaml",
    "secrets.yml",
}

HIGH_VALUE_NAMES = {
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "requirements.txt",
    "requirements-dev.txt",
    "poetry.lock",
    "pdm.lock",
    "uv.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "gradle.properties",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "go.mod",
    "go.sum",
    "cargo.toml",
    "cargo.lock",
    "composer.json",
    "gemfile",
    "gemfile.lock",
    "dockerfile",
    "makefile",
    ".gitlab-ci.yml",
    "azure-pipelines.yml",
}

CONFIGURATION_SUFFIXES = {
    ".toml",
    ".json",
    ".xml",
    ".gradle",
    ".kts",
    ".properties",
    ".yaml",
    ".yml",
    ".lock",
    ".txt",
    ".md",
    ".csproj",
    ".fsproj",
    ".vbproj",
    ".sln",
}

SOURCE_SUFFIXES = {
    ".bash",
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".cxx",
    ".go",
    ".groovy",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".php",
    ".py",
    ".pyi",
    ".rb",
    ".rs",
    ".scala",
    ".sh",
    ".swift",
    ".ts",
    ".tsx",
    ".zsh",
}

TOKEN_RE = re.compile(
    r"[A-Za-z][A-Za-z0-9_.+-]{1,}"
)


@dataclass(frozen=True)
class IndexedEvidence:
    descriptor: EvidenceDescriptor
    sanitized_text: str
    terms: tuple[str, ...]


class EvidenceCatalog:
    def __init__(
        self,
        records: tuple[
            IndexedEvidence,
            ...
        ],
    ) -> None:
        self.records = records
        self.by_id = {
            value.descriptor.evidence_id: value
            for value in records
        }

    @classmethod
    def build(
        cls,
        root: Path,
        sanitizer: Sanitizer,
        *,
        max_catalog_files: int,
        max_file_bytes: int,
    ) -> EvidenceCatalog:
        root = root.expanduser().resolve()

        if not root.is_dir():
            raise ValueError(
                f"Source root does not exist: {root}"
            )

        candidates = [
            path
            for path in root.rglob("*")
            if (
                path.is_file()
                and not any(
                    part in IGNORED_DIRECTORIES
                    for part in path.parts
                )
                and path.name.casefold()
                not in REJECTED_NAMES
                and eligible_file(path)
            )
        ]
        candidates.sort(
            key=lambda path: (
                -path_priority(
                    path.relative_to(root)
                ),
                path.relative_to(root)
                .as_posix()
                .casefold(),
            )
        )
        records: list[IndexedEvidence] = []

        for path in candidates[
            :max_catalog_files
        ]:
            relative = (
                path.relative_to(root)
                .as_posix()
            )

            try:
                raw = path.read_bytes()
            except OSError:
                continue

            if b"\0" in raw[:4096]:
                continue

            truncated = (
                len(raw) > max_file_bytes
            )
            selected = raw[:max_file_bytes]
            text = selected.decode(
                "utf-8",
                errors="replace",
            )
            sanitized = (
                sanitizer.sanitize_text(text)
            )
            digest = stable_digest(
                {
                    "path": relative,
                    "content": sanitized,
                }
            )
            evidence_id = (
                "ev-"
                + digest.split(":", 1)[1][:16]
            )
            kind = evidence_kind(
                Path(relative)
            )
            terms = tokenize(
                f"{relative} {kind} "
                f"{sanitized[:8192]}"
            )
            keywords = tuple(
                term
                for term, _ in Counter(
                    terms
                ).most_common(12)
            )
            descriptor = EvidenceDescriptor(
                evidence_id=evidence_id,
                relative_path=relative,
                safe_path=(
                    sanitizer.anonymizer
                    .safe_path(relative)
                ),
                kind=kind,
                digest=digest,
                byte_count=len(raw),
                truncated=truncated,
                relevance=float(
                    path_priority(
                        Path(relative)
                    )
                ),
                keywords=keywords,
            )
            records.append(
                IndexedEvidence(
                    descriptor=descriptor,
                    sanitized_text=sanitized,
                    terms=terms,
                )
            )

        if not records:
            raise ValueError(
                "No eligible build evidence was found"
            )

        return cls(tuple(records))

    def descriptor_payload(
        self,
    ) -> list[dict[str, Any]]:
        return [
            value.descriptor.as_dict()
            for value in self.records
        ]

    def private_descriptor_payload(
        self,
    ) -> list[dict[str, Any]]:
        return [
            value.descriptor.as_dict(
                include_private_path=True,
            )
            for value in self.records
        ]

    def search(
        self,
        query: str,
        *,
        limit: int,
    ) -> tuple[str, ...]:
        query_terms = tokenize(query)

        if not query_terms:
            return tuple(
                value.descriptor.evidence_id
                for value in self.records[:limit]
            )

        document_count = len(self.records)
        average_length = (
            sum(
                len(value.terms)
                for value in self.records
            )
            / max(1, document_count)
        )
        document_frequency = {
            term: sum(
                term in set(value.terms)
                for value in self.records
            )
            for term in set(query_terms)
        }
        scored: list[
            tuple[float, str]
        ] = []

        for value in self.records:
            frequencies = Counter(
                value.terms
            )
            score = (
                value.descriptor.relevance
                / 100
            )
            length = max(
                1,
                len(value.terms),
            )

            for term in query_terms:
                frequency = frequencies.get(
                    term,
                    0,
                )

                if not frequency:
                    continue

                frequency_count = (
                    document_frequency.get(
                        term,
                        0,
                    )
                )
                inverse = math.log(
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
                    value.descriptor.evidence_id,
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
            record = self.by_id.get(
                evidence_id
            )

            if record is None:
                raise ValueError(
                    f"Unknown evidence ID: "
                    f"{evidence_id}"
                )

            content = (
                record.sanitized_text
            )
            encoded = content.encode(
                "utf-8"
            )

            if consumed + len(encoded) > max_bytes:
                remaining = max(
                    0,
                    max_bytes - consumed,
                )

                if remaining < 256:
                    break

                encoded = encoded[:remaining]
                content = encoded.decode(
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

            if consumed >= max_bytes:
                break

        return selected, consumed


def tokenize(value: str) -> tuple[str, ...]:
    return tuple(
        match.group(0).casefold()
        for match in TOKEN_RE.finditer(
            str(value)
        )
    )


def eligible_file(path: Path) -> bool:
    name = path.name.casefold()
    suffix = path.suffix.casefold()

    if name in HIGH_VALUE_NAMES:
        return True

    if name.startswith(
        (
            "dockerfile.",
            "requirements-",
        )
    ):
        return True

    if (
        ".github" in path.parts
        or ".gitlab" in path.parts
    ):
        return suffix in {
            ".yml",
            ".yaml",
        }

    return (
        suffix in CONFIGURATION_SUFFIXES
        or suffix in SOURCE_SUFFIXES
    )


def evidence_kind(path: Path) -> str:
    name = path.name.casefold()
    suffix = path.suffix.casefold()

    if (
        name == ".gitlab-ci.yml"
        or ".github" in path.parts
        or ".gitlab" in path.parts
        or name == "azure-pipelines.yml"
    ):
        return "ci"

    if name.startswith("dockerfile"):
        return "container"

    if name.startswith(
        (
            "license",
            "copying",
            "notice",
        )
    ):
        return "license"

    if name in {
        "readme.md",
        "readme.txt",
    }:
        return "documentation"

    if suffix in SOURCE_SUFFIXES:
        return "source"

    if (
        name in HIGH_VALUE_NAMES
        or suffix
        in {
            ".toml",
            ".xml",
            ".gradle",
            ".kts",
            ".csproj",
            ".fsproj",
            ".vbproj",
            ".sln",
        }
    ):
        return "build"

    return "configuration"


def path_priority(path: Path) -> int:
    name = path.name.casefold()
    suffix = path.suffix.casefold()
    score = 10

    if name in HIGH_VALUE_NAMES:
        score += 80

    if name in {
        "pyproject.toml",
        "pom.xml",
        "package.json",
        "go.mod",
        "cargo.toml",
        "build.gradle",
        "build.gradle.kts",
        ".gitlab-ci.yml",
    }:
        score += 60

    if (
        ".github" in path.parts
        or ".gitlab" in path.parts
    ):
        score += 50

    if len(path.parts) == 1:
        score += 30

    if suffix in SOURCE_SUFFIXES:
        score += 5

    score -= min(
        25,
        len(path.parts) * 2,
    )

    return score
