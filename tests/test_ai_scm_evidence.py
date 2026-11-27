from __future__ import annotations

from wintermute.ai.safety import (
    Anonymizer,
    Sanitizer,
)
from wintermute.ai.scm_evidence import (
    RemoteFile,
    build_lazy_remote_catalog,
    build_remote_catalog,
)
from wintermute.scm.models import Repository


class Source:
    provider = "gitlab"

    def __init__(self) -> None:
        self.reads: list[str] = []
        self.repository = Repository(
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

    @property
    def request_count(self) -> int:
        return 1 + len(self.reads)

    def list_files(self):
        return (
            RemoteFile(
                "src/private/module.py",
                40,
            ),
            RemoteFile(
                "pyproject.toml",
                80,
            ),
            RemoteFile(
                ".env",
                20,
            ),
        )

    def read_file(
        self,
        path: str,
    ) -> bytes:
        self.reads.append(path)
        values = {
            "src/private/module.py": (
                b"print('example')\n"
            ),
            "pyproject.toml": (
                b"[project]\n"
                b"name='private-name'\n"
                b"API_TOKEN=secret-value\n"
            ),
            ".env": (
                b"PASSWORD=secret\n"
            ),
        }

        return values[path]


def sanitizer() -> Sanitizer:
    return Sanitizer(
        Anonymizer("test-key")
    )


def test_lazy_catalog_does_not_fetch_contents() -> None:
    source = Source()
    catalog = build_lazy_remote_catalog(
        source,
        sanitizer(),
        max_catalog_files=10,
        max_file_bytes=1000,
        max_total_bytes=2000,
    )

    assert source.reads == []
    assert catalog.listed_file_count == 2
    assert catalog.selected_file_count == 0

    selected = catalog.search(
        "python build",
        limit=1,
    )
    payload, _ = catalog.evidence_payload(
        selected,
        max_bytes=1000,
    )

    assert len(payload) == 1
    assert len(source.reads) == 1
    assert catalog.selected_file_count == 1


def test_remote_catalog_is_bounded_and_sanitized() -> None:
    source = Source()
    result = build_remote_catalog(
        source,
        sanitizer(),
        max_catalog_files=10,
        max_file_bytes=1000,
        max_total_bytes=2000,
    )

    assert result.listed_file_count == 3
    assert result.selected_file_count == 2
    assert result.failures == ()
    rendered = " ".join(
        value.sanitized_text
        for value
        in result.catalog.records
    )

    assert "secret-value" not in rendered
    assert "PASSWORD=secret" not in rendered
    assert ".env" not in {
        value.descriptor.relative_path
        for value
        in result.catalog.records
    }


def test_remote_catalog_prioritizes_build_files() -> None:
    result = build_remote_catalog(
        Source(),
        sanitizer(),
        max_catalog_files=1,
        max_file_bytes=1000,
        max_total_bytes=2000,
    )

    assert (
        result.catalog.records[0]
        .descriptor.relative_path
        == "pyproject.toml"
    )
