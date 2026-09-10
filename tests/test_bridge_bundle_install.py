from __future__ import annotations

import importlib.util
import stat
import zipfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (
    ROOT
    / "scripts"
    / "install_bridge_bundle.py"
)
SPEC = importlib.util.spec_from_file_location(
    "install_bridge_bundle",
    SCRIPT,
)
assert SPEC is not None
assert SPEC.loader is not None
installer = importlib.util.module_from_spec(
    SPEC
)
SPEC.loader.exec_module(installer)


def create_bundle(
    path: Path,
) -> None:
    with zipfile.ZipFile(
        path,
        "w",
    ) as archive:
        executable = zipfile.ZipInfo(
            "bridge/bridge-cli"
        )
        executable.external_attr = (
            (stat.S_IFREG | 0o755) << 16
        )
        archive.writestr(
            executable,
            b"#!/bin/sh\nexit 0\n",
        )
        archive.writestr(
            "bridge/workflows/example.json",
            b"{}\n",
        )


def test_bundle_install_is_pinned(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "bridge.zip"
    output = tmp_path / "installed"
    create_bundle(archive)
    digest = installer.sha256_file(
        archive
    )

    installer.install_archive(
        archive,
        output,
        source_url=(
            "https://repo.example/"
            "bridge.zip"
        ),
        archive_sha256=digest,
    )

    assert (
        output / "bridge-cli"
    ).is_symlink()
    assert (
        output / "bridge-cli"
    ).resolve().is_file()
    assert (
        output / "bundle-metadata.json"
    ).is_file()


def test_archive_traversal_is_rejected(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "bad.zip"

    with zipfile.ZipFile(
        archive,
        "w",
    ) as output:
        output.writestr(
            "../bridge-cli",
            b"bad",
        )

    with pytest.raises(
        RuntimeError,
        match="unsafe path",
    ):
        installer.install_archive(
            archive,
            tmp_path / "installed",
            source_url=(
                "https://repo.example/"
                "bridge.zip"
            ),
            archive_sha256=(
                installer.sha256_file(
                    archive
                )
            ),
        )


def test_bundle_url_requires_https_zip() -> None:
    with pytest.raises(ValueError):
        installer.validated_url(
            "http://example.invalid/bridge.zip"
        )

    with pytest.raises(ValueError):
        installer.validated_url(
            "https://example.invalid/latest/"
        )
