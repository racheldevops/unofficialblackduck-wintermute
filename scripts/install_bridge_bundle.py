#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import ssl
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


MAX_DOWNLOAD_BYTES = 1024 * 1024 * 1024
MAX_EXTRACTED_BYTES = 2 * 1024 * 1024 * 1024


def validated_url(value: str) -> str:
    selected = str(value or "").strip()
    parsed = urlsplit(selected)

    if (
        parsed.scheme.casefold() != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.casefold().endswith(".zip")
    ):
        raise ValueError(
            "Bridge bundle URL must be an HTTPS "
            "ZIP URL without credentials, query, "
            "or fragment"
        )

    return selected


def validated_sha256(value: str) -> str:
    selected = (
        str(value or "")
        .strip()
        .casefold()
        .removeprefix("sha256:")
    )

    if (
        len(selected) != 64
        or any(
            character
            not in "0123456789abcdef"
            for character in selected
        )
    ):
        raise ValueError(
            "Bridge bundle SHA-256 is invalid"
        )

    return selected


def tls_context(
    *,
    insecure: bool,
    ca_bundle: str | None,
) -> ssl.SSLContext | None:
    if insecure and ca_bundle:
        raise ValueError(
            "Use either --insecure or --ca-bundle"
        )

    if insecure:
        return ssl._create_unverified_context()

    if ca_bundle:
        path = Path(ca_bundle).expanduser()

        if not path.is_file():
            raise ValueError(
                f"CA bundle does not exist: {path}"
            )

        return ssl.create_default_context(
            cafile=str(path)
        )

    return None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as input_file:
        for chunk in iter(
            lambda: input_file.read(
                1024 * 1024
            ),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def download_bundle(
    url: str,
    destination: Path,
    *,
    insecure: bool = False,
    ca_bundle: str | None = None,
) -> str:
    request = Request(
        validated_url(url),
        headers={
            "Accept": "application/zip",
            "User-Agent": (
                "blackduck-wintermute-build"
            ),
        },
        method="GET",
    )
    digest = hashlib.sha256()
    total = 0
    context = tls_context(
        insecure=insecure,
        ca_bundle=ca_bundle,
    )

    with urlopen(
        request,
        timeout=120,
        context=context,
    ) as response:
        with destination.open(
            "wb"
        ) as output_file:
            while True:
                chunk = response.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                total += len(chunk)

                if total > MAX_DOWNLOAD_BYTES:
                    raise RuntimeError(
                        "Bridge bundle exceeded the "
                        "download size limit"
                    )

                digest.update(chunk)
                output_file.write(chunk)

            output_file.flush()
            os.fsync(output_file.fileno())

    if total == 0:
        raise RuntimeError(
            "Bridge bundle download was empty"
        )

    return digest.hexdigest()


def safe_archive_path(
    value: str,
) -> PurePosixPath:
    selected = str(value or "")

    if "\\" in selected:
        raise RuntimeError(
            "Bridge archive contains an unsafe path"
        )

    path = PurePosixPath(selected)

    if (
        path.is_absolute()
        or not path.parts
        or ".." in path.parts
    ):
        raise RuntimeError(
            "Bridge archive contains an unsafe path"
        )

    return path


def member_mode(
    info: zipfile.ZipInfo,
) -> int:
    return (
        info.external_attr >> 16
    ) & 0xFFFF


def make_directories_read_only(
    root: Path,
) -> None:
    directories = sorted(
        (
            path
            for path in root.rglob("*")
            if path.is_dir()
        ),
        key=lambda path: len(
            path.parts
        ),
        reverse=True,
    )

    for directory in directories:
        directory.chmod(0o555)

    root.chmod(0o555)


def remove_tree(path: Path) -> None:
    if not path.exists():
        return

    for root, directories, _files in os.walk(
        path,
        topdown=True,
        followlinks=False,
    ):
        Path(root).chmod(0o755)

        for directory in directories:
            selected = Path(root) / directory

            if not selected.is_symlink():
                selected.chmod(0o755)

    shutil.rmtree(
        path,
        ignore_errors=True,
    )


def install_archive(
    archive_path: Path,
    output: Path,
    *,
    source_url: str,
    archive_sha256: str,
) -> Path:
    if output.exists():
        raise RuntimeError(
            f"Bridge output already exists: {output}"
        )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{output.name}.",
            dir=output.parent,
        )
    )
    executable_candidates: list[
        Path
    ] = []
    extracted_bytes = 0
    moved = False

    try:
        with zipfile.ZipFile(
            archive_path
        ) as archive:
            for info in archive.infolist():
                relative = safe_archive_path(
                    info.filename
                )
                mode = member_mode(info)

                if stat.S_ISLNK(mode):
                    raise RuntimeError(
                        "Bridge archive contains "
                        "a symbolic link"
                    )

                destination = staging.joinpath(
                    *relative.parts
                )

                if info.is_dir():
                    destination.mkdir(
                        parents=True,
                        exist_ok=True,
                    )
                    continue

                if info.file_size < 0:
                    raise RuntimeError(
                        "Bridge archive contains an "
                        "invalid file size"
                    )

                extracted_bytes += (
                    info.file_size
                )

                if (
                    extracted_bytes
                    > MAX_EXTRACTED_BYTES
                ):
                    raise RuntimeError(
                        "Bridge archive exceeded the "
                        "extracted size limit"
                    )

                if destination.exists():
                    raise RuntimeError(
                        "Bridge archive contains a "
                        "duplicate path"
                    )

                destination.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                with archive.open(
                    info
                ) as input_file:
                    with destination.open(
                        "wb"
                    ) as output_file:
                        shutil.copyfileobj(
                            input_file,
                            output_file,
                            length=1024 * 1024,
                        )
                        output_file.flush()
                        os.fsync(
                            output_file.fileno()
                        )

                executable = (
                    destination.name
                    == "bridge-cli"
                    or bool(mode & 0o111)
                )
                destination.chmod(
                    0o555
                    if executable
                    else 0o444
                )

                if (
                    destination.name
                    == "bridge-cli"
                ):
                    executable_candidates.append(
                        destination
                    )

        if len(
            executable_candidates
        ) != 1:
            raise RuntimeError(
                "Bridge archive must contain "
                "exactly one bridge-cli executable"
            )

        executable = executable_candidates[0]
        relative_executable = (
            executable.relative_to(staging)
        )
        root_executable = (
            staging / "bridge-cli"
        )

        if (
            relative_executable
            != Path("bridge-cli")
        ):
            os.symlink(
                relative_executable.as_posix(),
                root_executable,
            )

        metadata = {
            "schema_version": 1,
            "source_url": source_url,
            "archive_sha256": (
                archive_sha256
            ),
            "executable": (
                relative_executable.as_posix()
            ),
            "extracted_bytes": (
                extracted_bytes
            ),
        }
        metadata_path = (
            staging
            / "bundle-metadata.json"
        )
        metadata_path.write_text(
            json.dumps(
                metadata,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        metadata_path.chmod(0o444)

        os.replace(
            staging,
            output,
        )
        moved = True
        make_directories_read_only(output)

        return output

    except BaseException:
        if moved:
            remove_tree(output)
        else:
            remove_tree(staging)

        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Download, verify, and install a "
            "Black Duck Bridge CLI Bundle."
        )
    )
    parser.add_argument(
        "--url",
        required=True,
    )
    parser.add_argument(
        "--sha256",
        default="",
    )
    parser.add_argument(
        "--output",
    )
    parser.add_argument(
        "--print-sha256",
        action="store_true",
    )
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument(
        "--insecure",
        action="store_true",
    )
    tls.add_argument(
        "--ca-bundle",
    )
    args = parser.parse_args()

    if not args.print_sha256:
        if not args.sha256:
            parser.error(
                "--sha256 is required for install"
            )

        if not args.output:
            parser.error(
                "--output is required for install"
            )

    return args


def main() -> int:
    args = parse_args()
    url = validated_url(args.url)

    with tempfile.TemporaryDirectory(
        prefix="wintermute-bridge-"
    ) as temporary:
        archive = (
            Path(temporary)
            / "bridge.zip"
        )
        actual = download_bundle(
            url,
            archive,
            insecure=args.insecure,
            ca_bundle=args.ca_bundle,
        )

        if args.print_sha256:
            print(actual)
            return 0

        expected = validated_sha256(
            args.sha256
        )

        if actual != expected:
            raise RuntimeError(
                "Bridge bundle SHA-256 mismatch: "
                f"expected {expected}, "
                f"received {actual}"
            )

        install_archive(
            archive,
            Path(args.output),
            source_url=url,
            archive_sha256=actual,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
