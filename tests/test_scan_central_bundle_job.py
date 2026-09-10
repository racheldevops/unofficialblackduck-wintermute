from __future__ import annotations

import pytest

from wintermute.scm.onboarding.central_bundle_job import (
    immutable_image_digest,
    parse_bridge_probe,
    parse_image_inspection,
)


DIGEST = "sha256:" + "a" * 64
IMAGE = (
    "registry.example.invalid/"
    "security/wintermute/scan@"
    + DIGEST
)


def inspection_text(
    *,
    media_type: str = (
        "application/vnd.oci.image.index.v1+json"
    ),
    platforms: tuple[str, ...] = (
        "linux/amd64",
        "linux/arm64",
    ),
) -> str:
    lines = [
        f"Name: {IMAGE}",
        f"MediaType: {media_type}",
        f"Digest: {DIGEST}",
        "",
        "Manifests:",
    ]

    for index, selected in enumerate(
        platforms,
        start=1,
    ):
        lines.extend(
            [
                (
                    "  Name: "
                    "registry.example.invalid/"
                    "security/wintermute/scan@"
                    "sha256:"
                    + str(index) * 64
                ),
                (
                    "  MediaType: "
                    "application/vnd.oci.image."
                    "manifest.v1+json"
                ),
                f"  Platform: {selected}",
            ]
        )

    return "\n".join(lines)


def test_image_requires_digest_reference() -> None:
    assert immutable_image_digest(
        IMAGE
    ) == DIGEST

    with pytest.raises(
        ValueError,
        match="immutable",
    ):
        immutable_image_digest(
            "registry.example.invalid/scan:latest"
        )


def test_multiarch_image_inspection() -> None:
    result = parse_image_inspection(
        IMAGE,
        inspection_text(),
    )

    assert result["index_digest"] == DIGEST
    assert result["platforms"] == [
        "linux/amd64",
        "linux/arm64",
    ]


def test_image_inspection_rejects_single_manifest() -> None:
    with pytest.raises(
        RuntimeError,
        match="not a multi-architecture",
    ):
        parse_image_inspection(
            IMAGE,
            inspection_text(
                media_type=(
                    "application/vnd.oci.image."
                    "manifest.v1+json"
                ),
            ),
        )


def test_image_inspection_requires_both_platforms() -> None:
    with pytest.raises(
        RuntimeError,
        match="linux/arm64",
    ):
        parse_image_inspection(
            IMAGE,
            inspection_text(
                platforms=(
                    "linux/amd64",
                ),
            ),
        )


def test_image_inspection_requires_expected_digest() -> None:
    changed = inspection_text().replace(
        f"Digest: {DIGEST}",
        (
            "Digest: sha256:"
            + "b" * 64
        ),
        1,
    )

    with pytest.raises(
        RuntimeError,
        match="digest mismatch",
    ):
        parse_image_inspection(
            IMAGE,
            changed,
        )


def test_bridge_probe_parses_supported_machine() -> None:
    result = parse_bridge_probe(
        (
            '{"bridge_sha256":"'
            + "c" * 64
            + '","machine":"aarch64"}\n'
        )
    )

    assert result == {
        "bridge_sha256": "c" * 64,
        "machine": "aarch64",
        "platform": "linux/arm64",
    }


def test_bridge_probe_rejects_bad_digest() -> None:
    with pytest.raises(
        RuntimeError,
        match="digest is invalid",
    ):
        parse_bridge_probe(
            (
                '{"bridge_sha256":"short",'
                '"machine":"x86_64"}'
            )
        )
