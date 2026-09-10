from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_scan_target_selects_bridge_by_architecture() -> None:
    text = (
        ROOT / "Dockerfile"
    ).read_text(encoding="utf-8")

    assert "ARG TARGETARCH" in text
    assert (
        "ARG BRIDGE_BUNDLE_AMD64_URL="
        in text
    )
    assert (
        "ARG BRIDGE_BUNDLE_AMD64_SHA256"
        in text
    )
    assert (
        "ARG BRIDGE_BUNDLE_ARM64_URL="
        in text
    )
    assert (
        "ARG BRIDGE_BUNDLE_ARM64_SHA256"
        in text
    )
    assert 'amd64)' in text
    assert 'arm64)' in text
    assert (
        "Unsupported scan image architecture"
        in text
    )


def test_other_runtime_targets_do_not_require_bridge() -> None:
    text = (
        ROOT / "Dockerfile"
    ).read_text(encoding="utf-8")
    scan_start = text.index(
        "FROM runtime-base AS scan"
    )
    bridge_copy = text.index(
        "COPY --from=bridge-bundle",
    )

    assert bridge_copy > scan_start

    for target in (
        "source",
        "jira",
        "datadog",
        "scm",
    ):
        assert (
            f"FROM runtime-base AS {target}"
            in text[:scan_start]
        )


def test_scan_target_is_non_root() -> None:
    text = (
        ROOT / "Dockerfile"
    ).read_text(encoding="utf-8")
    stage = text.split(
        "FROM runtime-base AS scan",
        1,
    )[1].split(
        "FROM runtime-base AS runtime",
        1,
    )[0]

    assert (
        'ENTRYPOINT ["blackduck-wintermute-scan"]'
        in stage
    )
    assert (
        "BLACKDUCK_BRIDGE_PATH="
        "/opt/blackduck/bridge/bridge-cli"
        in stage
    )
    assert (
        stage.rfind("USER 10001:10001")
        > stage.rfind("USER root")
    )


def test_multiarch_script_builds_both_platforms() -> None:
    text = (
        ROOT
        / "scripts"
        / "build_scan_multiarch.zsh"
    ).read_text(encoding="utf-8")

    assert (
        "--platform linux/amd64,linux/arm64"
        in text
    )
    assert (
        "BRIDGE_BUNDLE_AMD64_SHA256"
        in text
    )
    assert (
        "BRIDGE_BUNDLE_ARM64_SHA256"
        in text
    )
    assert "--push" in text
    assert ":latest" in text
