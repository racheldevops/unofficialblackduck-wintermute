from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (
    ROOT
    / "scripts"
    / "render_cohort_manifest.py"
)
SPEC = importlib.util.spec_from_file_location(
    "render_cohort_manifest",
    SCRIPT,
)
assert SPEC is not None
assert SPEC.loader is not None
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)


def test_apply_modes_require_confirmation() -> None:
    with pytest.raises(
        RuntimeError,
        match="requires confirm_apply",
    ):
        renderer.validate_options(
            registry_host="registry.example",
            registry_repository=(
                "security/blackduck-wintermute"
            ),
            image_tag="abc123",
            namespace="blackduck-wintermute",
            jira_mode="apply",
            datadog_mode="dry-run",
            confirm_apply=False,
            retain_cohorts=10,
        )


def test_latest_image_tag_is_rejected() -> None:
    with pytest.raises(
        RuntimeError,
        match="immutable",
    ):
        renderer.validate_options(
            registry_host="registry.example",
            registry_repository=(
                "security/blackduck-wintermute"
            ),
            image_tag="latest",
            namespace="blackduck-wintermute",
            jira_mode="dry-run",
            datadog_mode="dry-run",
            confirm_apply=False,
            retain_cohorts=10,
        )


def test_schedule_patch_contains_all_images() -> None:
    images = renderer.image_names(
        "registry.example",
        "security/blackduck-wintermute",
        "commit123",
    )
    patch = renderer.schedule_patch(
        schedule="0 2 * * *",
        timezone="Etc/UTC",
        suspend=True,
        jira_mode="dry-run",
        datadog_mode="dry-run",
        confirm_apply=False,
        retain_cohorts=10,
        images=images,
    )

    for image in images.values():
        assert f"value: {image}" in patch


def test_schedule_defaults_are_safe() -> None:
    patch = renderer.schedule_patch(
        schedule="0 2 * * *",
        timezone="Etc/UTC",
        suspend=True,
        jira_mode="dry-run",
        datadog_mode="dry-run",
        confirm_apply=False,
        retain_cohorts=10,
    )

    assert "suspend: true" in patch
    assert "value: dry-run" in patch
    assert 'value: "false"' in patch
    assert 'value: "10"' in patch


def test_renderer_rewrites_argo_images(
    tmp_path: Path,
) -> None:
    kubectl = shutil.which("kubectl")

    if not kubectl:
        pytest.skip("kubectl is unavailable")

    output = tmp_path / "manifest.yaml"

    renderer.render_manifest(
        ROOT,
        output=output,
        registry_host="registry.example",
        registry_repository=(
            "security/blackduck-wintermute"
        ),
        image_tag="commit123",
        namespace="blackduck-wintermute-test",
        jira_mode="dry-run",
        datadog_mode="dry-run",
        confirm_apply=False,
        retain_cohorts=10,
        schedule="0 2 * * *",
        timezone="Etc/UTC",
        suspend=True,
        kubectl=kubectl,
    )

    text = output.read_text(
        encoding="utf-8"
    )
    expected = {
        "source": (
            "registry.example/security/"
            "blackduck-wintermute-source:commit123"
        ),
        "jira": (
            "registry.example/security/"
            "blackduck-wintermute-jira:commit123"
        ),
        "datadog": (
            "registry.example/security/"
            "blackduck-wintermute-datadog:commit123"
        ),
    }

    for target, image in expected.items():
        assert text.count(f"value: {image}") == 1
        expected_runtime_count = (
            3 if target == "source" else 1
        )
        assert text.count(
            f"{{{{workflow.parameters.{target}-image}}}}"
        ) == expected_runtime_count

    assert "namespace: blackduck-wintermute-test" in text
    assert (
        "name: blackduck-wintermute-cohort-jira-config"
        in text
    )
    assert (
        "blackduck-wintermute-test-cohort-jira-config"
        not in text
    )
    assert "registry.invalid" not in text
    assert ":replace-me" not in text
