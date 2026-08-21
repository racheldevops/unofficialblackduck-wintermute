from __future__ import annotations

import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_cohort_and_scm_entrypoints_exist() -> None:
    payload = tomllib.loads(
        (ROOT / "pyproject.toml").read_text(
            encoding="utf-8"
        )
    )
    scripts = payload["project"]["scripts"]

    expected = {
        "blackduck-wintermute-cohort-source": (
            "wintermute.blackduck.cohort_source:main"
        ),
        "blackduck-wintermute-jira-cohort": (
            "wintermute.jira.cohort_pipeline:main"
        ),
        "blackduck-wintermute-datadog-cohort": (
            "wintermute.datadog.cohort_pipeline:main"
        ),
        "blackduck-wintermute-scm-overview": (
            "wintermute.scm.overview:main"
        ),
    }

    for name, target in expected.items():
        assert scripts[name] == target


def test_dockerfile_has_four_workflow_targets() -> None:
    text = (ROOT / "Dockerfile").read_text(
        encoding="utf-8"
    )

    expected = {
        "source": (
            "blackduck-wintermute-cohort-source"
        ),
        "jira": (
            "blackduck-wintermute-jira-cohort"
        ),
        "datadog": (
            "blackduck-wintermute-datadog-cohort"
        ),
        "scm": (
            "blackduck-wintermute-scm-overview"
        ),
    }

    for target, entrypoint in expected.items():
        assert (
            f"FROM runtime-base AS {target}"
            in text
        )
        assert (
            f'ENTRYPOINT ["{entrypoint}"]'
            in text
        )


def test_scm_image_defaults_are_conservative() -> None:
    text = (ROOT / "Dockerfile").read_text(
        encoding="utf-8"
    )
    stage = text.split(
        "FROM runtime-base AS scm",
        1,
    )[1].split(
        "FROM runtime-base AS runtime",
        1,
    )[0]

    assert (
        'ENTRYPOINT ["blackduck-wintermute-scm-overview"]'
        in stage
    )
    assert '"--workers", "1"' in stage
    assert '"--evidence-workers", "1"' in stage
    assert '"--scan-evidence-workers", "1"' in stage
    assert '"--page-limit", "100"' in stage
    assert "--collect-direct-scan-evidence" not in stage


def test_argo_scm_is_optional_and_read_only() -> None:
    text = (
        ROOT
        / "deploy"
        / "cohort"
        / "workflow-template.yaml"
    ).read_text(encoding="utf-8")

    assert "name: scm-image" in text
    assert "name: scm-mode" in text
    assert "          - read-only" in text
    assert (
        "when: \"{{=workflow.parameters['scm-mode'] "
        "!= 'disabled'}}\""
        in text
    )
    assert (
        "command:\n"
        "          - blackduck-wintermute-scm-overview"
        in text
    )
    assert (
        "name: blackduck-wintermute-scm-credentials"
        in text
    )
    assert (
        "name: blackduck-wintermute-blackduck-credentials"
        in text
    )
    assert "--allow-partial" not in text


def test_argo_storage_is_isolated() -> None:
    text = (
        ROOT
        / "deploy"
        / "cohort"
        / "workflow-template.yaml"
    ).read_text(encoding="utf-8")

    for claim in (
        "blackduck-wintermute-cohorts",
        "blackduck-wintermute-source-data",
        "blackduck-wintermute-jira-data",
        "blackduck-wintermute-datadog-data",
        "blackduck-wintermute-scm-data",
    ):
        assert f"claimName: {claim}" in text
