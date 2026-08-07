from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_source_image_uses_bounded_lineage_cache_trust() -> None:
    text = (ROOT / "Dockerfile").read_text(
        encoding="utf-8"
    )
    source = text.split(
        "FROM runtime-base AS source",
        1,
    )[1].split(
        "FROM runtime-base AS jira",
        1,
    )[0]

    assert (
        '"--lineage-cache-max-age-days", "7"'
        in source
    )
    assert (
        '"--trust-lineage-cache-without-update-marker"'
        in source
    )


def test_cohort_workflow_uses_bounded_lineage_cache_trust() -> None:
    text = (
        ROOT
        / "deploy"
        / "cohort"
        / "workflow-template.yaml"
    ).read_text(encoding="utf-8")
    source = text.split(
        "\n    - name: source\n",
        1,
    )[1].split(
        "\n    - name: jira\n",
        1,
    )[0]

    assert (
        "          - --lineage-cache-max-age-days\n"
        '          - "7"\n'
        in source
    )
    assert (
        "          - --trust-lineage-cache-without-update-marker"
        in source
    )
