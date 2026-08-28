from __future__ import annotations

from pathlib import Path

from wintermute.scm import overview


def test_gitlab_overview_routes_inventory(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv(
        "SCM_URL",
        "https://gitlab.example.invalid",
    )
    monkeypatch.setenv(
        "GITLAB_GROUP",
        "group/subgroup",
    )
    monkeypatch.setenv(
        "GITLAB_TOKEN",
        "token",
    )
    monkeypatch.setenv(
        "BLACKDUCK_URL",
        "https://blackduck.example.invalid",
    )
    monkeypatch.setenv(
        "BLACKDUCK_API_TOKEN",
        "token",
    )
    captured = {}

    def inventory(
        arguments,
    ) -> int:
        captured["inventory"] = arguments
        return 0

    def coverage(
        arguments,
    ) -> int:
        captured["coverage"] = arguments
        return 0

    args = overview.parse_args(
        [
            "--output-root",
            str(tmp_path),
            "--snapshot-id",
            "gitlab-test",
            "--insecure",
            "--max-projects",
            "2",
            "--max-versions",
            "5",
        ]
    )

    assert overview.run(
        args,
        inventory_operation=inventory,
        coverage_operation=coverage,
    ) == 0

    inventory_arguments = captured[
        "inventory"
    ]
    coverage_arguments = captured[
        "coverage"
    ]

    assert "--scm-url" in inventory_arguments
    assert (
        inventory_arguments[
            inventory_arguments.index(
                "--scm-url"
            )
            + 1
        ]
        == "https://gitlab.example.invalid"
    )
    assert "--group" in inventory_arguments
    assert (
        inventory_arguments[
            inventory_arguments.index(
                "--group"
            )
            + 1
        ]
        == "group/subgroup"
    )
    assert "--organization" not in (
        inventory_arguments
    )
    assert "--max-projects" in (
        coverage_arguments
    )
    assert "--max-versions" in (
        coverage_arguments
    )


def test_github_remains_default(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv(
        "SCM_URL",
        raising=False,
    )
    monkeypatch.delenv(
        "GITLAB_GROUP",
        raising=False,
    )
    monkeypatch.delenv(
        "GITLAB_REST_URL",
        raising=False,
    )
    monkeypatch.setenv(
        "GITHUB_ORG",
        "acme",
    )
    monkeypatch.setenv(
        "GITHUB_TOKEN",
        "token",
    )
    monkeypatch.setenv(
        "BLACKDUCK_URL",
        "https://blackduck.example.invalid",
    )
    monkeypatch.setenv(
        "BLACKDUCK_API_TOKEN",
        "token",
    )
    captured = {}

    def inventory(
        arguments,
    ) -> int:
        captured["inventory"] = arguments
        return 0

    args = overview.parse_args(
        [
            "--output-root",
            str(tmp_path),
            "--snapshot-id",
            "github-test",
        ]
    )

    assert overview.run(
        args,
        inventory_operation=inventory,
        coverage_operation=lambda _: 0,
    ) == 0
    assert "--organization" in (
        captured["inventory"]
    )
    assert "--group" not in (
        captured["inventory"]
    )
