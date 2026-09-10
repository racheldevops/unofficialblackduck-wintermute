from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from wintermute.scm.onboarding.central_variables import (
    blackduck_variables,
    build_variables_plan,
    execute_variables_plan,
    load_variables_plan,
    write_variables_plan,
)
from wintermute.scm.onboarding.http import (
    HttpResult,
)


PROJECT = "rhorner/wintermute-security-scans"


def desired() -> dict[str, dict[str, Any]]:
    return blackduck_variables(
        {
            "BLACKDUCK_URL": (
                "https://blackduck.example"
            ),
            "BLACKDUCK_API_TOKEN": (
                "secret-blackduck-token"
            ),
        }
    )


def endpoint_key(path: str) -> str:
    return unquote(
        path.rsplit("/", 1)[-1]
    )


class Client:
    def __init__(self) -> None:
        self.requests = 0
        self.writes = 0
        self.branch_protected = False
        self.variables: dict[
            str,
            dict[str, Any],
        ] = {}

    def get_json(
        self,
        path: str,
        *,
        params=None,
        allow_not_found=False,
    ) -> HttpResult:
        del params
        self.requests += 1

        if path == (
            "/projects/rhorner%2F"
            "wintermute-security-scans"
        ):
            return HttpResult(
                200,
                {
                    "id": 20,
                    "path_with_namespace": (
                        PROJECT
                    ),
                    "default_branch": "main",
                    "visibility": "private",
                },
                {},
            )

        if "/protected_branches/" in path:
            if not self.branch_protected:
                assert allow_not_found
                return HttpResult(
                    404,
                    None,
                    {},
                )

            return HttpResult(
                200,
                {"name": "main"},
                {},
            )

        if "/variables/" in path:
            key = endpoint_key(path)
            value = self.variables.get(key)

            if value is None:
                assert allow_not_found
                return HttpResult(
                    404,
                    None,
                    {},
                )

            return HttpResult(
                200,
                dict(value),
                {},
            )

        raise AssertionError(path)

    def mutate_json(
        self,
        method: str,
        path: str,
        body: dict[str, Any],
        *,
        expected_statuses: set[int],
    ) -> HttpResult:
        self.requests += 1
        self.writes += 1

        if path.endswith(
            "/protected_branches"
        ):
            assert method == "POST"
            assert expected_statuses == {201}
            self.branch_protected = True
            return HttpResult(
                201,
                {"name": body["name"]},
                {},
            )

        if path.endswith("/variables"):
            assert method == "POST"
            assert expected_statuses == {201}
            self.variables[
                body["key"]
            ] = dict(body)
            return HttpResult(
                201,
                dict(body),
                {},
            )

        key = endpoint_key(path)
        assert method == "PUT"
        assert expected_statuses == {200}
        self.variables[key] = dict(body)

        return HttpResult(
            200,
            dict(body),
            {},
        )


def loaded(
    tmp_path: Path,
    client: Client,
):
    plan = build_variables_plan(
        client,
        project=PROJECT,
        branch="main",
        desired_variables=desired(),
    )
    directory = write_variables_plan(
        tmp_path / "plans",
        plan,
    )

    return load_variables_plan(
        directory
    )


def test_plan_contains_no_secret_values(
    tmp_path: Path,
) -> None:
    client = Client()
    selected = loaded(
        tmp_path,
        client,
    )
    rendered = (
        selected.directory
        / "plan.json"
    ).read_text(encoding="utf-8")

    assert "secret-blackduck-token" not in rendered
    assert (
        "https://blackduck.example"
        not in rendered
    )
    assert (
        "BLACKDUCK_API_TOKEN"
        in rendered
    )
    assert (
        selected.plan[
            "estimated_writes"
        ]
        == 3
    )


def test_dry_run_does_not_write(
    tmp_path: Path,
) -> None:
    client = Client()
    selected = loaded(
        tmp_path,
        client,
    )
    writes_before = client.writes
    code, result, _ = (
        execute_variables_plan(
            selected,
            client,
            desired_variables=desired(),
            mode="dry-run",
            result_root=(
                tmp_path / "results"
            ),
            maximum_writes=3,
        )
    )

    assert code == 0
    assert result["outcome"] == "planned"
    assert result["writes"] == 0
    assert client.writes == writes_before
    assert (
        result["secret_values_recorded"]
        is False
    )


def test_apply_configures_and_verifies(
    tmp_path: Path,
) -> None:
    client = Client()
    selected = loaded(
        tmp_path,
        client,
    )
    code, result, _ = (
        execute_variables_plan(
            selected,
            client,
            desired_variables=desired(),
            mode="apply",
            result_root=(
                tmp_path / "results"
            ),
            maximum_writes=3,
            confirm_apply=True,
            expected_plan_digest=(
                selected.digest
            ),
        )
    )

    assert code == 0
    assert result["outcome"] == "applied"
    assert result["writes"] == 3
    assert client.branch_protected is True
    assert set(client.variables) == {
        "BLACKDUCK_URL",
        "BLACKDUCK_API_TOKEN",
    }
    assert client.variables[
        "BLACKDUCK_URL"
    ]["protected"] is True
    assert client.variables[
        "BLACKDUCK_URL"
    ]["masked"] is False
    assert client.variables[
        "BLACKDUCK_API_TOKEN"
    ]["protected"] is True
    assert client.variables[
        "BLACKDUCK_API_TOKEN"
    ]["masked"] is True


def test_second_plan_is_idempotent(
    tmp_path: Path,
) -> None:
    client = Client()
    first = loaded(
        tmp_path,
        client,
    )
    execute_variables_plan(
        first,
        client,
        desired_variables=desired(),
        mode="apply",
        result_root=(
            tmp_path / "results"
        ),
        maximum_writes=3,
        confirm_apply=True,
        expected_plan_digest=(
            first.digest
        ),
    )
    second = build_variables_plan(
        client,
        project=PROJECT,
        branch="main",
        desired_variables=desired(),
    )

    assert second["actions"] == []
    assert second[
        "estimated_writes"
    ] == 0


def test_result_contains_no_secret(
    tmp_path: Path,
) -> None:
    client = Client()
    selected = loaded(
        tmp_path,
        client,
    )
    _, _, result_path = (
        execute_variables_plan(
            selected,
            client,
            desired_variables=desired(),
            mode="dry-run",
            result_root=(
                tmp_path / "results"
            ),
            maximum_writes=3,
        )
    )
    rendered = (
        result_path / "result.json"
    ).read_text(encoding="utf-8")

    assert "secret-blackduck-token" not in rendered
    assert (
        "https://blackduck.example"
        not in rendered
    )

    payload = json.loads(rendered)

    assert payload[
        "secret_values_recorded"
    ] is False
