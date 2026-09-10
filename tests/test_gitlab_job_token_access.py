from __future__ import annotations

from pathlib import Path

from wintermute.scm.onboarding.job_token_access import (
    GitLabJobTokenAccessClient,
    build_access_plan,
    execute_access_plan,
    load_verified_access_plan,
    probe_access,
    write_access_plan,
)
from wintermute.scm.onboarding.http import (
    HttpResult,
)


class Client:
    requests = 0
    writes = 0

    def __init__(self) -> None:
        self.scope_enabled = {
            10: False,
            20: True,
        }
        self.allowed_groups = {
            10: set(),
            20: set(),
        }
        self.mutations = []

    def get_json(
        self,
        path,
        *,
        params=None,
        allow_not_found=False,
    ):
        del params
        del allow_not_found
        self.requests += 1

        if path == "/groups/bd-releng":
            return HttpResult(
                200,
                {
                    "id": 30,
                    "full_path": "bd-releng",
                },
                {},
            )

        if path == (
            "/projects/rhorner%2Fwintermute"
        ):
            return HttpResult(
                200,
                {"id": 10},
                {},
            )

        if path == (
            "/projects/rhorner%2F"
            "wintermute-security-scans"
        ):
            return HttpResult(
                200,
                {"id": 20},
                {},
            )

        if path.endswith(
            "/job_token_scope"
        ):
            project_id = int(
                path.split("/")[2]
            )

            return HttpResult(
                200,
                {
                    "inbound_enabled": (
                        self.scope_enabled[
                            project_id
                        ]
                    )
                },
                {},
            )

        raise AssertionError(path)

    def paged_list(
        self,
        path,
        *,
        params=None,
    ):
        del params
        self.requests += 1
        project_id = int(
            path.split("/")[2]
        )

        return [
            {"id": value}
            for value in sorted(
                self.allowed_groups[
                    project_id
                ]
            )
        ]

    def mutate_json(
        self,
        method,
        path,
        body,
        *,
        expected_statuses,
    ):
        del expected_statuses
        self.requests += 1
        self.writes += 1
        self.mutations.append(
            (method, path, dict(body))
        )
        project_id = int(
            path.split("/")[2]
        )

        if method == "PATCH":
            self.scope_enabled[
                project_id
            ] = True

            return HttpResult(
                200,
                {
                    "inbound_enabled": True
                },
                {},
            )

        self.allowed_groups[
            project_id
        ].add(
            int(body["target_group_id"])
        )

        return HttpResult(
            201,
            {"id": 30},
            {},
        )


def loaded_plan(
    tmp_path: Path,
):
    plan = build_access_plan(
        bootstrap_plan_id=(
            "bootstrap-one"
        ),
        bootstrap_plan_digest=(
            "sha256:" + "a" * 64
        ),
        central_project=(
            "rhorner/"
            "wintermute-security-scans"
        ),
        image_project=(
            "rhorner/wintermute"
        ),
        consumer_group="bd-releng",
    )
    directory = write_access_plan(
        tmp_path / "plans",
        plan,
    )

    return load_verified_access_plan(
        directory
    )


def test_read_client_class_is_provider_scoped() -> None:
    assert issubclass(
        GitLabJobTokenAccessClient,
        __import__(
            "wintermute.scm.onboarding.http",
            fromlist=[
                "OnboardingHttpClient"
            ],
        ).OnboardingHttpClient,
    )


def test_probe_plans_group_access(
    tmp_path: Path,
) -> None:
    result = probe_access(
        loaded_plan(tmp_path),
        Client(),
        allow_pending_projects=False,
    )

    assert result["status"] == "ready"
    assert result["estimated_writes"] == 3
    assert {
        value["kind"]
        for value in result["actions"]
    } == {
        "gitlab.job-token-scope.enable",
        (
            "gitlab.job-token-group-"
            "allowlist.add"
        ),
    }


def test_apply_configures_and_verifies(
    tmp_path: Path,
) -> None:
    plan = loaded_plan(tmp_path)
    client = Client()
    code, result, path = (
        execute_access_plan(
            plan,
            client,
            mode="apply",
            confirm_apply=True,
            expected_plan_digest=(
                plan.digest
            ),
            maximum_writes=3,
            result_root=(
                tmp_path / "results"
            ),
        )
    )

    assert code == 0
    assert result["status"] == "ok"
    assert result["outcome"] == "applied"
    assert result["writes"] == 3
    assert result["after"][
        "actions"
    ] == []
    assert (
        path / "result.json"
    ).is_file()


def test_dry_run_never_writes(
    tmp_path: Path,
) -> None:
    client = Client()
    code, result, _ = execute_access_plan(
        loaded_plan(tmp_path),
        client,
        mode="dry-run",
        maximum_writes=3,
        result_root=(
            tmp_path / "results"
        ),
    )

    assert code == 0
    assert result["outcome"] == "planned"
    assert result["writes"] == 0
    assert client.writes == 0
