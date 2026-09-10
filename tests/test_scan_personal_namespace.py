from __future__ import annotations

from pathlib import Path
from typing import Any

from wintermute.scm.onboarding.bootstrap import (
    GitLabBootstrapTarget,
    LoadedBootstrapPlan,
    build_bootstrap_plan,
)
from wintermute.scm.onboarding.bootstrap_providers import (
    GitLabBootstrapAdapter,
)
from wintermute.scm.onboarding.http import (
    HttpResult,
)


class Bundle:
    bundle_id = "bundle-one"
    digest = "sha256:" + "a" * 64
    files = {
        "registry/scan-registry.json": b"{}\n",
        (
            "templates/"
            "wintermute-security.yml"
        ): (
            b"wintermute_security_scan:\n"
        ),
    }


class Client:
    def __init__(self) -> None:
        self.created: (
            dict[str, Any] | None
        ) = None

    def get_json(
        self,
        path,
        *,
        params=None,
        allow_not_found=False,
    ):
        del params

        if path == "/user":
            return HttpResult(
                200,
                {
                    "id": 7,
                    "username": "rhorner",
                    "namespace_id": 17,
                },
                {},
            )

        if (
            path
            == "/projects/"
            "rhorner%2F"
            "wintermute-security-scans"
            and allow_not_found
        ):
            return HttpResult(
                404,
                None,
                {},
            )

        raise AssertionError(path)

    def mutate_json(
        self,
        method,
        path,
        body,
        *,
        expected_statuses,
    ):
        assert method == "POST"
        assert path == "/projects"
        assert expected_statuses == {201}
        assert "namespace_id" not in body
        self.created = dict(body)

        return HttpResult(
            201,
            {
                "path_with_namespace": (
                    "rhorner/"
                    "wintermute-security-scans"
                ),
                "default_branch": "main",
            },
            {},
        )


def bootstrap_bundle(
    tmp_path: Path,
) -> LoadedBootstrapPlan:
    return LoadedBootstrapPlan(
        directory=tmp_path,
        plan={
            "repositories": [
                {
                    "provider": "gitlab",
                    "namespace": "rhorner",
                    "namespace_type": "user",
                    "repository": (
                        "wintermute-security-scans"
                    ),
                    "name_with_owner": (
                        "rhorner/"
                        "wintermute-security-scans"
                    ),
                    "default_branch": "main",
                }
            ]
        },
        digest="sha256:" + "a" * 64,
        files={
            "gitlab": {
                (
                    "registry/"
                    "scan-registry.json"
                ): b"{}\n",
                (
                    "templates/"
                    "wintermute-security.yml"
                ): b"scan:\n",
                (
                    "wintermute-managed.json"
                ): b"{}\n",
            }
        },
    )


def test_personal_namespace_is_recorded() -> None:
    plan, _ = build_bootstrap_plan(
        Bundle(),
        gitlab=GitLabBootstrapTarget(
            namespace="rhorner",
            namespace_type="user",
        ),
    )
    repository = plan["repositories"][0]

    assert repository[
        "name_with_owner"
    ] == (
        "rhorner/"
        "wintermute-security-scans"
    )
    assert repository[
        "namespace_type"
    ] == "user"


def test_user_namespace_creation_omits_namespace_id(
    tmp_path: Path,
) -> None:
    client = Client()
    adapter = GitLabBootstrapAdapter(
        client
    )
    selected = bootstrap_bundle(
        tmp_path
    )
    probe = adapter.probe(selected)

    assert probe["status"] == "ready"
    assert probe[
        "namespace_type"
    ] == "user"

    writes = adapter.apply(
        selected,
        [
            {
                "kind": (
                    "gitlab.project.create"
                )
            }
        ],
    )

    assert writes == 1
    assert client.created is not None
    assert (
        "namespace_id"
        not in client.created
    )


def test_user_namespace_rejects_other_token_user(
    tmp_path: Path,
) -> None:
    class WrongUserClient(Client):
        def get_json(
            self,
            path,
            *,
            params=None,
            allow_not_found=False,
        ):
            if path == "/user":
                return HttpResult(
                    200,
                    {
                        "id": 8,
                        "username": "other-user",
                    },
                    {},
                )

            return super().get_json(
                path,
                params=params,
                allow_not_found=(
                    allow_not_found
                ),
            )

    adapter = GitLabBootstrapAdapter(
        WrongUserClient()
    )

    try:
        adapter.probe(
            bootstrap_bundle(tmp_path)
        )
    except RuntimeError as error:
        assert (
            "not the planned user namespace"
            in str(error)
        )
    else:
        raise AssertionError(
            "Wrong GitLab user was accepted"
        )
