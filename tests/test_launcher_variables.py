from __future__ import annotations

import copy
from types import SimpleNamespace

import pytest

from wintermute.scm.onboarding import central_variables as variables
from wintermute.scm.onboarding import setup


KEY = "WINTERMUTE_GITLAB_READ_TOKEN"
PROJECT = "example/security-scans"
TOKEN = "synthetic-general-token"


class Client:
    def __init__(self):
        self.requests = 0
        self.writes = 0
        self.protected = False
        self.variables = {}
        self.mutations = []

    def get_json(self, path, **kwargs):
        self.requests += 1
        if path == "/projects/example%2Fsecurity-scans":
            return SimpleNamespace(
                status_code=200,
                payload={
                    "id": 70,
                    "path_with_namespace": PROJECT,
                    "visibility": "private",
                    "default_branch": "main",
                },
            )
        if path == "/projects/70/protected_branches/main":
            return SimpleNamespace(
                status_code=200 if self.protected else 404,
                payload={"name": "main"} if self.protected else None,
            )
        prefix = "/projects/70/variables/"
        if path.startswith(prefix):
            key = path[len(prefix):]
            current = self.variables.get(key)
            return SimpleNamespace(
                status_code=200 if current is not None else 404,
                payload=copy.deepcopy(current),
            )
        raise AssertionError(f"Unexpected endpoint: {path}")

    def mutate_json(self, method, path, body, *, expected_statuses):
        self.requests += 1
        self.writes += 1
        self.mutations.append((method, path))

        if method == "POST" and path == "/projects/70/protected_branches":
            self.protected = True
            return SimpleNamespace(status_code=201, payload={"name": "main"})

        if method == "POST" and path == "/projects/70/variables":
            self.variables[body["key"]] = copy.deepcopy(body)
            return SimpleNamespace(status_code=201, payload=copy.deepcopy(body))

        if method == "PUT" and path.startswith("/projects/70/variables/"):
            key = path.rsplit("/", 1)[-1]
            assert key == body["key"]
            self.variables[key] = copy.deepcopy(body)
            return SimpleNamespace(status_code=200, payload=copy.deepcopy(body))

        raise AssertionError(f"Unexpected mutation: {method} {path}")


def desired(token=TOKEN):
    return variables.launcher_variables({"GITLAB_TOKEN": token})


def plan(tmp_path, client, desired_variables):
    payload = variables.build_variables_plan(
        client,
        project=PROJECT,
        branch="main",
        desired_variables=desired_variables,
    )
    directory = variables.write_variables_plan(tmp_path / "plans", payload)
    return variables.load_variables_plan(directory)


def execute(tmp_path, loaded, client, desired_variables, mode):
    return variables.execute_variables_plan(
        loaded,
        client,
        desired_variables=desired_variables,
        mode=mode,
        result_root=tmp_path / "results",
        maximum_writes=3,
        confirm_apply=mode == "apply",
        expected_plan_digest=loaded.digest if mode == "apply" else "",
    )


def test_one_token_provisions_masked_protected_nonexpanding_variable():
    value = desired()[KEY]
    assert value["value"] == TOKEN
    assert value["masked"] is True
    assert value["protected"] is True
    assert value["raw"] is True
    assert value["variable_type"] == "env_var"
    assert value["environment_scope"] == "*"


def test_optional_dedicated_token_overrides_general_token():
    value = variables.launcher_variables({
        "GITLAB_TOKEN": TOKEN,
        KEY: "synthetic-dedicated-token",
    })
    assert value[KEY]["value"] == "synthetic-dedicated-token"


def test_action_token_is_not_implicitly_deployed():
    value = variables.launcher_variables({
        "GITLAB_TOKEN": TOKEN,
        "GITLAB_ACTION_TOKEN": "synthetic-administrator-token",
    })
    assert value[KEY]["value"] == TOKEN


def test_variable_selection_does_not_modify_environment():
    environment = {"GITLAB_TOKEN": TOKEN}
    before = dict(environment)
    variables.launcher_variables(environment)
    assert environment == before


def test_missing_general_token_fails_without_action_fallback():
    with pytest.raises(variables.CentralVariablesError, match="GITLAB_TOKEN"):
        variables.launcher_variables({
            "GITLAB_ACTION_TOKEN": "synthetic-action-token",
        })


@pytest.mark.parametrize("token", ["short", "bad\ntoken", "bad token value"])
def test_invalid_masked_token_is_rejected(token):
    with pytest.raises(variables.CentralVariablesError):
        variables.launcher_variables({"GITLAB_TOKEN": token})


def test_setup_always_includes_launcher_authentication(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", TOKEN)
    monkeypatch.delenv(KEY, raising=False)
    monkeypatch.delenv("BLACKDUCK_URL", raising=False)
    monkeypatch.delenv("BLACKDUCK_API_TOKEN", raising=False)
    assert set(setup.desired_blackduck_variables({})) == {KEY}


def test_setup_can_include_blackduck_variables(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", TOKEN)
    monkeypatch.delenv(KEY, raising=False)
    monkeypatch.setenv("BLACKDUCK_URL", "https://blackduck.example.invalid")
    monkeypatch.setenv("BLACKDUCK_API_TOKEN", "synthetic-scanner-token")
    result = setup.desired_blackduck_variables({
        "provision_blackduck_variables": True,
    })
    assert set(result) == {KEY, "BLACKDUCK_URL", "BLACKDUCK_API_TOKEN"}


def test_dry_run_performs_no_mutations(tmp_path):
    client = Client()
    wanted = desired()
    loaded = plan(tmp_path, client, wanted)

    code, result, _ = execute(tmp_path, loaded, client, wanted, "dry-run")
    assert code == 0
    assert result["estimated_writes"] == 2
    assert result["writes"] == 0
    assert client.writes == 0


def test_apply_provisions_and_reads_back(tmp_path):
    client = Client()
    wanted = desired()
    loaded = plan(tmp_path, client, wanted)

    code, result, _ = execute(tmp_path, loaded, client, wanted, "apply")
    assert code == 0
    assert result["status"] == "ok"
    assert result["writes"] == 2
    assert client.protected is True
    assert client.variables[KEY] == wanted[KEY]
    assert result["after"]["variables"][0]["value_matches"] is True


def test_second_setup_requires_zero_writes(tmp_path):
    client = Client()
    wanted = desired()
    loaded = plan(tmp_path, client, wanted)
    execute(tmp_path, loaded, client, wanted, "apply")
    writes_before = client.writes

    second = plan(tmp_path, client, wanted)
    assert second.plan["actions"] == []
    code, result, _ = execute(tmp_path, second, client, wanted, "apply")
    assert code == 0
    assert result["writes"] == 0
    assert client.writes == writes_before


def test_token_rotation_updates_existing_variable(tmp_path):
    client = Client()
    wanted = desired()
    execute(
        tmp_path,
        plan(tmp_path, client, wanted),
        client,
        wanted,
        "apply",
    )

    rotated = desired("synthetic-rotated-token")
    loaded = plan(tmp_path, client, rotated)
    assert len(loaded.plan["actions"]) == 1
    assert loaded.plan["actions"][0]["kind"] == "gitlab.variable.update"

    code, result, _ = execute(tmp_path, loaded, client, rotated, "apply")
    assert code == 0
    assert result["writes"] == 1
    assert client.variables[KEY]["value"] == "synthetic-rotated-token"


def test_plaintext_tokens_are_not_written_to_artifacts(tmp_path):
    client = Client()
    wanted = desired()
    loaded = plan(tmp_path, client, wanted)
    execute(tmp_path, loaded, client, wanted, "apply")

    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert TOKEN.encode("utf-8") not in path.read_bytes()


def test_zero_budget_blocks_variable_creation(tmp_path):
    client = Client()
    wanted = desired()
    loaded = plan(tmp_path, client, wanted)
    code, result, _ = variables.execute_variables_plan(
        loaded,
        client,
        desired_variables=wanted,
        mode="apply",
        result_root=tmp_path / "results",
        maximum_writes=0,
        confirm_apply=True,
        expected_plan_digest=loaded.digest,
    )
    assert code == 1
    assert result["outcome"] == "budget-exhausted"
    assert client.writes == 0
