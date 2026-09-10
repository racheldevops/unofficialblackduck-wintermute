from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from wintermute.scm.onboarding import configuration_paths, setup


def test_explicit_environment_path_takes_precedence(tmp_path):
    local = tmp_path / configuration_paths.LOCAL_CONFIGURATION_NAME
    local.write_text("{}", encoding="utf-8")
    configured = tmp_path / "selected.json"

    selected = configuration_paths.default_configuration_path(
        environment={"WINTERMUTE_ONBOARD_CONFIG": str(configured)},
        directory=tmp_path,
    )
    assert selected == str(configured)


def test_missing_environment_path_does_not_fall_back(tmp_path):
    local = tmp_path / configuration_paths.LOCAL_CONFIGURATION_NAME
    local.write_text("{}", encoding="utf-8")
    missing = tmp_path / "missing.json"

    assert configuration_paths.default_configuration_path(
        environment={"WINTERMUTE_ONBOARD_CONFIG": str(missing)},
        directory=tmp_path,
    ) == str(missing)


def test_local_configuration_is_discovered(tmp_path):
    local = tmp_path / configuration_paths.LOCAL_CONFIGURATION_NAME
    local.write_text("{}", encoding="utf-8")
    assert configuration_paths.default_configuration_path(
        environment={},
        directory=tmp_path,
    ) == str(local.resolve())


def test_example_is_not_automatically_selected(tmp_path):
    example = tmp_path / configuration_paths.EXAMPLE_CONFIGURATION_NAME
    example.write_text("{}", encoding="utf-8")
    assert configuration_paths.default_configuration_path(
        environment={},
        directory=tmp_path,
    ) is None


def test_parser_explicit_path_overrides_default(monkeypatch):
    monkeypatch.setattr(
        configuration_paths,
        "default_configuration_path",
        lambda: "default.local.json",
    )
    args = setup.parse_args(["--config", "explicit.json", "--dry-run"])
    assert args.config == "explicit.json"


def test_parser_uses_discovered_path(monkeypatch):
    monkeypatch.setattr(
        configuration_paths,
        "default_configuration_path",
        lambda: "default.local.json",
    )
    assert setup.parse_args(["--dry-run"]).config == "default.local.json"


def test_missing_configuration_has_actionable_error(monkeypatch, capsys):
    monkeypatch.setattr(
        configuration_paths,
        "default_configuration_path",
        lambda: None,
    )
    with pytest.raises(SystemExit) as error:
        setup.parse_args(["--dry-run"])
    assert error.value.code == 2
    assert "WINTERMUTE_ONBOARD_CONFIG" in capsys.readouterr().err


def test_help_works_without_configuration(monkeypatch):
    monkeypatch.setattr(
        configuration_paths,
        "default_configuration_path",
        lambda: None,
    )
    with pytest.raises(SystemExit) as error:
        setup.parse_args(["--help"])
    assert error.value.code == 0


def test_example_contains_no_mutation_or_publish_defaults():
    path = (
        configuration_paths.configuration_directory()
        / configuration_paths.EXAMPLE_CONFIGURATION_NAME
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["provision_blackduck_variables"] is False
    assert payload["tls"]["insecure"] is False
    assert "publish_if_missing" not in payload["scan_image"]
    assert payload["gitlab"]["url"] == "https://gitlab.example.invalid"


def test_private_configuration_is_excluded_from_package_data():
    root = Path(__file__).resolve().parents[1]
    payload = tomllib.loads(
        (root / "pyproject.toml").read_text(encoding="utf-8")
    )
    setuptools = payload["tool"]["setuptools"]
    assert setuptools["package-data"]["wintermute.scm.onboarding"] == [
        "config/wintermute-onboard.example.json"
    ]
    assert "config/*.local.json" in setuptools["exclude-package-data"][
        "wintermute.scm.onboarding"
    ]


def test_private_configuration_has_git_and_docker_exclusions():
    root = Path(__file__).resolve().parents[1]
    git_rules = (root / ".gitignore").read_text(encoding="utf-8").splitlines()
    docker_rules = (root / ".dockerignore").read_text(
        encoding="utf-8"
    ).splitlines()
    assert (
        "/src/wintermute/scm/onboarding/config/*.local.json"
        in git_rules
    )
    assert (
        "src/wintermute/scm/onboarding/config/*.local.json"
        in docker_rules
    )
    assert "config" in docker_rules
