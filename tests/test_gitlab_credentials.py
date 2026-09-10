from __future__ import annotations

import pytest

from wintermute.scm.onboarding.credentials import gitlab_action_token


def test_action_token_takes_precedence():
    assert gitlab_action_token({
        "GITLAB_ACTION_TOKEN": "explicit-action-token",
        "GITLAB_TOKEN": "general-token",
    }) == "explicit-action-token"


def test_general_token_is_used_when_action_token_is_absent():
    assert gitlab_action_token({
        "GITLAB_TOKEN": "general-token",
    }) == "general-token"


@pytest.mark.parametrize("action_token", ["", "   "])
def test_empty_action_token_uses_general_token(action_token):
    assert gitlab_action_token({
        "GITLAB_ACTION_TOKEN": action_token,
        "GITLAB_TOKEN": "general-token",
    }) == "general-token"


def test_selection_does_not_modify_environment():
    environment = {"GITLAB_TOKEN": "general-token"}
    before = dict(environment)
    assert gitlab_action_token(environment) == "general-token"
    assert environment == before


def test_missing_credentials_report_both_supported_variables():
    with pytest.raises(
        RuntimeError,
        match="GITLAB_ACTION_TOKEN or GITLAB_TOKEN",
    ):
        gitlab_action_token({})


@pytest.mark.parametrize("name", ["GITLAB_ACTION_TOKEN", "GITLAB_TOKEN"])
@pytest.mark.parametrize("invalid", ["bad\ntoken", "bad\rtoken"])
def test_line_breaks_are_rejected_without_exposing_token(name, invalid):
    with pytest.raises(ValueError) as error:
        gitlab_action_token({name: invalid})
    assert invalid not in str(error.value)
    assert name in str(error.value)


def test_invalid_explicit_token_does_not_silently_fall_back():
    with pytest.raises(ValueError, match="GITLAB_ACTION_TOKEN"):
        gitlab_action_token({
            "GITLAB_ACTION_TOKEN": "invalid\ntoken",
            "GITLAB_TOKEN": "general-token",
        })
