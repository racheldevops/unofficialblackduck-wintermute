from __future__ import annotations

import argparse

import pytest

from wintermute.ai.models import stable_digest
from wintermute.scm.onboarding import setup


def test_parser_accepts_insecure():
    args = setup.parse_args([
        "--config", "example.json", "--dry-run", "--insecure",
    ])
    assert args.insecure is True
    assert args.ca_bundle is None


def test_parser_accepts_ca_bundle():
    args = setup.parse_args([
        "--config", "example.json", "--dry-run",
        "--ca-bundle", "customer-ca.pem",
    ])
    assert args.ca_bundle == "customer-ca.pem"
    assert args.insecure is None


def test_parser_rejects_conflicting_tls_flags():
    with pytest.raises(SystemExit) as error:
        setup.parse_args([
            "--config", "example.json", "--insecure",
            "--ca-bundle", "customer-ca.pem",
        ])
    assert error.value.code == 2


def test_no_flags_preserve_configuration():
    configuration = {
        "tls": {"insecure": True, "ca_bundle": ""},
    }
    result = setup.apply_tls_overrides(
        configuration,
        argparse.Namespace(),
    )
    assert result == configuration
    assert result is not configuration


def test_insecure_clears_configured_ca_without_mutating_input():
    configuration = {
        "tls": {"insecure": False, "ca_bundle": "old-ca.pem"},
    }
    result = setup.apply_tls_overrides(
        configuration,
        argparse.Namespace(insecure=True, ca_bundle=None),
    )
    assert result["tls"] == {"insecure": True, "ca_bundle": ""}
    assert configuration["tls"]["ca_bundle"] == "old-ca.pem"
    assert stable_digest(result) != stable_digest(configuration)


def test_ca_override_enables_verification(tmp_path):
    ca = tmp_path / "customer-ca.pem"
    result = setup.apply_tls_overrides(
        {"tls": {"insecure": True, "ca_bundle": ""}},
        argparse.Namespace(insecure=None, ca_bundle=str(ca)),
    )
    assert result["tls"] == {
        "insecure": False,
        "ca_bundle": str(ca.resolve()),
    }


def test_empty_ca_override_is_rejected():
    with pytest.raises(setup.SetupError, match="must not be empty"):
        setup.apply_tls_overrides(
            {},
            argparse.Namespace(insecure=None, ca_bundle=""),
        )


def test_identical_effective_settings_keep_digest():
    configuration = {"tls": {"insecure": True, "ca_bundle": ""}}
    result = setup.apply_tls_overrides(
        configuration,
        argparse.Namespace(insecure=True, ca_bundle=None),
    )
    assert stable_digest(result) == stable_digest(configuration)
