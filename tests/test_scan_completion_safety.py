from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.request import Request

import pytest

from wintermute.scan.security import (
    RejectRedirects,
    bridge_checksums,
    redact_payload,
    resolve_bridge_checksum,
)
from wintermute.scm.onboarding import cli, setup
from wintermute.scm.onboarding.central_bundle import (
    CentralBundleConfiguration,
    render_gitlab_launcher,
)
from wintermute.scm.onboarding.central_upgrade import (
    read_remote_file,
)
from wintermute.scan.trigger import (
    LauncherTriggerError,
    run as trigger_run,
)


def test_action_token_falls_back_without_changing_environment(monkeypatch):
    import os

    monkeypatch.setenv("GITLAB_TOKEN", "synthetic-general-token")
    monkeypatch.delenv("GITLAB_ACTION_TOKEN", raising=False)

    cli.configure_gitlab_token()

    assert setup.action_token() == "synthetic-general-token"
    assert "GITLAB_ACTION_TOKEN" not in os.environ



def test_explicit_action_token_is_used(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "synthetic-read-token")
    monkeypatch.setenv("GITLAB_ACTION_TOKEN", "synthetic-action-token")
    assert setup.action_token() == "synthetic-action-token"


def test_blackduck_provisioning_is_opt_in(monkeypatch):
    monkeypatch.delenv("BLACKDUCK_URL", raising=False)
    monkeypatch.delenv("BLACKDUCK_API_TOKEN", raising=False)
    monkeypatch.delenv("WINTERMUTE_GITLAB_READ_TOKEN", raising=False)
    monkeypatch.setenv("GITLAB_TOKEN", "synthetic-general-token")

    for configuration in ({}, {"provision_blackduck_variables": False}):
        desired = setup.desired_blackduck_variables(configuration)
        assert set(desired) == {"WINTERMUTE_GITLAB_READ_TOKEN"}
        assert desired["WINTERMUTE_GITLAB_READ_TOKEN"]["value"] == (
            "synthetic-general-token"
        )


@pytest.mark.parametrize("value", ["false", 0, None])
def test_blackduck_provisioning_requires_boolean(value):
    with pytest.raises(setup.SetupError, match="must be boolean"):
        setup.desired_blackduck_variables({
            "provision_blackduck_variables": value,
        })


def test_blackduck_provisioning_requires_credentials_when_enabled(monkeypatch):
    monkeypatch.delenv("BLACKDUCK_URL", raising=False)
    monkeypatch.delenv("BLACKDUCK_API_TOKEN", raising=False)
    monkeypatch.delenv("WINTERMUTE_GITLAB_READ_TOKEN", raising=False)
    monkeypatch.setenv("GITLAB_TOKEN", "synthetic-general-token")

    with pytest.raises(RuntimeError, match="BLACKDUCK"):
        setup.desired_blackduck_variables({
            "provision_blackduck_variables": True,
        })


def test_setup_does_not_publish_missing_image(tmp_path, monkeypatch):
    calls = []

    def inspect(*args, **kwargs):
        raise RuntimeError("image unavailable")

    def publish(*args, **kwargs):
        calls.append("publish")
        raise AssertionError("Image publication must not occur")

    monkeypatch.setattr(setup, "inspect_image", inspect)
    monkeypatch.setattr(setup, "publish_scan_image", publish)

    with pytest.raises(setup.SetupError, match="never publishes"):
        setup.resolve_scan_image(
            tmp_path,
            {
                "scan_image": {
                    "digest_reference": (
                        "registry.example.invalid/scan@sha256:" + "a" * 64
                    ),
                    "publish_if_missing": True,
                },
            },
            work_directory=tmp_path,
        )
    assert calls == []


def test_setup_uses_checksums_for_both_architectures(tmp_path, monkeypatch):
    checksums = {
        "linux/amd64": "a" * 64,
        "linux/arm64": "b" * 64,
    }
    monkeypatch.setattr(
        setup,
        "inspect_image",
        lambda *a, **k: {"platforms": sorted(checksums)},
    )
    monkeypatch.setattr(setup, "launcher_available", lambda *a, **k: True)
    monkeypatch.setattr(
        setup,
        "inspect_bridge_platforms",
        lambda *a, **k: checksums,
    )
    _, _, bridge, published = setup.resolve_scan_image(
        tmp_path,
        {
            "scan_image": {
                "digest_reference": (
                    "registry.example.invalid/scan@sha256:" + "c" * 64
                ),
            },
        },
        work_directory=tmp_path,
    )
    assert json.loads(bridge["bridge_sha256"]) == checksums
    assert published is False


def test_checksum_selection_is_architecture_specific():
    value = json.dumps({
        "linux/amd64": "a" * 64,
        "linux/arm64": "b" * 64,
    })
    assert resolve_bridge_checksum(value, machine="x86_64") == "a" * 64
    assert resolve_bridge_checksum(value, machine="aarch64") == "b" * 64
    assert resolve_bridge_checksum("c" * 64) == "c" * 64


def test_checksum_map_rejects_missing_architecture():
    with pytest.raises(ValueError, match="linux/amd64 and linux/arm64"):
        bridge_checksums(json.dumps({"linux/amd64": "a" * 64}))


def test_checksum_map_rejects_duplicate_platform():
    value = (
        '{"linux/amd64":"' + "a" * 64
        + '","linux/amd64":"' + "b" * 64
        + '","linux/arm64":"' + "c" * 64 + '"}'
    )
    with pytest.raises(ValueError, match="Duplicate"):
        bridge_checksums(value)


def test_renderer_quotes_checksum_map():
    checksums = json.dumps({
        "linux/amd64": "a" * 64,
        "linux/arm64": "b" * 64,
    }, sort_keys=True, separators=(",", ":"))
    configuration = CentralBundleConfiguration(
        image="registry.example.invalid/scan@sha256:" + "c" * 64,
        bridge_sha256=checksums,
        gitlab_project="example/security-scans",
    )
    configuration.validate()
    rendered = render_gitlab_launcher(configuration, "d" * 64)
    assert "--expected-bridge-sha256 '" + checksums + "'" in rendered
    assert 'WINTERMUTE_SCAN_MODE: "dry-run"' in rendered


def test_authenticated_redirects_fail_closed():
    request = Request("https://gitlab.example.invalid/api/v4/projects/42")
    with pytest.raises(RuntimeError, match="before forwarding"):
        RejectRedirects().redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://other.example.invalid",
        )


def test_file_metadata_content_avoids_second_request():
    content = b"managed configuration\n"
    calls = []

    class Client:
        def get_json(self, path, **kwargs):
            calls.append(("GET", path))
            return SimpleNamespace(
                status_code=200,
                payload={
                    "file_path": "registry/scan-registry.json",
                    "last_commit_id": "a" * 40,
                    "encoding": "base64",
                    "content": base64.b64encode(content).decode("ascii"),
                    "content_sha256": hashlib.sha256(content).hexdigest(),
                },
            )

        def get_bytes(self, *args, **kwargs):
            raise AssertionError("Redundant raw-content request")

    result = read_remote_file(
        Client(),
        "example/security-scans",
        "registry/scan-registry.json",
        "main",
        allow_missing=False,
    )
    assert result.content == content
    assert len(calls) == 1


def test_setup_receipts_redact_before_writing(tmp_path, monkeypatch):
    monkeypatch.setenv("GITLAB_ACTION_TOKEN", "synthetic-action-secret")
    directory = setup.write_setup_receipt(
        tmp_path,
        "test-setup",
        {
            "error": "Request failed synthetic-action-secret",
            "phases": [{"error": "synthetic-action-secret"}],
        },
    )
    text = (directory / "setup.json").read_text(encoding="utf-8")
    assert "synthetic-action-secret" not in text
    assert "[REDACTED]" in text


def test_payload_redaction_preserves_numeric_values(monkeypatch):
    monkeypatch.setenv("BLACKDUCK_API_TOKEN", "synthetic-blackduck-secret")
    value = redact_payload({
        "writes": 0,
        "verified": True,
        "nested": ["synthetic-blackduck-secret"],
    })
    assert value == {
        "writes": 0,
        "verified": True,
        "nested": ["[REDACTED]"],
    }


def test_trigger_requires_confirmation_before_other_work():
    with pytest.raises(LauncherTriggerError, match="confirm-trigger"):
        trigger_run(SimpleNamespace(confirm_trigger=False))


def template_plan(policy="required", repository_id="42"):
    return SimpleNamespace(assignments={
        "assignments": [{
            "provider": "gitlab",
            "provider_instance": "gitlab.example.invalid",
            "repository_id": repository_id,
            "name_with_owner": "example/application",
            "onboarding_policy": policy,
            "scan_contract_id": "scan-example",
        }],
    })


def test_setup_rejects_unapproved_target():
    with pytest.raises(setup.SetupError, match="approved"):
        setup.verify_approved_targets(
            template_plan("review"),
            gitlab={"rest_url": "https://gitlab.example.invalid/api/v4"},
            targets=("example/application",),
        )


def test_setup_rejects_changed_project_identity():
    with pytest.raises(setup.SetupError, match="identity differs"):
        setup.verify_approved_targets(
            template_plan(),
            gitlab={"rest_url": "https://gitlab.example.invalid/api/v4"},
            targets=("example/application",),
            access_plan={
                "observation": {
                    "targets": [{
                        "target_project": "example/application",
                        "target_project_id": 99,
                    }],
                },
            },
        )


def test_setup_accepts_exact_approved_project_identity():
    setup.verify_approved_targets(
        template_plan(),
        gitlab={"rest_url": "https://gitlab.example.invalid/api/v4"},
        targets=("example/application",),
        access_plan={
            "observation": {
                "targets": [{
                    "target_project": "example/application",
                    "target_project_id": 42,
                }],
            },
        },
    )
