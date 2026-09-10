from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from wintermute.ai.models import stable_digest
from wintermute.scan import contracts


def registry():
    contract = {
        "schema_version": 1,
        "engine": "bridge",
        "products": ["blackduck-sca"],
        "scan_mode": "hybrid",
        "timeout_seconds": 3600,
        "runtime_parameters": {
            "binary_scan": False,
            "buildless": True,
            "detector_search_depth": 3,
            "project_name_strategy": "provider-id",
        },
    }
    contract["contract_digest"] = stable_digest(contract)
    return {
        "schema_version": 1,
        "contracts": [{
            "scan_contract_id": "scan-example",
            "contract": contract,
        }],
        "assignments": [{
            "provider": "gitlab",
            "provider_instance": "gitlab.example.invalid:8443",
            "repository_id": "42",
            "scan_contract_id": "scan-example",
        }],
    }


def write_registry(tmp_path: Path, payload):
    content = json.dumps(payload).encode("utf-8")
    path = tmp_path / "registry.json"
    path.write_bytes(content)
    return path, hashlib.sha256(content).hexdigest()


def test_registry_loads_verified_content(tmp_path):
    expected = registry()
    path, digest = write_registry(tmp_path, expected)
    assert contracts.load_registry(path, expected_sha256=digest) == expected


def test_registry_rejects_wrong_checksum(tmp_path):
    path, _ = write_registry(tmp_path, registry())
    with pytest.raises(contracts.ScanRegistryError, match="checksum mismatch"):
        contracts.load_registry(path, expected_sha256="0" * 64)


def test_registry_reads_and_verifies_the_same_bytes(tmp_path, monkeypatch):
    path, digest = write_registry(tmp_path, registry())

    def forbidden(*args, **kwargs):
        raise AssertionError("Registry must not be reopened as text")

    monkeypatch.setattr(Path, "read_text", forbidden)
    loaded = contracts.load_registry(path, expected_sha256=digest)
    assert loaded["schema_version"] == 1


def test_registry_size_is_bounded(tmp_path, monkeypatch):
    path, digest = write_registry(tmp_path, registry())
    monkeypatch.setattr(contracts, "MAX_REGISTRY_BYTES", 16)
    with pytest.raises(contracts.ScanRegistryError, match="size limit"):
        contracts.load_registry(path, expected_sha256=digest)


@pytest.mark.parametrize(
    "content",
    [
        b'{"schema_version":1,"schema_version":1}',
        b'{"schema_version":1,"extra":NaN}',
        b'{"schema_version":1,"extra":Infinity}',
        b'{"schema_version":1,"extra":-Infinity}',
    ],
)
def test_registry_rejects_ambiguous_json(tmp_path, content):
    path = tmp_path / "registry.json"
    path.write_bytes(content)
    with pytest.raises(contracts.ScanRegistryError):
        contracts.load_registry(
            path,
            expected_sha256=hashlib.sha256(content).hexdigest(),
        )


def test_contract_digest_is_verified(tmp_path):
    payload = registry()
    payload["contracts"][0]["contract"]["timeout_seconds"] = 7200
    path, digest = write_registry(tmp_path, payload)
    with pytest.raises(contracts.ScanRegistryError, match="contract digest"):
        contracts.load_registry(path, expected_sha256=digest)


def test_legacy_contract_without_embedded_digest_is_supported(tmp_path):
    payload = registry()
    payload["contracts"][0]["contract"].pop("contract_digest")
    path, digest = write_registry(tmp_path, payload)
    assert contracts.load_registry(path, expected_sha256=digest)


def test_provider_instance_preserves_port():
    assert contracts.normalized_instance(
        "https://gitlab.example.invalid:8443/api/v4"
    ) == "gitlab.example.invalid:8443"
    assert not contracts.instances_match(
        "gitlab",
        "gitlab.example.invalid:8443",
        "gitlab.example.invalid:9443",
    )


@pytest.mark.parametrize(
    "instance",
    [
        "https://user:password@gitlab.example.invalid",
        "http://gitlab.example.invalid",
        "https://gitlab.example.invalid/?token=x",
        "https://gitlab.example.invalid/#fragment",
        "https://gitlab.example.invalid/project/path",
        "gitlab.example.invalid:invalid",
        "gitlab example.invalid",
    ],
)
def test_invalid_instances_are_rejected(instance):
    with pytest.raises(contracts.ScanRegistryError):
        contracts.normalized_instance(instance)


def test_github_aliases_cannot_create_duplicate_assignments(tmp_path):
    payload = registry()
    payload["assignments"] = [
        {
            "provider": "github",
            "provider_instance": instance,
            "repository_id": "repository-node-id",
            "scan_contract_id": "scan-example",
        }
        for instance in ("api.github.com", "github.com")
    ]
    path, digest = write_registry(tmp_path, payload)
    with pytest.raises(contracts.ScanRegistryError, match="Duplicate"):
        contracts.load_registry(path, expected_sha256=digest)


def test_different_gitlab_ports_remain_distinct(tmp_path):
    payload = registry()
    second = copy.deepcopy(payload["assignments"][0])
    second["provider_instance"] = "gitlab.example.invalid:9443"
    payload["assignments"].append(second)
    path, digest = write_registry(tmp_path, payload)
    loaded = contracts.load_registry(path, expected_sha256=digest)
    resolved = contracts.resolve_scan(
        loaded,
        provider="gitlab",
        provider_instance="https://gitlab.example.invalid:9443/api/v4",
        repository_id="42",
    )
    assert resolved.provider_instance == "gitlab.example.invalid:9443"


def test_resolved_contract_does_not_share_mutable_parameters(tmp_path):
    payload = registry()
    path, digest = write_registry(tmp_path, payload)
    loaded = contracts.load_registry(path, expected_sha256=digest)
    resolved = contracts.resolve_scan(
        loaded,
        provider="gitlab",
        provider_instance="gitlab.example.invalid:8443",
        repository_id="42",
    )
    resolved.contract["runtime_parameters"]["buildless"] = False
    assert loaded["contracts"][0]["contract"]["runtime_parameters"]["buildless"] is True


@pytest.mark.parametrize("identifier", [True, 1.5, "0042", "0", "-1", "main"])
def test_gitlab_repository_ids_are_strict(identifier):
    with pytest.raises(contracts.ScanRegistryError):
        contracts.repository_identifier(identifier, "gitlab")


@pytest.mark.parametrize(
    "parameters",
    [
        {"buildless": "true"},
        {"binary_scan": 1},
        {"detector_search_depth": True},
        {"detector_search_depth": None},
        {"project_name_strategy": []},
        {"shell_command": "not-allowed"},
    ],
)
def test_runtime_parameters_are_validated(parameters):
    value = registry()["contracts"][0]["contract"]
    value.pop("contract_digest")
    value["runtime_parameters"] = parameters
    with pytest.raises(contracts.ScanRegistryError):
        contracts.validate_contract(value)
