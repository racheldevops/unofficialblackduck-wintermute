from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from wintermute.scan.contracts import (
    load_registry,
    resolve_scan,
)
from wintermute.scan.engine import (
    planned_commands,
)


def registry(
    tmp_path: Path,
) -> tuple[Path, str]:
    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "contracts": [
                    {
                        "scan_contract_id": (
                            "scan-python"
                        ),
                        "contract": {
                            "schema_version": 1,
                            "template_id": (
                                "python-security-scan"
                            ),
                            "template_version": 1,
                            "engine": "bridge",
                            "products": [
                                "blackduck-sca"
                            ],
                            "scan_mode": (
                                "detector"
                            ),
                            "resource_class": (
                                "medium"
                            ),
                            "timeout_seconds": 3600,
                            "runtime_parameters": {
                                "binary_scan": False,
                                "buildless": True,
                                "detector_search_depth": 3,
                                "project_name_strategy": (
                                    "provider-id"
                                ),
                            },
                        },
                    }
                ],
                "assignments": [
                    {
                        "provider": "github",
                        "provider_instance": (
                            "api.github.com"
                        ),
                        "repository_id": "101",
                        "scan_contract_id": (
                            "scan-python"
                        ),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    digest = hashlib.sha256(
        path.read_bytes()
    ).hexdigest()

    return path, digest


def test_registry_resolves_public_github(
    tmp_path: Path,
) -> None:
    path, digest = registry(tmp_path)
    payload = load_registry(
        path,
        expected_sha256=digest,
    )
    resolved = resolve_scan(
        payload,
        provider="github",
        provider_instance=(
            "https://api.github.com"
        ),
        repository_id="101",
    )

    assert resolved.contract_id == (
        "scan-python"
    )
    assert resolved.contract[
        "engine"
    ] == "bridge"


def test_registry_rejects_other_repository(
    tmp_path: Path,
) -> None:
    path, digest = registry(tmp_path)
    payload = load_registry(
        path,
        expected_sha256=digest,
    )

    with pytest.raises(
        RuntimeError,
        match="no approved",
    ):
        resolve_scan(
            payload,
            provider="github",
            provider_instance=(
                "api.github.com"
            ),
            repository_id="999",
        )


def test_bridge_command_is_allowlisted(
    tmp_path: Path,
) -> None:
    path, digest = registry(tmp_path)
    payload = load_registry(
        path,
        expected_sha256=digest,
    )
    resolved = resolve_scan(
        payload,
        provider="github",
        provider_instance=(
            "api.github.com"
        ),
        repository_id="101",
    )

    assert planned_commands(
        Path("/opt/blackduck/bridge"),
        resolved,
    ) == [
        [
            "/opt/blackduck/bridge",
            "--stage",
            "blackducksca",
        ]
    ]
