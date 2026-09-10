from __future__ import annotations

import json
from pathlib import Path

from wintermute.ai.config import (
    AISettings,
)
from wintermute.ai.gateway import (
    AIGateway,
)
from wintermute.ai.models import (
    ModelResponse,
    ModelUsage,
)
from wintermute.ai.retrieval import (
    EvidenceCatalog,
)
from wintermute.ai.safety import (
    Anonymizer,
    Sanitizer,
)
from wintermute.ai.storage import (
    AIResponseCache,
    AIUsageLedger,
    write_analysis,
)


class Provider:
    def __init__(self) -> None:
        self.calls = 0

    def complete(
        self,
        messages,
    ) -> ModelResponse:
        self.calls += 1
        payload = json.loads(
            messages[1]["content"]
        )
        evidence_ids = [
            value["evidence_id"]
            for value in payload[
                "selected_evidence"
            ]
        ]

        return ModelResponse(
            content=json.dumps(
                {
                    "status": "complete",
                    "profile": {
                        "languages": [
                            "python"
                        ],
                        "build_systems": [
                            "python"
                        ],
                        "package_managers": [
                            "pip"
                        ],
                        "layout": (
                            "single-project"
                        ),
                        "scan_mode": "detector",
                        "central_template": (
                            "python"
                        ),
                        "parameters": {
                            "buildless": True,
                            "detector_search_depth": 3,
                        },
                        "confidence": 0.9,
                        "evidence_ids": (
                            evidence_ids
                        ),
                        "conflicts": [],
                        "unresolved_questions": [],
                    },
                }
            ),
            usage=ModelUsage(
                input_tokens=100,
                output_tokens=50,
            ),
            request_id="test",
        )


def settings() -> AISettings:
    value = AISettings(
        provider="vllm",
        model="test-model",
        endpoint=(
            "http://127.0.0.1:8000/v1"
        ),
        request_interval_seconds=0.01,
    )
    value.validate()
    return value


def catalog(
    tmp_path: Path,
) -> EvidenceCatalog:
    source = tmp_path / "source"
    source.mkdir()
    (
        source / "pyproject.toml"
    ).write_text(
        """
[project]
name = "private-project"
dependencies = ["requests"]
""",
        encoding="utf-8",
    )
    (
        source / ".gitlab-ci.yml"
    ).write_text(
        """
build:
  script:
    - python -m pytest
TOKEN=must-not-leave
""",
        encoding="utf-8",
    )

    return EvidenceCatalog.build(
        source,
        Sanitizer(
            Anonymizer("test-key")
        ),
        max_catalog_files=20,
        max_file_bytes=10000,
    )


def test_sanitizer_redacts_secrets() -> None:
    sanitizer = Sanitizer(
        Anonymizer("key")
    )
    result = sanitizer.sanitize_text(
        "API_TOKEN=secret-value\n"
        "contact@example.invalid\n"
        "https://internal.example/path\n"
    )

    assert "secret-value" not in result
    assert "contact@example.invalid" not in result
    assert "internal.example" not in result


def test_scan_profile_gateway(
    tmp_path: Path,
) -> None:
    provider = Provider()
    response_cache = AIResponseCache(
        tmp_path / "responses.sqlite3"
    )
    ledger = AIUsageLedger(
        tmp_path / "usage.sqlite3"
    )
    gateway = AIGateway(
        settings(),
        provider,
        response_cache,
        ledger,
    )
    selected_catalog = catalog(tmp_path)
    result = gateway.scan_profile(
        selected_catalog,
        repository_alias="repository-test",
        tenant_alias="tenant-test",
    )

    assert (
        result.result["central_template"]
        == "python"
    )
    assert result.usage.input_tokens == 100
    assert provider.calls == 1

    directory = write_analysis(
        tmp_path / "analyses",
        result,
        evidence_catalog=(
            selected_catalog
            .private_descriptor_payload()
        ),
    )

    assert (
        directory / "analysis.json"
    ).is_file()
    assert (
        directory / "checksums.json"
    ).is_file()
    assert (
        directory / "READY"
    ).is_file()


def test_response_cache_avoids_second_call(
    tmp_path: Path,
) -> None:
    provider = Provider()
    response_cache = AIResponseCache(
        tmp_path / "responses.sqlite3"
    )
    ledger = AIUsageLedger(
        tmp_path / "usage.sqlite3"
    )
    gateway = AIGateway(
        settings(),
        provider,
        response_cache,
        ledger,
    )
    selected_catalog = catalog(tmp_path)

    gateway.scan_profile(
        selected_catalog,
        repository_alias="repository-test",
        tenant_alias="tenant-test",
    )
    gateway.scan_profile(
        selected_catalog,
        repository_alias="repository-test",
        tenant_alias="tenant-test",
    )

    assert provider.calls == 1
    assert (
        ledger.summary()[
            "cache_hit_count"
        ]
        == 1
    )
