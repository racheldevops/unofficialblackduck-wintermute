from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from wintermute.ai.config import AISettings
from wintermute.ai.provider import (
    OpenAICompatibleProvider,
)
from wintermute.ai.retrieval import (
    EvidenceCatalog,
)
from wintermute.ai.safety import (
    Anonymizer,
    Sanitizer,
)
from wintermute.ai.scan_profile import (
    validate_scan_profile,
)


def catalog(
    tmp_path: Path,
) -> EvidenceCatalog:
    source = tmp_path / "source"
    source.mkdir()
    (
        source / "pyproject.toml"
    ).write_text(
        "[project]\nname='example'\n",
        encoding="utf-8",
    )

    return EvidenceCatalog.build(
        source,
        Sanitizer(
            Anonymizer("key")
        ),
        max_catalog_files=10,
        max_file_bytes=10000,
    )


def test_model_response_is_normalized(
    tmp_path: Path,
) -> None:
    selected = catalog(tmp_path)
    evidence_id = (
        selected.records[0]
        .descriptor.evidence_id
    )
    profile = validate_scan_profile(
        {
            "languages": [
                "Python",
                {
                    "name": "Shell"
                },
            ],
            "build_systems": [
                "pip",
                "Docker",
                "unusual-builder",
            ],
            "package_managers": {
                "values": [
                    "pip",
                    "setuptools",
                ]
            },
            "layout": "single_project",
            "scan_mode": "detect",
            "central_template": "pip",
            "parameters": {
                "build_less": "true",
                "detectorSearchDepth": "3",
                "unsupported": [
                    "ignored"
                ],
            },
            "confidence": "90",
            "evidence_ids": evidence_id,
            "conflicts": {
                "items": [
                    "one conflict"
                ]
            },
            "unresolved_questions": "",
        },
        selected,
    )

    assert profile["languages"] == [
        "python",
        "shell",
    ]
    assert profile["layout"] == (
        "single-project"
    )
    assert profile["scan_mode"] == (
        "detector"
    )
    assert profile["central_template"] == (
        "python"
    )
    assert profile["confidence"] == 0.9
    assert profile["parameters"] == {
        "buildless": True,
        "detector_search_depth": 3,
    }
    assert "generic" in (
        profile["build_systems"]
    )
    assert profile["conflicts"]


class Response:
    status = 200
    headers: dict[str, str] = {}

    def __init__(
        self,
        content: str | None,
        *,
        finish_reason: str,
    ) -> None:
        self.content = content
        self.finish_reason = finish_reason

    def __enter__(self):
        return self

    def __exit__(
        self,
        exception_type: Any,
        exception: Any,
        traceback: Any,
    ) -> None:
        del exception_type
        del exception
        del traceback

    def read(
        self,
        limit: int = -1,
    ) -> bytes:
        del limit

        return json.dumps(
            {
                "id": "response",
                "choices": [
                    {
                        "message": {
                            "content": (
                                self.content
                            )
                        },
                        "finish_reason": (
                            self.finish_reason
                        ),
                    }
                ],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 20,
                    "completion_tokens_details": {
                        "reasoning_tokens": 15
                    },
                },
            }
        ).encode("utf-8")


def test_empty_reasoning_response_is_retried(
    monkeypatch,
) -> None:
    responses = [
        Response(
            None,
            finish_reason="length",
        ),
        Response(
            '{"status":"complete"}',
            finish_reason="stop",
        ),
    ]
    calls = 0

    def fake_urlopen(
        request,
        **kwargs,
    ):
        del request
        del kwargs
        nonlocal calls
        calls += 1
        return responses.pop(0)

    monkeypatch.setattr(
        (
            "wintermute.ai.provider."
            "urlopen"
        ),
        fake_urlopen,
    )
    settings = AISettings(
        provider="vllm",
        model="blackduck-gpt-5.5",
        endpoint=(
            "http://127.0.0.1:4000/v1"
        ),
        retries=1,
        retry_delay_seconds=0,
        request_interval_seconds=0.01,
    )
    provider = OpenAICompatibleProvider(
        settings,
        sleeper=lambda _: None,
    )
    response = provider.complete(
        [
            {
                "role": "user",
                "content": "{}",
            }
        ]
    )

    assert calls == 2
    assert response.content == (
        '{"status":"complete"}'
    )
    assert response.usage.input_tokens == 20
    assert response.usage.output_tokens == 40
    assert response.usage.reasoning_tokens == 30
