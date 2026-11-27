from __future__ import annotations

import json
from typing import Any

from wintermute.ai.config import AISettings
from wintermute.ai.provider import (
    COMPATIBLE_TEMPERATURE,
    OpenAICompatibleProvider,
)


class Response:
    status = 200
    headers = {
        "x-request-id": "request-one",
    }

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
                "id": "request-one",
                "choices": [
                    {
                        "message": {
                            "content": (
                                '{"status":"complete"}'
                            )
                        }
                    }
                ],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 5,
                },
            }
        ).encode("utf-8")


def test_openai_compatible_temperature_is_one(
    monkeypatch,
) -> None:
    requests = []

    def fake_urlopen(
        request,
        **kwargs,
    ):
        del kwargs
        requests.append(request)
        return Response()

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
        request_interval_seconds=0.01,
    )
    provider = OpenAICompatibleProvider(
        settings
    )

    provider.complete(
        [
            {
                "role": "user",
                "content": "{}",
            }
        ]
    )
    payload = json.loads(
        requests[0].data.decode("utf-8")
    )

    assert COMPATIBLE_TEMPERATURE == 1
    assert payload["temperature"] == 1
