from __future__ import annotations

import hashlib
import json
from pathlib import Path

from wintermute.scm.onboarding.artifacts import (
    write_execution_result,
)


def test_execution_result_references_bytes(
    tmp_path: Path,
) -> None:
    policy = (
        b"pipeline_execution_policy:\n"
        b"  - enabled: false\n"
    )
    directory = write_execution_result(
        tmp_path / "results",
        {
            "execution_id": "execution-one",
            "status": "ok",
            "before": {
                "files": {
                    "policy.yml": policy,
                }
            },
        },
    )
    payload = json.loads(
        (
            directory
            / "result.json"
        ).read_text(
            encoding="utf-8"
        )
    )
    reference = payload["before"][
        "files"
    ]["policy.yml"]

    assert reference == {
        "representation": (
            "sha256-reference"
        ),
        "sha256": hashlib.sha256(
            policy
        ).hexdigest(),
        "size": len(policy),
    }
    assert (
        directory / "READY"
    ).is_file()


def test_execution_result_handles_nested_bytes(
    tmp_path: Path,
) -> None:
    directory = write_execution_result(
        tmp_path / "results",
        {
            "execution_id": "execution-two",
            "items": [
                {
                    "content": bytearray(
                        b"example"
                    )
                }
            ],
        },
    )
    payload = json.loads(
        (
            directory
            / "result.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    assert payload["items"][0][
        "content"
    ]["size"] == 7
