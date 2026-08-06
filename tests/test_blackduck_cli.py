from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import pytest

from wintermute.blackduck import cli


VERSION_HREF = (
    "https://bd.example/api/projects/service/"
    "versions/1"
)


class Client:
    base_url = "https://bd.example"

    def __init__(
        self,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        del args, kwargs
        self.bearer_token = None

    def authenticate(self) -> None:
        self.bearer_token = "bearer"

    def clone_for_worker(self) -> Client:
        return self

    def get(self, href: str) -> dict[str, Any]:
        return {
            "versionName": "1",
            "_meta": {"href": href},
        }

    def paged_get(
        self,
        href: str,
    ) -> list[dict[str, Any]]:
        if href.endswith(
            "/vulnerable-bom-components"
        ):
            return [
                {
                    "componentName": "openssl",
                    "componentVersionName": "3.0.1",
                    "_meta": {
                        "links": [
                            {
                                "rel": "vulnerabilities",
                                "href": (
                                    "https://bd.example/"
                                    "vulnerabilities"
                                ),
                            }
                        ]
                    },
                }
            ]

        if href.endswith("/vulnerabilities"):
            return [
                {
                    "vulnerabilityName": (
                        "CVE-2026-0001"
                    ),
                    "overallScore": 9.8,
                    "severity": "CRITICAL",
                }
            ]

        return []


def test_loads_csv_and_json_input(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "input.csv"

    with csv_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as output_file:
        writer = csv.DictWriter(
            output_file,
            fieldnames=[
                "project",
                "project_version",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "project": "Service",
                "project_version": "1",
            }
        )

    json_path = tmp_path / "input.json"
    json_path.write_text(
        json.dumps(
            [
                {
                    "project": "Service",
                    "project_version": "1",
                }
            ]
        ),
        encoding="utf-8",
    )

    assert cli.load_input_rows(
        str(csv_path)
    ) == [
        {
            "project": "Service",
            "project_version": "1",
        }
    ]
    assert cli.load_input_rows(
        str(json_path)
    ) == [
        {
            "project": "Service",
            "project_version": "1",
        }
    ]


def test_candidate_scope_requires_input() -> None:
    args = cli.parse_args(
        [
            "--scope",
            "candidate-projects",
            "--bd-url",
            "https://bd.example",
            "--api-token",
            "token",
        ]
    )

    with pytest.raises(
        RuntimeError,
        match="--input is required",
    ):
        cli.validate_args(args)


def test_general_cli_collects_explicit_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli,
        "BlackDuckClient",
        Client,
    )
    input_path = tmp_path / "targets.json"
    output_path = tmp_path / "findings.json"
    manifest_path = tmp_path / "manifest.json"
    failures_path = tmp_path / "failures.json"

    input_path.write_text(
        json.dumps(
            [
                {
                    "project": "Service",
                    "project_version": "1",
                    "project_version_href": (
                        VERSION_HREF
                    ),
                }
            ]
        ),
        encoding="utf-8",
    )
    args = cli.parse_args(
        [
            "--scope",
            "explicit-project-versions",
            "--input",
            str(input_path),
            "--out",
            str(output_path),
            "--manifest-out",
            str(manifest_path),
            "--failures-out",
            str(failures_path),
            "--bd-url",
            "https://bd.example",
            "--api-token",
            "token",
            "--no-api-cache",
        ]
    )

    assert cli.run(args) == 0

    payload = json.loads(
        output_path.read_text(
            encoding="utf-8"
        )
    )
    manifest = json.loads(
        manifest_path.read_text(
            encoding="utf-8"
        )
    )

    assert payload["scope"] == (
        "explicit-project-versions"
    )
    assert payload["target_count"] == 1
    assert payload["finding_count"] == 1
    assert payload["failure_count"] == 0
    assert payload["findings"][0][
        "vulnerability"
    ] == "CVE-2026-0001"
    assert manifest["target_count"] == 1
