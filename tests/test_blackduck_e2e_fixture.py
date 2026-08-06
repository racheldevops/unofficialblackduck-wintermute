from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest

from wintermute.blackduck import client as client_module
from wintermute.blackduck.client import BlackDuckClient
from wintermute.blackduck.criteria import (
    jira_parent_rollup_criteria,
)
from wintermute.blackduck.projections import (
    datadog_finding_rows,
    jira_parent_rollup_rows,
)
from wintermute.blackduck.pull import (
    PullRequest,
    pull_scope,
)
from wintermute.blackduck.scopes import (
    CollectionScope,
)


FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "blackduck"
    / "parent-rollup-e2e.json"
)


class Response:
    status = 200

    def __init__(self, payload: Any) -> None:
        self.payload = payload

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(
            self.payload
        ).encode("utf-8")


def test_sanitized_blackduck_fixture_runs_full_shared_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = json.loads(
        FIXTURE.read_text(encoding="utf-8")
    )
    responses = fixture["responses"]
    calls: list[str] = []
    authorization_headers: list[str] = []

    def fake_urlopen(
        request: Any,
        timeout: int,
        context: Any,
    ) -> Response:
        del timeout, context
        parsed = urlparse(request.full_url)
        key = (
            f"{request.get_method()} "
            f"{parsed.path}"
        )
        calls.append(key)
        authorization = request.get_header(
            "Authorization"
        )

        if authorization:
            authorization_headers.append(
                authorization
            )

        if key not in responses:
            raise AssertionError(
                f"Unexpected fixture request: {key}"
            )

        return Response(responses[key])

    monkeypatch.setattr(
        client_module,
        "urlopen",
        fake_urlopen,
    )

    client = BlackDuckClient(
        base_url=fixture["base_url"],
        api_token="x",
        retries=0,
        page_limit=100,
    )
    client.authenticate()

    execution = pull_scope(
        client,
        PullRequest(
            scope=CollectionScope.PARENT_ROLLUP,
            criteria=jira_parent_rollup_criteria(),
            workers=2,
            component_workers=2,
            resolve_bom_names=True,
        ),
        rows=[],
        generated_at="2026-08-06T00:00:00Z",
    )
    findings = execution.collection.findings
    jira_rows = jira_parent_rollup_rows(
        findings
    )
    datadog_rows = datadog_finding_rows(
        findings
    )
    expected = fixture["expected"]

    assert execution.target_count == expected[
        "targets"
    ]
    assert (
        execution.manifest.lineage_context_count
        == expected["relationships"]
    )
    assert execution.finding_count == expected[
        "findings"
    ]
    assert len(jira_rows) == expected[
        "jira_rows"
    ]
    assert len(datadog_rows) == expected[
        "datadog_rows"
    ]
    assert jira_rows[0]["parent_project"] == (
        expected["parent_project"]
    )
    assert jira_rows[0]["subproject"] == (
        expected["affected_project"]
    )
    assert jira_rows[0]["component"] == expected[
        "component"
    ]
    assert jira_rows[0]["vulnerability"] == (
        expected["vulnerability"]
    )
    assert datadog_rows[0]["project"] == (
        expected["affected_project"]
    )
    assert datadog_rows[0]["vulnerability"] == (
        expected["vulnerability"]
    )
    assert execution.failure_count == 0
    assert "token x" in (
        authorization_headers
    )
    assert "Bearer x" in (
        authorization_headers
    )
    assert set(calls) == set(responses)
