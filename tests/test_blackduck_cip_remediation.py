from __future__ import annotations

from typing import Any

from wintermute.blackduck.actions.models import (
    ActionEvidence,
    ActionOwnership,
    ActionTarget,
    BlackDuckAction,
    stable_digest,
)
from wintermute.blackduck.actions.remediation import (
    VulnerabilityRemediationHandler,
)
from wintermute.blackduck.jobs.cip.security_data import (
    branch_candidates,
    parse_fixed_by,
)


BASE_URL = "https://blackduck.example.invalid"


class Client:
    def __init__(self) -> None:
        self.state = {
            "remediationStatus": "NEW",
            "comment": "",
        }
        self.requests: list[
            tuple[str, str, dict[str, Any]]
        ] = []

    def get(
        self,
        url: str,
    ) -> dict[str, Any]:
        del url
        return dict(self.state)

    def request(
        self,
        method: str,
        url: str,
        *,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        self.requests.append(
            (
                method,
                url,
                dict(body),
            )
        )
        self.state = dict(body)
        return {}


def action() -> BlackDuckAction:
    evidence = {
        "tag": "v6.1.173-cip56",
    }

    return BlackDuckAction.build(
        kind="vulnerability-remediation.set",
        target=ActionTarget(
            resource_type=(
                "vulnerability-remediation"
            ),
            resource_href=(
                f"{BASE_URL}/api/projects/p/"
                "versions/v/components/c/"
                "versions/cv/vulnerabilities/"
                "CVE-2026-0001/remediation"
            ),
            project_version_href=(
                f"{BASE_URL}/api/projects/p/"
                "versions/v"
            ),
            identifiers={
                "vulnerability": (
                    "CVE-2026-0001"
                ),
            },
        ),
        observed={
            "remediation_status": "NEW",
            "comment": "",
            "owner": "",
        },
        desired={
            "remediation_status": "PATCHED",
            "preserve_existing_decisions": True,
            "comment": "Fix commit is present.",
        },
        ownership=ActionOwnership(
            producer="cip-remediation",
            marker="wintermute:cip:v1",
        ),
        evidence=ActionEvidence(
            provider="cip-kernel-sec",
            subject="CVE-2026-0001",
            revision="a" * 40,
            digest=stable_digest(evidence),
            details=evidence,
        ),
        reason="Fix is present",
    )


def test_handler_updates_remediation() -> None:
    client = Client()
    handler = VulnerabilityRemediationHandler(
        client,
        client,
    )
    current = handler.read_state(action())

    assert handler.conflict_reason(
        action(),
        current,
    ) == ""

    handler.apply(action(), current)

    assert len(client.requests) == 1
    assert (
        client.requests[0][2][
            "remediationStatus"
        ]
        == "PATCHED"
    )
    assert (
        "wintermute:cip:v1"
        in client.requests[0][2]["comment"]
    )


def test_handler_preserves_user_decision() -> None:
    client = Client()
    client.state = {
        "remediationStatus": "IGNORED",
        "comment": "Reviewed by analyst",
    }
    handler = VulnerabilityRemediationHandler(
        client,
        client,
    )
    current = handler.read_state(action())

    assert handler.conflict_reason(
        action(),
        current,
    )


def test_parse_fixed_by() -> None:
    first = "a" * 40
    second = "b" * 40
    payload = f"""
description: example
fixed-by:
  mainline: [{first}]
  cip/6.1:
    - {second}
references:
  - https://example.invalid
"""

    assert parse_fixed_by(payload) == {
        "mainline": (first,),
        "cip/6.1": (second,),
    }


def test_branch_candidates() -> None:
    assert branch_candidates(
        "linux-6.1.y-cip"
    ) == (
        "linux-6.1.y-cip",
        "cip/6.1",
        "stable/6.1",
        "6.1",
        "mainline",
    )
