from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from types import SimpleNamespace
from urllib.error import HTTPError

import pytest

from wintermute.jira import pipeline
from wintermute.jira import product_digest_recency as recency


NOW = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)


def finding(identifier):
    return SimpleNamespace(vulnerability=identifier)


def test_recency_flag_and_year_flag_parse_together(monkeypatch):
    monkeypatch.setattr(sys, "argv", [
        "blackduck-jira-pipeline",
        "--dry-run",
        "--first-detected-within-days", "14",
        "--vulnerability-year", "2025",
    ])
    args = pipeline.parse_args()
    assert args.first_detected_within_days == 14
    assert args.vulnerability_year == [2025]


@pytest.mark.parametrize("value", ["0", "-1", "3651", "1.5", "two"])
def test_invalid_recency_option_is_rejected(monkeypatch, capsys, value):
    monkeypatch.setattr(sys, "argv", [
        "blackduck-jira-pipeline",
        "--first-detected-within-days", value,
    ])
    assert pipeline.main() == pipeline.EXIT_ARGUMENT_ERROR
    assert "--first-detected-within-days" in capsys.readouterr().err


def test_recency_uses_digest_date_not_identifier_year(monkeypatch):
    monkeypatch.setattr(recency, "load_digest", lambda client: {
        "BDSA-2025-2867": "2026-10-27T12:00:00Z",
        "CVE-2026-0001": "2026-09-01T12:00:00Z",
        "CVE-2026-0002": "bad-date",
        "CVE-2026-0003": "2026-11-03T12:00:00Z",
    })
    items = [
        finding(identifier) for identifier in (
            "BDSA-2025-2867",
            "CVE-2026-0001",
            "CVE-2026-0002",
            "CVE-2026-0003",
            "CVE-2026-0004",
        )
    ]
    report = {}
    selected = recency.filter_recent_findings(
        object(), items, 14, report, now=NOW,
    )
    assert [item.vulnerability for item in selected] == ["BDSA-2025-2867"]
    assert report["first_detected_filter"]["matched"] == 1
    assert report["first_detected_filter"]["older"] == 1
    assert report["first_detected_filter"]["invalid_date"] == 1
    assert report["first_detected_filter"]["future_date"] == 1
    assert report["first_detected_filter"]["unmatched"] == 1


def test_incomplete_digest_prevents_selection(monkeypatch):
    class Client:
        page_limit = 2

    pages = [
        {"totalCount": 3, "items": [
            {"vulnerabilityId": "BDSA-2025-1", "firstDetected": "2026-11-01T00:00:00Z"},
            {"vulnerabilityId": "BDSA-2025-2", "firstDetected": "2026-11-01T00:00:00Z"},
        ]},
        {"totalCount": 3, "items": []},
    ]
    monkeypatch.setattr(
        recency, "read_page",
        lambda client, *, offset, limit: pages.pop(0),
    )
    with pytest.raises(RuntimeError, match="before totalCount"):
        recency.filter_recent_findings(
            Client(), [finding("BDSA-2025-1")], 14, {}, now=NOW,
        )


def test_digest_failure_does_not_become_allow_partial(monkeypatch):
    def broken(client):
        raise RuntimeError("Black Duck digest unavailable")

    monkeypatch.setattr(recency, "load_digest", broken)
    with pytest.raises(RuntimeError, match="digest unavailable"):
        recency.filter_recent_findings(
            object(), [finding("BDSA-2025-2867")], 14, {}, now=NOW,
        )


def test_no_flag_does_not_fetch_digest(monkeypatch):
    monkeypatch.setattr(
        recency, "load_digest",
        lambda client: pytest.fail("Digest must not be fetched"),
    )
    items = [finding("CVE-2026-0001")]
    assert recency.filter_recent_findings(object(), items, None, {}) == items
