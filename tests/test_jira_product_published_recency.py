from __future__ import annotations

import sys
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from wintermute.jira import pipeline
from wintermute.jira import product_published_recency as published


NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)


def finding(identifier):
    return SimpleNamespace(vulnerability=identifier)


def test_cli_options_are_independent(monkeypatch):
    monkeypatch.setattr(sys, "argv", [
        "blackduck-jira-pipeline",
        "--dry-run",
        "--vulnerability-year", "2025",
        "--first-detected-within-days", "30",
        "--published-within-days", "14",
    ])
    args = pipeline.parse_args()
    assert args.vulnerability_year == [2025]
    assert args.first_detected_within_days == 30
    assert args.published_within_days == 14


@pytest.mark.parametrize("value", ["0", "3651", "-1", "1.5", "no"])
def test_invalid_published_days_rejected(monkeypatch, capsys, value):
    monkeypatch.setattr(sys, "argv", [
        "blackduck-jira-pipeline", "--published-within-days", value,
    ])
    assert pipeline.main() == pipeline.EXIT_ARGUMENT_ERROR
    assert "--published-within-days" in capsys.readouterr().err


def test_published_filter_uses_exact_advisory_once(monkeypatch):
    calls = []

    def read(client, identifier):
        calls.append(identifier)
        return {
            "BDSA-2025-2867": {
                "name": "BDSA-2025-2867",
                "publishedDate": "2026-10-29T12:00:00Z",
            },
            "CVE-2026-0001": {
                "name": "CVE-2026-0001",
                "publishedDate": "2026-09-01T12:00:00Z",
            },
        }[identifier]

    monkeypatch.setattr(published, "read_advisory", read)
    items = [
        finding("BDSA-2025-2867"),
        finding("BDSA-2025-2867"),
        finding("CVE-2026-0001"),
    ]
    report = {}
    selected = published.filter_published_findings(
        object(), items, 14, report, now=NOW,
    )

    assert [item.vulnerability for item in selected] == [
        "BDSA-2025-2867", "BDSA-2025-2867",
    ]
    assert calls == ["BDSA-2025-2867", "CVE-2026-0001"]
    assert report["published_filter"]["matched"] == 2
    assert report["published_filter"]["older"] == 1


def test_allow_partial_excludes_failed_id_but_keeps_other(monkeypatch):
    def read(client, identifier):
        if identifier == "CVE-2026-0002":
            raise RuntimeError("Advisory unavailable")
        return {
            "name": identifier,
            "publishedDate": "2026-11-01T12:00:00Z",
        }

    monkeypatch.setattr(published, "read_advisory", read)
    report = {}
    selected = published.filter_published_findings(
        object(),
        [finding("CVE-2026-0001"), finding("CVE-2026-0002")],
        14,
        report,
        strict=False,
        now=NOW,
    )
    assert [item.vulnerability for item in selected] == ["CVE-2026-0001"]
    assert report["published_filter"]["read_failed"] == 1
    assert "CVE-2026-0002" in report["published_filter"]["failed_advisories"]


def test_strict_rejects_failed_advisory(monkeypatch):
    monkeypatch.setattr(
        published, "read_advisory",
        lambda client, identifier: (_ for _ in ()).throw(
            RuntimeError("Advisory unavailable")
        ),
    )
    with pytest.raises(RuntimeError, match="Published-date lookup failed"):
        published.filter_published_findings(
            object(), [finding("CVE-2026-0001")], 14, {}, now=NOW,
        )


def test_missing_or_future_date_is_not_recent(monkeypatch):
    dates = {
        "CVE-2026-0001": "",
        "CVE-2026-0002": "2026-11-04T12:00:00Z",
    }
    monkeypatch.setattr(
        published, "read_advisory",
        lambda client, identifier: {
            "name": identifier,
            "publishedDate": dates[identifier],
        },
    )
    report = {}
    assert published.filter_published_findings(
        object(),
        [finding("CVE-2026-0001"), finding("CVE-2026-0002")],
        14, report, now=NOW,
    ) == []
    assert report["published_filter"]["invalid_date"] == 1
    assert report["published_filter"]["future_date"] == 1


def test_no_published_flag_makes_no_advisory_requests(monkeypatch):
    monkeypatch.setattr(
        published, "read_advisory",
        lambda client, identifier: pytest.fail("Unexpected advisory GET"),
    )
    items = [finding("CVE-2026-0001")]
    assert published.filter_published_findings(
        object(), items, None, {},
    ) == items
