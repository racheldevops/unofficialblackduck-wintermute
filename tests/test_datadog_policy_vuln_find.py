from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from harness.datadog import policy_vuln_find as finder


PROJECT_HREF = "https://bd.example/api/projects/project-a"
VERSION_HREF = (
    "https://bd.example/api/projects/project-a/versions/version-a"
)


def project() -> dict[str, Any]:
    return {
        "name": "Service A",
        "_meta": {
            "href": PROJECT_HREF,
            "links": [
                {
                    "rel": "versions",
                    "href": f"{PROJECT_HREF}/versions",
                }
            ],
        },
    }


def version() -> dict[str, Any]:
    return {
        "versionName": "1.0",
        "phase": "RELEASED",
        "updatedAt": "2026-08-01T00:00:00Z",
        "_meta": {"href": VERSION_HREF},
    }


def settings(**overrides: Any) -> finder.ScanSettings:
    values: dict[str, Any] = {
        "base_url": "https://bd.example",
        "api_token": "token",
        "bearer_token": "bearer",
        "insecure": False,
        "timeout": 30,
        "retries": 1,
        "retry_delay": 0.0,
        "page_limit": 100,
        "debug": False,
        "candidate_mode": "vulnerable-only",
        "policy_name": "",
        "policy_rule_id": "",
        "skip_policy_rules": False,
    }
    values.update(overrides)
    return finder.ScanSettings(**values)


def valid_args(**overrides: Any) -> argparse.Namespace:
    values: dict[str, Any] = {
        "timeout": 30,
        "retries": 1,
        "retry_delay": 2.0,
        "page_limit": 100,
        "refresh_older_than_hours": 6.0,
        "workers": 4,
        "progress_every": 25,
        "cache_save_every": 100,
        "max_runtime_minutes": None,
        "policy_name": None,
        "policy_rule_id": None,
        "skip_policy_rules": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_canonical_href_and_candidate_identity() -> None:
    href = f"{VERSION_HREF}/?ignored=true#fragment"

    assert finder.canonical_href(href) == VERSION_HREF
    key = finder.candidate_key("Service A", "1.0", href)
    assert key == f"Service A|1.0|{VERSION_HREF}"


def test_signature_is_stable_and_canonical() -> None:
    first = finder.signature(project(), version())
    changed = finder.signature(
        project(),
        {**version(), "phase": "DEVELOPMENT"},
    )

    assert first == finder.signature(project(), version())
    assert first != changed

    payload = json.loads(first)
    assert payload["project"] == "Service A"
    assert payload["project_version_href"] == VERSION_HREF


def test_client_paged_get_reads_multiple_pages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = finder.BlackDuckClient(
        base_url="https://bd.example",
        api_token="token",
        insecure=False,
        timeout=30,
        retries=0,
        retry_delay=0,
        page_limit=2,
        debug=False,
    )
    calls: list[int] = []

    def fake_get(
        path: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        assert path == "/api/items"
        offset = int((params or {})["offset"])
        calls.append(offset)

        if offset == 0:
            return {
                "items": [{"id": 1}, {"id": 2}],
                "totalCount": 3,
            }

        return {
            "items": [{"id": 3}],
            "totalCount": 3,
        }

    monkeypatch.setattr(client, "get", fake_get)

    assert client.paged_get("/api/items") == [
        {"id": 1},
        {"id": 2},
        {"id": 3},
    ]
    assert calls == [0, 2]


def test_collection_count_uses_total_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = finder.BlackDuckClient(
        base_url="https://bd.example",
        api_token="token",
        insecure=False,
        timeout=30,
        retries=0,
        retry_delay=0,
        page_limit=100,
        debug=False,
    )
    monkeypatch.setattr(
        client,
        "get",
        lambda *_: {
            "items": [{"id": 1}],
            "totalCount": 42,
        },
    )

    count, items = client.collection_count_and_items(
        "/api/items",
        limit=1,
    )

    assert count == 42
    assert items == [{"id": 1}]


def test_cache_round_trip_and_settings_validation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cache.json"
    expected_settings = {
        "candidate_mode": "vulnerable-only",
        "policy_name": "",
        "policy_rule_id": "",
        "skip_policy_rules": False,
    }
    cache = finder.fresh_cache(
        "https://bd.example",
        expected_settings,
    )
    cache["candidates"]["entry"] = {"status": "ok"}
    finder.save_cache(str(path), cache)

    loaded = finder.load_cache(
        str(path),
        "https://bd.example",
        refresh_all=False,
        settings=expected_settings,
    )
    incompatible = finder.load_cache(
        str(path),
        "https://bd.example",
        refresh_all=False,
        settings={
            **expected_settings,
            "candidate_mode": "both",
        },
    )

    assert loaded["candidates"]["entry"]["status"] == "ok"
    assert incompatible["candidates"] == {}


def test_cache_stale_uses_scan_age() -> None:
    fresh = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }
    missing = {}

    assert finder.cache_stale(fresh, 6.0) is False
    assert finder.cache_stale(missing, 6.0) is True
    assert finder.cache_stale(missing, -1) is False


def test_build_inventory_applies_filters() -> None:
    class Client:
        def paged_get(
            self,
            path: str,
            params: dict[str, Any] | None = None,
        ) -> list[dict[str, Any]]:
            del params

            if path == "/api/projects":
                return [
                    project(),
                    {
                        "name": "Other",
                        "_meta": {
                            "href": "https://bd.example/api/projects/other"
                        },
                    },
                ]

            if path == f"{PROJECT_HREF}/versions":
                return [
                    version(),
                    {
                        **version(),
                        "versionName": "2.0",
                        "_meta": {
                            "href": f"{PROJECT_HREF}/versions/version-b"
                        },
                    },
                ]

            return []

    args = argparse.Namespace(
        project_name="Service A",
        project_name_contains=None,
        max_projects=None,
        max_versions=None,
        version_name="1.0",
        phase="RELEASED",
    )

    inventory = finder.build_inventory(Client(), args)

    assert len(inventory) == 1
    assert finder.version_name(inventory[0][1]) == "1.0"


def test_scan_candidate_marks_vulnerable_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        finder,
        "count_vulnerable_components",
        lambda **_: 3,
    )

    row = finder.scan_candidate(
        object(),
        project(),
        version(),
        settings(candidate_mode="vulnerable-only"),
    )

    assert row["candidate_reason"] == "vulnerable-bom-components"
    assert row["candidate_vulnerable_component_count"] == "3"
    assert row["candidate_key"] == (
        f"Service A|1.0|{VERSION_HREF}"
    )
    assert row["candidate_external_id"] == finder.sha256_hex(
        row["candidate_key"]
    )


def test_requested_policy_must_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        finder,
        "count_vulnerable_components",
        lambda **_: 2,
    )
    monkeypatch.setattr(
        finder,
        "count_policy_violations",
        lambda **_: (1, 1, "", ""),
    )

    no_match = finder.scan_candidate(
        object(),
        project(),
        version(),
        settings(
            candidate_mode="both",
            policy_name="Required Policy",
        ),
    )

    monkeypatch.setattr(
        finder,
        "count_policy_violations",
        lambda **_: (
            1,
            1,
            "Required Policy",
            "https://bd.example/policies/rule",
        ),
    )

    match = finder.scan_candidate(
        object(),
        project(),
        version(),
        settings(
            candidate_mode="both",
            policy_name="Required Policy",
        ),
    )

    assert no_match["candidate_reason"] == ""
    assert "requested-policy-match" in match["candidate_reason"]


def test_count_policy_violations_skips_rule_traversal_when_unneeded() -> None:
    class Client:
        debug = False

        def collection_count_and_items(
            self,
            path: str,
            params: dict[str, Any] | None = None,
            limit: int = 1,
        ) -> tuple[int, list[dict[str, Any]]]:
            assert path == f"{VERSION_HREF}/components"
            assert params == {"filter": "policyStatus:IN_VIOLATION"}
            assert limit == 1
            return 4, [{"id": 1}]

    result = finder.count_policy_violations(
        Client(),
        VERSION_HREF,
        settings(candidate_mode="policy-only"),
    )

    assert result == (4, 0, "", "")


def test_scan_worker_converts_exception_to_failed_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        finder,
        "scan_candidate",
        lambda *_: (_ for _ in ()).throw(
            RuntimeError("temporary failure")
        ),
    )

    result = finder.scan_one_candidate_version(
        settings(),
        project(),
        version(),
        finder.signature(project(), version()),
    )

    assert result.status == "failed"
    assert result.is_candidate is False
    assert result.error == "temporary failure"
    assert result.row["cache_entry_status"] == "failed"


def test_write_changes_reports_all_change_types(
    tmp_path: Path,
) -> None:
    path = tmp_path / "changes.csv"
    unchanged = {
        "candidate_external_id": "unchanged",
        "project": "Same",
        "candidate_reason": "reason",
    }
    changed_old = {
        "candidate_external_id": "changed",
        "project": "Changed",
        "candidate_reason": "old",
    }
    changed_new = {
        **changed_old,
        "candidate_reason": "new",
    }
    removed = {
        "candidate_external_id": "removed",
        "project": "Removed",
    }
    added = {
        "candidate_external_id": "added",
        "project": "Added",
    }

    counts = finder.write_changes(
        str(path),
        [unchanged, changed_old, removed],
        [unchanged, changed_new, added],
    )

    assert counts == (1, 1, 1, 1)

    with path.open(newline="", encoding="utf-8") as input_file:
        rows = list(csv.DictReader(input_file))

    assert {
        row["change_type"]
        for row in rows
    } == {"added", "removed", "changed"}


def test_validate_args_clamps_worker_count() -> None:
    args = valid_args(workers=100)

    finder.validate_args(args)

    assert args.workers == finder.MAX_WORKERS


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"timeout": 0}, "timeout"),
        ({"retries": -1}, "retries"),
        ({"workers": 0}, "workers"),
        ({"progress_every": 0}, "progress-every"),
        ({"cache_save_every": 0}, "cache-save-every"),
        (
            {
                "policy_name": "Policy",
                "skip_policy_rules": True,
            },
            "skip-policy-rules",
        ),
    ],
)
def test_validate_args_rejects_invalid_values(
    override: dict[str, Any],
    message: str,
) -> None:
    args = valid_args(**override)

    with pytest.raises(RuntimeError, match=message):
        finder.validate_args(args)


def test_inventory_fetches_project_versions_concurrently() -> None:
    import threading
    import time

    projects = [
        {
            "name": f"Service {index}",
            "_meta": {
                "href": f"https://bd.example/api/projects/{index}",
                "links": [
                    {
                        "rel": "versions",
                        "href": (
                            f"https://bd.example/api/projects/"
                            f"{index}/versions"
                        ),
                    }
                ],
            },
        }
        for index in range(4)
    ]

    class Client:
        def __init__(self) -> None:
            self.lock = threading.Lock()
            self.active = 0
            self.max_active = 0

        def clone_for_worker(self) -> Client:
            return self

        def paged_get(
            self,
            path: str,
            params: dict[str, Any] | None = None,
        ) -> list[dict[str, Any]]:
            del params

            if path == "/api/projects":
                return projects

            with self.lock:
                self.active += 1
                self.max_active = max(
                    self.max_active,
                    self.active,
                )

            try:
                time.sleep(0.03)
                project_id = path.split("/")[-2]
                return [
                    {
                        "versionName": "1.0",
                        "phase": "RELEASED",
                        "_meta": {
                            "href": (
                                f"https://bd.example/api/projects/"
                                f"{project_id}/versions/1"
                            )
                        },
                    }
                ]
            finally:
                with self.lock:
                    self.active -= 1

    args = argparse.Namespace(
        project_name=None,
        project_name_contains=None,
        max_projects=None,
        max_versions=None,
        version_name=None,
        phase=None,
        workers=4,
    )
    client = Client()
    inventory = finder.build_inventory(client, args)

    assert client.max_active > 1
    assert [
        project["name"]
        for project, version in inventory
    ] == [
        "Service 0",
        "Service 1",
        "Service 2",
        "Service 3",
    ]
