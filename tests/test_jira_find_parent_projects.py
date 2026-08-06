from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from wintermute.jira import find_parent_projects as parents


PROJECT_UUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
PARENT_VERSION_UUID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
CHILD_PROJECT_UUID = "cccccccc-cccc-cccc-cccc-cccccccccccc"
CHILD_VERSION_UUID = "dddddddd-dddd-dddd-dddd-dddddddddddd"

PARENT_HREF = (
    f"https://bd.example/api/projects/{PROJECT_UUID}/versions/"
    f"{PARENT_VERSION_UUID}"
)
CHILD_HREF = (
    f"https://bd.example/api/projects/{CHILD_PROJECT_UUID}/versions/"
    f"{CHILD_VERSION_UUID}"
)


def version(
    project_name: str = "Parent",
    version_name: str = "1.0",
    project_href: str | None = None,
    version_href: str = PARENT_HREF,
    updated: str = "2026-08-01T00:00:00Z",
) -> parents.VersionInfo:
    return parents.VersionInfo(
        project_name=project_name,
        version_name=version_name,
        project_href=project_href or version_href.rsplit("/versions/", 1)[0],
        version_href=version_href,
        phase="RELEASED",
        updated=updated,
        created="2026-01-01T00:00:00Z",
    )


def relation(child_href: str = CHILD_HREF) -> dict[str, str]:
    return {
        "parent_project": "Parent",
        "parent_version": "1.0",
        "child_project": "Child",
        "child_version": "2.0",
        "parent_version_href": PARENT_HREF,
        "child_version_href": child_href,
    }


def test_blackduck_client_rejects_conflicting_tls_modes() -> None:
    with pytest.raises(ValueError):
        parents.BlackDuckClient(
            "https://bd.example",
            "token",
            insecure=True,
            ca_bundle="/tmp/ca.pem",
        )


def test_make_url_merges_and_encodes_query_parameters() -> None:
    client = parents.BlackDuckClient("https://bd.example/", "token")

    url = client._make_url(
        "/api/projects?existing=yes",
        {"q": "name:Project A", "limit": 100, "none": None},
    )

    assert url.startswith("https://bd.example/api/projects?")
    assert "existing=yes" in url
    assert "q=name%3AProject+A" in url
    assert "limit=100" in url
    assert "none=" not in url


def test_paged_get_reads_all_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    client = parents.BlackDuckClient("https://bd.example", "token")
    calls: list[dict[str, object]] = []

    def fake_get(
        path: str,
        params: dict[str, object] | None = None,
    ) -> dict[str, object]:
        assert path == "/api/projects"
        page = dict(params or {})
        calls.append(page)

        if page["offset"] == 0:
            return {"items": [{"id": 1}, {"id": 2}], "totalCount": 3}

        return {"items": [{"id": 3}], "totalCount": 3}

    monkeypatch.setattr(client, "get", fake_get)

    assert client.paged_get("/api/projects", limit=2) == [
        {"id": 1},
        {"id": 2},
        {"id": 3},
    ]
    assert [call["offset"] for call in calls] == [0, 2]


def test_extracts_and_canonicalizes_project_version_hrefs() -> None:
    raw = f"https://other.example{CHILD_HREF.split('bd.example', 1)[1]}?x=1#part"

    assert parents.extract_project_version_hrefs(
        raw,
        "https://bd.example",
    ) == [
        CHILD_HREF.replace("bd.example", "other.example")
    ]

    relative = f"/prefix/api/projects/{CHILD_PROJECT_UUID}/versions/{CHILD_VERSION_UUID}"
    assert parents.extract_project_version_hrefs(
        relative,
        "https://bd.example",
    ) == [CHILD_HREF]


def test_build_indexes_supports_href_and_exact_name_lookup() -> None:
    parent = version()
    child = version(
        project_name="Child",
        version_name="2.0",
        version_href=CHILD_HREF,
    )

    by_href, by_name = parents.build_indexes([parent, child])

    assert by_href[CHILD_HREF] == child
    assert by_name[("Child", "2.0")] == [child]


def test_discover_subprojects_prefers_api_href(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = version()
    child = version(
        project_name="Child",
        version_name="2.0",
        version_href=CHILD_HREF,
    )
    client = parents.BlackDuckClient("https://bd.example", "token")

    monkeypatch.setattr(
        parents,
        "get_bom_components",
        lambda *_: [
            {
                "componentName": "Child",
                "componentVersionName": "2.0",
                "_meta": {
                    "links": [
                        {
                            "rel": "project-version",
                            "href": f"{CHILD_HREF}?ignored=true",
                        }
                    ]
                },
            }
        ],
    )

    discovered = parents.discover_subprojects_for_version(
        client,
        parent,
        {PARENT_HREF: parent, CHILD_HREF: child},
        {("Child", "2.0"): [child]},
        resolve_bom_names=True,
        debug=False,
    )

    assert len(discovered) == 1
    assert discovered[0]["child_version_href"] == CHILD_HREF
    assert discovered[0]["detection_method"] == "api-href"


def test_discover_subprojects_uses_name_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = version()
    child = version(
        project_name="Child",
        version_name="2.0",
        version_href=CHILD_HREF,
    )
    client = parents.BlackDuckClient("https://bd.example", "token")

    monkeypatch.setattr(
        parents,
        "get_bom_components",
        lambda *_: [
            {
                "componentName": "Child",
                "componentVersionName": "2.0",
            }
        ],
    )

    discovered = parents.discover_subprojects_for_version(
        client,
        parent,
        {PARENT_HREF: parent, CHILD_HREF: child},
        {("Child", "2.0"): [child]},
        resolve_bom_names=True,
        debug=False,
    )

    assert len(discovered) == 1
    assert discovered[0]["detection_method"] == "bom-component-name-version"


def test_dedupe_relations_uses_parent_and_child_hrefs() -> None:
    first = relation()
    duplicate = {**first, "child_project": "Renamed child"}
    different = relation(
        CHILD_HREF.replace(CHILD_VERSION_UUID, "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")
    )

    assert parents.dedupe_relations([first, duplicate, different]) == [
        first,
        different,
    ]


def test_scan_reason_covers_cache_decisions() -> None:
    item = version()
    current_entry = {
        "signature": item.signature(),
        "status": "ok",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }

    assert parents.scan_reason_for_version(
        item,
        current_entry,
        refresh_all=False,
        refresh_failed=True,
        refresh_older_than_days=7,
        trust_cache_without_update_marker=False,
    ) is None

    assert parents.scan_reason_for_version(
        item,
        None,
        refresh_all=False,
        refresh_failed=True,
        refresh_older_than_days=7,
        trust_cache_without_update_marker=False,
    ) == "new-version"

    assert parents.scan_reason_for_version(
        item,
        current_entry,
        refresh_all=True,
        refresh_failed=True,
        refresh_older_than_days=7,
        trust_cache_without_update_marker=False,
    ) == "refresh-all"

    failed_entry = {**current_entry, "status": "failed"}
    assert parents.scan_reason_for_version(
        item,
        failed_entry,
        refresh_all=False,
        refresh_failed=True,
        refresh_older_than_days=7,
        trust_cache_without_update_marker=False,
    ) == "previous-scan-failed"

    no_marker = version(updated="")
    no_marker_entry = {
        "signature": no_marker.signature(),
        "status": "ok",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }
    assert parents.scan_reason_for_version(
        no_marker,
        no_marker_entry,
        refresh_all=False,
        refresh_failed=True,
        refresh_older_than_days=-1,
        trust_cache_without_update_marker=False,
    ) == "no-update-marker"


def test_plan_scan_marks_reused_entries() -> None:
    item = version()
    cache = parents.new_cache("https://bd.example", False)
    cache["entries"][item.version_href] = {
        "signature": item.signature(),
        "status": "ok",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "relations": [],
    }

    planned, reused = parents.plan_scan(
        cache,
        [item],
        refresh_all=False,
        refresh_failed=True,
        refresh_older_than_days=7,
        trust_cache_without_update_marker=False,
    )

    assert planned == []
    assert reused == 1
    assert (
        cache["entries"][item.version_href]["reuse_reason"]
        == "unchanged-cache-hit"
    )


def test_failed_rescan_retains_previous_relations() -> None:
    item = version()
    cached_relation = relation()
    cache = parents.new_cache("https://bd.example", False)
    cache["entries"][item.version_href] = {
        "relations": [cached_relation],
    }

    parents.update_cache_with_scan_results(
        cache,
        [(item, "previous-scan-failed", [], "temporary failure")],
    )

    entry = cache["entries"][item.version_href]
    assert entry["status"] == "failed"
    assert entry["error"] == "temporary failure"
    assert entry["relations"] == [cached_relation]


def test_successful_rescan_replaces_previous_relations() -> None:
    item = version()
    cache = parents.new_cache("https://bd.example", False)
    cache["entries"][item.version_href] = {
        "relations": [relation("https://bd.example/old")],
    }
    replacement = relation()

    parents.update_cache_with_scan_results(
        cache,
        [(item, "version-changed", [replacement], None)],
    )

    entry = cache["entries"][item.version_href]
    assert entry["status"] == "ok"
    assert entry["relations"] == [replacement]


def test_prune_cache_removes_versions_outside_inventory() -> None:
    item = version()
    cache = parents.new_cache("https://bd.example", False)
    cache["entries"] = {
        item.version_href: {},
        "https://bd.example/stale": {},
    }

    assert parents.prune_cache_to_current_inventory(cache, [item]) == 1
    assert set(cache["entries"]) == {item.version_href}


def test_load_cache_rejects_incompatible_schema(tmp_path: Path) -> None:
    cache_path = tmp_path / "cache.json"
    cache_path.write_text(
        json.dumps(
            {
                "schema_version": 0,
                "base_url": "https://bd.example",
                "entries": {"stale": {}},
            }
        ),
        encoding="utf-8",
    )

    loaded = parents.load_cache(
        str(cache_path),
        "https://bd.example",
        False,
    )

    assert loaded["schema_version"] == parents.CACHE_SCHEMA_VERSION
    assert loaded["entries"] == {}


def test_write_changes_reports_added_and_removed_rows(
    tmp_path: Path,
) -> None:
    old = relation(
        CHILD_HREF.replace(CHILD_VERSION_UUID, "11111111-1111-1111-1111-111111111111")
    )
    new = relation(
        CHILD_HREF.replace(CHILD_VERSION_UUID, "22222222-2222-2222-2222-222222222222")
    )
    output = tmp_path / "changes.csv"

    parents.write_changes_csv([old], [new], str(output))

    with output.open(newline="", encoding="utf-8") as input_file:
        rows = list(csv.DictReader(input_file))

    assert {row["change_type"] for row in rows} == {"added", "removed"}
    assert len(rows) == 2


def test_default_page_limit_is_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = parents.BlackDuckClient(
        "https://bd.example",
        "token",
        page_limit=17,
    )
    limits: list[int] = []

    def fake_get(
        path: str,
        params: dict[str, object] | None = None,
    ) -> dict[str, object]:
        del path
        limits.append(int((params or {})["limit"]))
        return {"items": [], "totalCount": 0}

    monkeypatch.setattr(client, "get", fake_get)

    assert client.paged_get("/api/items") == []
    assert limits == [17]


def test_version_inventory_fetches_projects_concurrently() -> None:
    import threading
    import time

    projects = [
        {
            "name": f"Project {index}",
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
        base_url = "https://bd.example"

        def __init__(self) -> None:
            self.lock = threading.Lock()
            self.active = 0
            self.max_active = 0

        def clone_for_worker(self) -> Client:
            return self

        def paged_get(
            self,
            path: str,
            params: dict[str, object] | None = None,
            limit: int | None = None,
        ) -> list[dict[str, object]]:
            del params, limit

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

    client = Client()
    inventory = parents.build_version_inventory(
        client,
        project_name_contains=None,
        max_projects=None,
        debug=False,
        workers=4,
    )

    assert client.max_active > 1
    assert [
        item.project_name
        for item in inventory
    ] == [
        "Project 0",
        "Project 1",
        "Project 2",
        "Project 3",
    ]


def test_parent_discovery_does_not_retain_unique_bom_responses() -> None:
    client = parents.BlackDuckClient(
        "https://bd.example",
        "token",
    )
    clone = client.clone_for_worker()

    assert client.cache_raw_gets is False
    assert client.cache_paged_results is False
    assert clone.cache_raw_gets is False
    assert clone.cache_paged_results is False
