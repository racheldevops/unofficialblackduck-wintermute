from __future__ import annotations

import time
import argparse
import copy
import csv
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from harness.jira import subp_vuln_rollup as rollup


PROJECT_UUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
VERSION_UUID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
VERSION_HREF = (
    f"https://bd.example/api/projects/{PROJECT_UUID}/versions/"
    f"{VERSION_UUID}"
)


class MinimalClient:
    def __init__(self) -> None:
        self.base_url = "https://bd.example"
        self.debug = False
        self.timeout = 30
        self.retries = 1
        self.vulnerability_summary_cache: dict[
            tuple[str, str, float],
            list[dict[str, Any]],
        ] = {}


def valid_args(**overrides: Any) -> argparse.Namespace:
    values: dict[str, Any] = {
        "timeout": 30,
        "retries": 1,
        "retry_delay": 2.0,
        "page_limit": 100,
        "depth": 1,
        "api_cache_max_age_hours": 20.0,
        "api_cache_max_entries": 5000,
        "require_entity": False,
        "entity_custom_field": "foo Entity",
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_api_response_cache_returns_deep_copies(
    tmp_path: Path,
) -> None:
    cache = rollup.ApiResponseCache(
        path=str(tmp_path / "cache.json"),
        base_url="https://bd.example",
        max_age_hours=-1,
        max_entries=10,
        debug=False,
    )
    cache.put_items(
        "https://bd.example/items",
        [{"nested": {"value": 1}}],
        total_count=1,
    )

    first = cache.get_items("https://bd.example/items")
    assert first is not None
    first[0]["nested"]["value"] = 99

    second = cache.get_items("https://bd.example/items")
    assert second == [{"nested": {"value": 1}}]


def test_api_response_cache_prunes_oldest_entries(
    tmp_path: Path,
) -> None:
    cache = rollup.ApiResponseCache(
        path=str(tmp_path / "cache.json"),
        base_url="https://bd.example",
        max_age_hours=-1,
        max_entries=2,
        debug=False,
    )
    cache.data["entries"] = {
        "old": {
            "cached_at": "2026-01-01T00:00:00+00:00",
            "last_used_at": "2026-01-01T00:00:00+00:00",
            "items": [],
        },
        "middle": {
            "cached_at": "2026-01-02T00:00:00+00:00",
            "last_used_at": "2026-01-02T00:00:00+00:00",
            "items": [],
        },
        "new": {
            "cached_at": "2026-01-03T00:00:00+00:00",
            "last_used_at": "2026-01-03T00:00:00+00:00",
            "items": [],
        },
    }

    cache.prune()

    assert set(cache.data["entries"]) == {"middle", "new"}


def test_api_response_cache_save_and_load_round_trip(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cache.json"
    cache = rollup.ApiResponseCache(
        path=str(path),
        base_url="https://bd.example",
        max_age_hours=-1,
        max_entries=10,
        debug=False,
    )
    cache.put_items("https://bd.example/items", [{"id": 1}])
    cache.save()

    loaded = rollup.ApiResponseCache.load(
        path=str(path),
        base_url="https://bd.example",
        max_age_hours=-1,
        refresh=False,
        max_entries=10,
        debug=False,
    )

    assert loaded.get_items("https://bd.example/items") == [{"id": 1}]


def test_blackduck_paged_get_reuses_in_run_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = rollup.BlackDuckClient(
        base_url="https://bd.example",
        api_token="token",
        page_limit=2,
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
            return {"items": [{"id": 1}, {"id": 2}], "totalCount": 3}

        return {"items": [{"id": 3}], "totalCount": 3}

    monkeypatch.setattr(client, "get", fake_get)

    first = client.paged_get("/api/items")
    second = client.paged_get("/api/items")

    assert first == [{"id": 1}, {"id": 2}, {"id": 3}]
    assert second == first
    assert calls == [0, 2]


def test_custom_field_rendering_supports_nested_values() -> None:
    payload = {
        "customField": {
            "name": "foo Entity",
        },
        "selectedValues": [
            {"label": "Team B"},
            {"label": "Team A"},
        ],
    }

    found, value = rollup.find_named_custom_field(
        payload,
        "FOO entity",
    )

    assert found is True
    assert value == "Team A;Team B"


def test_read_project_custom_field_caches_project_lookup() -> None:
    class Client(MinimalClient):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def get(self, href: str) -> dict[str, Any]:
            self.calls += 1
            assert href.endswith(f"/api/projects/{PROJECT_UUID}")
            return {"foo Entity": "Team A"}

        def paged_get(self, href: str) -> list[dict[str, Any]]:
            raise AssertionError(f"Unexpected paged request: {href}")

    client = Client()

    first = rollup.read_project_custom_field(
        client,
        VERSION_HREF,
        {"versionName": "1"},
        "foo Entity",
    )
    second = rollup.read_project_custom_field(
        client,
        VERSION_HREF,
        {"versionName": "1"},
        "foo Entity",
    )

    assert first == "Team A"
    assert second == "Team A"
    assert client.calls == 1


def test_extract_vulnerability_candidates_finds_nested_records() -> None:
    payload = {
        "wrapper": {
            "vulnerability": {
                "vulnerabilityName": "CVE-1",
                "overallScore": 9.5,
                "severity": "CRITICAL",
            }
        }
    }

    candidates = rollup.extract_vulnerability_candidates(
        payload,
        "overallScore",
    )

    assert candidates
    assert {
        rollup.vulnerability_identifier(candidate)
        for candidate in candidates
    } == {"CVE-1"}


def test_summarize_vulnerabilities_filters_threshold_and_caches() -> None:
    class Client(MinimalClient):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def paged_get(self, href: str) -> list[dict[str, Any]]:
            self.calls += 1
            assert href == "https://bd.example/vulnerabilities"
            return [
                {
                    "vulnerabilityName": "CVE-1",
                    "overallScore": 9.8,
                    "severity": "CRITICAL",
                    "cvssVector": "CVSS:3.1/AV:N",
                    "_meta": {
                        "href": "https://bd.example/vulnerabilities/CVE-1"
                    },
                },
                {
                    "vulnerabilityName": "CVE-2",
                    "overallScore": 5.0,
                    "severity": "MEDIUM",
                },
            ]

    client = Client()
    component = {
        "_meta": {
            "links": [
                {
                    "rel": "vulnerabilities",
                    "href": "https://bd.example/vulnerabilities",
                }
            ]
        }
    }

    first = rollup.summarize_vulnerabilities_for_component(
        client,
        component,
        "library",
        "1.0",
        threshold=7.0,
        score_field="overallScore",
    )
    second = rollup.summarize_vulnerabilities_for_component(
        client,
        component,
        "library",
        "1.0",
        threshold=7.0,
        score_field="overallScore",
    )

    assert first == [
        {
            "vulnerability": "CVE-1",
            "score": 9.8,
            "severity": "CRITICAL",
            "cvss_vector": "CVSS:3.1/AV:N",
            "blackduck_url": (
                "https://bd.example/vulnerabilities/CVE-1"
            ),
        }
    ]
    assert second == first
    assert client.calls == 1


def test_extract_component_version_resolves_display_name() -> None:
    class Client(MinimalClient):
        def get(self, href: str) -> dict[str, Any]:
            assert href == "https://bd.example/api/components/a/versions/b"
            return {"versionName": "4.5.6"}

    name, href = rollup.extract_component_version_details(
        Client(),
        {
            "componentVersionHref": (
                "https://bd.example/api/components/a/versions/b/"
            )
        },
    )

    assert name == "4.5.6"
    assert href == "https://bd.example/api/components/a/versions/b"


def test_collect_findings_deduplicates_component_vulnerability_urls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    component = {
        "componentName": "library",
        "_meta": {
            "links": [
                {
                    "rel": "vulnerabilities",
                    "href": "https://bd.example/component-vulnerabilities",
                }
            ]
        },
    }
    client = MinimalClient()

    monkeypatch.setattr(
        rollup,
        "read_project_custom_field",
        lambda **_: "Team A",
    )
    monkeypatch.setattr(
        rollup,
        "get_vulnerable_bom_components",
        lambda *_: [copy.deepcopy(component), copy.deepcopy(component)],
    )
    monkeypatch.setattr(
        rollup,
        "extract_component_version_details",
        lambda *_: (
            "1.2.3",
            "https://bd.example/api/components/a/versions/b",
        ),
    )
    monkeypatch.setattr(
        rollup,
        "summarize_vulnerabilities_for_component",
        lambda **_: [
            {
                "vulnerability": "CVE-1",
                "score": 9.8,
                "severity": "CRITICAL",
                "cvss_vector": "CVSS:3.1/AV:N",
                "blackduck_url": "https://bd.example/vulnerabilities/CVE-1",
            }
        ],
    )

    findings = rollup.collect_findings_for_subproject(
        client,
        parent_project="Parent",
        parent_version="1",
        subproject_ref={
            "project_name": "Child",
            "version_name": "2",
            "version_href": VERSION_HREF,
            "version": {"versionName": "2"},
            "parent_version_href": "https://bd.example/parent/1",
            "path": "Child/2",
            "source": "api-href",
        },
        threshold=7.0,
        score_field="overallScore",
        entity_custom_field="foo Entity",
        require_entity=True,
    )

    assert len(findings) == 1
    assert findings[0]["entity"] == "Team A"
    assert findings[0]["component_version"] == "1.2.3"
    assert findings[0]["rollup_key"] == (
        "Parent|1|Child|2|library|1.2.3|CVE-1"
    )


def test_collect_findings_requires_entity_when_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        rollup,
        "read_project_custom_field",
        lambda **_: "",
    )

    with pytest.raises(RuntimeError, match="does not have a populated"):
        rollup.collect_findings_for_subproject(
            MinimalClient(),
            parent_project="Parent",
            parent_version="1",
            subproject_ref={
                "project_name": "Child",
                "version_name": "2",
                "version_href": VERSION_HREF,
                "version": {"versionName": "2"},
            },
            threshold=7.0,
            score_field="overallScore",
            entity_custom_field="foo Entity",
            require_entity=True,
        )


def test_parent_csv_loading_deduplicates_relationships(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "parents.csv"
    fieldnames = [
        "parent_project",
        "parent_version",
        "child_project",
        "child_version",
        "parent_version_href",
        "child_version_href",
        "detection_method",
    ]
    row = {
        "parent_project": "Parent",
        "parent_version": "1",
        "child_project": "Child",
        "child_version": "2",
        "parent_version_href": "https://bd.example/parent/1/",
        "child_version_href": f"{VERSION_HREF}/",
        "detection_method": "api-href",
    }

    with csv_path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow(row)
        writer.writerow(row)

    class Client(MinimalClient):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def get(self, href: str) -> dict[str, Any]:
            self.calls += 1
            return {"versionName": "2", "_meta": {"href": href}}

    client = Client()
    failures: list[rollup.FailedRelationship] = []

    refs = rollup.load_subproject_refs_from_parent_csv(
        client,
        str(csv_path),
        parent_project_filter=None,
        parent_version_filter=None,
        debug=False,
        failures=failures,
    )

    assert len(refs) == 1
    assert refs[0]["version_href"] == VERSION_HREF
    assert client.calls == 1
    assert failures == []


def test_parent_csv_loading_records_failed_child(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "parents.csv"
    csv_path.write_text(
        "\n".join(
            [
                (
                    "parent_project,parent_version,child_project,"
                    "child_version,parent_version_href,child_version_href"
                ),
                (
                    f"Parent,1,Child,2,https://bd.example/parent/1,"
                    f"{VERSION_HREF}"
                ),
            ]
        ),
        encoding="utf-8",
    )

    class Client(MinimalClient):
        def get(self, href: str) -> dict[str, Any]:
            raise RuntimeError(f"failed: {href}")

    failures: list[rollup.FailedRelationship] = []
    refs = rollup.load_subproject_refs_from_parent_csv(
        Client(),
        str(csv_path),
        parent_project_filter=None,
        parent_version_filter=None,
        debug=False,
        failures=failures,
    )

    assert refs == []
    assert len(failures) == 1
    assert failures[0].stage == "load-child-version"
    assert failures[0].child_version_href == VERSION_HREF


def test_filter_subprojects_supports_all_target_fields() -> None:
    subprojects = [
        {
            "project_name": "A",
            "version_name": "1",
            "version_href": "https://bd.example/a/1/",
        },
        {
            "project_name": "B",
            "version_name": "2",
            "version_href": "https://bd.example/b/2",
        },
    ]

    assert rollup.filter_subprojects_for_targeting(
        subprojects,
        only_child_project="B",
        only_child_version="2",
        only_child_href="https://bd.example/b/2/",
    ) == [subprojects[1]]


def test_collect_subprojects_continues_after_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MinimalClient()
    subprojects = [
        {
            "project_name": "Good",
            "version_name": "1",
            "version_href": "https://bd.example/good/1",
            "version": {},
            "source": "test",
        },
        {
            "project_name": "Bad",
            "version_name": "2",
            "version_href": "https://bd.example/bad/2",
            "version": {},
            "source": "test",
        },
    ]

    def fake_collect(
        client: Any,
        parent_project: str,
        parent_version: str,
        subproject_ref: dict[str, Any],
        threshold: float,
        score_field: str,
        entity_custom_field: str,
        require_entity: bool,
    ) -> list[dict[str, Any]]:
        del (
            client,
            parent_project,
            parent_version,
            threshold,
            score_field,
            entity_custom_field,
            require_entity,
        )
        if subproject_ref["project_name"] == "Bad":
            raise RuntimeError("temporary failure")
        return [{"rollup_key": "good"}]

    monkeypatch.setattr(
        rollup,
        "collect_findings_for_subproject",
        fake_collect,
    )
    args = argparse.Namespace(
        debug=False,
        threshold=7.0,
        score_field="overallScore",
        entity_custom_field="foo Entity",
        require_entity=False,
    )

    findings, failures = rollup.collect_findings_for_subprojects(
        client,
        subprojects,
        args,
        default_parent_project="Parent",
        default_parent_version="1",
    )

    assert findings == [{"rollup_key": "good"}]
    assert len(failures) == 1
    assert failures[0].child_project == "Bad"
    assert failures[0].stage == "collect-vulnerabilities"


def test_walk_subprojects_respects_depth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = {"_meta": {"href": "https://bd.example/root"}}
    child = {"_meta": {"href": "https://bd.example/child"}}
    grandchild = {"_meta": {"href": "https://bd.example/grandchild"}}

    def fake_discover(
        client: Any,
        project_version: dict[str, Any],
        resolve_bom_names: bool,
        debug: bool,
    ) -> list[dict[str, Any]]:
        del client, resolve_bom_names, debug
        href = rollup.get_self_href(project_version)

        if href == "https://bd.example/root":
            return [
                {
                    "project_name": "Child",
                    "version_name": "1",
                    "version_href": "https://bd.example/child",
                    "version": child,
                    "source": "href",
                }
            ]

        if href == "https://bd.example/child":
            return [
                {
                    "project_name": "Grandchild",
                    "version_name": "1",
                    "version_href": "https://bd.example/grandchild",
                    "version": grandchild,
                    "source": "href",
                }
            ]

        return []

    monkeypatch.setattr(
        rollup,
        "discover_direct_subprojects",
        fake_discover,
    )

    refs = rollup.walk_subprojects(
        MinimalClient(),
        root,
        depth=2,
        resolve_bom_names=False,
        debug=False,
    )

    assert [ref["project_name"] for ref in refs] == [
        "Child",
        "Grandchild",
    ]
    assert refs[0]["path"] == "Child/1"
    assert refs[1]["path"] == "Child/1 > Grandchild/1"


def test_validate_args_rejects_invalid_values() -> None:
    with pytest.raises(RuntimeError, match="timeout"):
        rollup.validate_args(valid_args(timeout=0))

    with pytest.raises(RuntimeError, match="retries"):
        rollup.validate_args(valid_args(retries=-1))

    with pytest.raises(RuntimeError, match="entity-custom-field"):
        rollup.validate_args(
            valid_args(
                require_entity=True,
                entity_custom_field="",
            )
        )


def test_resolve_rollup_input_accepts_existing_csv(
    tmp_path: Path,
) -> None:
    csv_path = tmp_path / "parents.csv"
    csv_path.write_text("header\n", encoding="utf-8")
    args = argparse.Namespace(
        parents_csv=str(csv_path),
        parent_project=None,
        parent_version=None,
        debug=False,
    )

    assert rollup.resolve_rollup_input(args) == "parents-csv"


def test_dedupe_findings_uses_rollup_key() -> None:
    first = {"rollup_key": "one", "value": 1}
    duplicate = {"rollup_key": "one", "value": 2}
    second = {"rollup_key": "two", "value": 3}

    assert rollup.dedupe_findings(
        [first, duplicate, second]
    ) == [first, second]

def test_parallel_collection_preserves_relationship_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = rollup.BlackDuckClient(
        base_url="https://bd.example",
        api_token="token",
    )
    client.bearer_token = "bearer"

    subprojects = [
        {
            "project_name": "Slow",
            "version_name": "1",
            "version_href": "https://bd.example/slow/1",
            "version": {},
            "source": "test",
        },
        {
            "project_name": "Fast",
            "version_name": "1",
            "version_href": "https://bd.example/fast/1",
            "version": {},
            "source": "test",
        },
    ]

    def fake_collect(
        client: Any,
        parent_project: str,
        parent_version: str,
        subproject_ref: dict[str, Any],
        threshold: float,
        score_field: str,
        entity_custom_field: str,
        require_entity: bool,
    ) -> list[dict[str, Any]]:
        del (
            client,
            parent_project,
            parent_version,
            threshold,
            score_field,
            entity_custom_field,
            require_entity,
        )

        if subproject_ref["project_name"] == "Slow":
            time.sleep(0.03)

        return [
            {
                "rollup_key": subproject_ref["project_name"],
            }
        ]

    monkeypatch.setattr(
        rollup,
        "collect_findings_for_subproject",
        fake_collect,
    )

    args = argparse.Namespace(
        debug=False,
        threshold=7.0,
        score_field="overallScore",
        entity_custom_field="foo Entity",
        require_entity=False,
        workers=2,
    )

    findings, failures = rollup.collect_findings_for_subprojects(
        client,
        subprojects,
        args,
        default_parent_project="Parent",
        default_parent_version="1",
    )

    assert failures == []
    assert [
        finding["rollup_key"]
        for finding in findings
    ] == ["Slow", "Fast"]


def test_validate_args_clamps_rollup_workers() -> None:
    args = valid_args(workers=100)

    rollup.validate_args(args)

    assert args.workers == rollup.MAX_IO_WORKERS

