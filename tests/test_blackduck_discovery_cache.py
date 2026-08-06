from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from wintermute.blackduck import discovery_cache


@dataclass(frozen=True)
class Version:
    project_name: str = "Parent"
    version_name: str = "1"
    project_href: str = (
        "https://bd.example/projects/parent"
    )
    version_href: str = (
        "https://bd.example/projects/parent/"
        "versions/1"
    )
    phase: str = "RELEASED"
    updated: str = (
        "2026-08-01T00:00:00Z"
    )
    created: str = (
        "2026-01-01T00:00:00Z"
    )

    def signature(self) -> str:
        return json.dumps(
            {
                "project_name": self.project_name,
                "version_name": self.version_name,
                "project_href": self.project_href,
                "version_href": self.version_href,
                "phase": self.phase,
                "updated": self.updated,
                "created": self.created,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def relation() -> dict[str, str]:
    return {
        "parent_project": "Parent",
        "parent_version": "1",
        "parent_version_href": (
            "https://bd.example/projects/parent/"
            "versions/1"
        ),
        "child_project": "Child",
        "child_version": "2",
        "child_version_href": (
            "https://bd.example/projects/child/"
            "versions/2"
        ),
    }


def test_shared_cache_round_trip(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cache.json"
    cache = discovery_cache.new_cache(
        "https://bd.example",
        True,
    )
    cache["entries"]["item"] = {
        "status": "ok"
    }
    discovery_cache.save_cache(
        str(path),
        cache,
    )

    loaded = discovery_cache.load_cache(
        str(path),
        "https://bd.example",
        True,
    )

    assert loaded["entries"]["item"] == {
        "status": "ok"
    }


def test_shared_cache_plans_reuse() -> None:
    version = Version()
    cache = discovery_cache.new_cache(
        "https://bd.example",
        False,
    )
    cache["entries"][version.version_href] = {
        "signature": version.signature(),
        "status": "ok",
        "scanned_at": (
            datetime.now(timezone.utc)
            .isoformat()
        ),
        "relations": [],
    }

    planned, reused = (
        discovery_cache.plan_scan(
            cache,
            [version],
            refresh_all=False,
            refresh_failed=True,
            refresh_older_than_days=7,
            trust_cache_without_update_marker=False,
        )
    )

    assert planned == []
    assert reused == 1
    assert (
        cache["entries"][version.version_href][
            "reuse_reason"
        ]
        == "unchanged-cache-hit"
    )


def test_failed_scan_retains_previous_relationships() -> None:
    version = Version()
    cache = discovery_cache.new_cache(
        "https://bd.example",
        False,
    )
    cache["entries"][version.version_href] = {
        "relations": [relation()]
    }

    discovery_cache.update_cache_with_scan_results(
        cache,
        [
            (
                version,
                "previous-scan-failed",
                [],
                "temporary failure",
            )
        ],
    )

    entry = cache["entries"][
        version.version_href
    ]
    assert entry["status"] == "failed"
    assert entry["relations"] == [relation()]


def test_successful_scan_replaces_relationships() -> None:
    version = Version()
    cache = discovery_cache.new_cache(
        "https://bd.example",
        False,
    )
    cache["entries"][version.version_href] = {
        "relations": []
    }

    discovery_cache.update_cache_with_scan_results(
        cache,
        [
            (
                version,
                "new-version",
                [relation()],
                None,
            )
        ],
    )

    entry = cache["entries"][
        version.version_href
    ]
    assert entry["status"] == "ok"
    assert entry["relations"] == [relation()]
