from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from wintermute.concurrency import SingleFlight
from wintermute.paths import ensure_parent_dir


CACHE_SCHEMA_VERSION = 1


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )
    except ValueError:
        return None


class ApiResponseCache:
    def __init__(
        self,
        path: str,
        base_url: str,
        max_age_hours: float,
        max_entries: int,
        refresh: bool = False,
        debug: bool = False,
    ):
        self.path = path
        self.base_url = base_url.rstrip("/")
        self.max_age_hours = max_age_hours
        self.max_entries = max_entries
        self.debug = debug
        self.lock = threading.RLock()
        self._lock = self.lock
        self._singleflight: SingleFlight[
            str,
            list[dict[str, Any]],
        ] = SingleFlight()
        self.data: dict[str, Any] = self._fresh_data()

        if refresh:
            print(
                f"Refreshing API cache; ignoring existing cache at "
                f"{path}.",
                file=sys.stderr,
            )
            return

        self._load_existing()

    @classmethod
    def load(
        cls,
        path: str,
        base_url: str,
        max_age_hours: float,
        refresh: bool,
        max_entries: int,
        debug: bool,
    ) -> ApiResponseCache:
        return cls(
            path=path,
            base_url=base_url,
            max_age_hours=max_age_hours,
            max_entries=max_entries,
            refresh=refresh,
            debug=debug,
        )

    def _fresh_data(self) -> dict[str, Any]:
        timestamp = now_iso()

        return {
            "schema_version": CACHE_SCHEMA_VERSION,
            "base_url": self.base_url,
            "created_at": timestamp,
            "updated_at": timestamp,
            "settings": {
                "max_age_hours": self.max_age_hours,
                "max_entries": self.max_entries,
            },
            "entries": {},
        }

    def _load_existing(self) -> None:
        if not self.path or not os.path.exists(self.path):
            print(
                f"No API cache found at {self.path}; "
                "fresh API reads required.",
                file=sys.stderr,
            )
            return

        try:
            with open(self.path, encoding="utf-8") as input_file:
                loaded = json.load(input_file)
        except (OSError, json.JSONDecodeError) as error:
            print(
                f"Warning: failed to read API cache "
                f"{self.path}: {error}; fresh API reads required.",
                file=sys.stderr,
            )
            return

        if not isinstance(loaded, dict):
            print(
                f"API cache {self.path} is not an object; "
                "fresh API reads required.",
                file=sys.stderr,
            )
            return

        if loaded.get("schema_version") != CACHE_SCHEMA_VERSION:
            print(
                f"API cache schema mismatch in {self.path}; "
                "fresh API reads required.",
                file=sys.stderr,
            )
            return

        if (
            str(loaded.get("base_url") or "").rstrip("/")
            != self.base_url
        ):
            print(
                "API cache base URL differs from current Black Duck "
                "URL; fresh API reads required.",
                file=sys.stderr,
            )
            return

        entries = loaded.get("entries")

        if not isinstance(entries, dict):
            print(
                f"API cache entries are invalid in {self.path}; "
                "fresh API reads required.",
                file=sys.stderr,
            )
            return

        loaded.setdefault("settings", {})
        self.data = loaded
        self.prune()

        print(
            f"Loaded API cache from {self.path} with "
            f"{len(self.data.get('entries', {}))} entrie(s).",
            file=sys.stderr,
        )

    def get_items(
        self,
        source_url: str,
    ) -> list[dict[str, Any]] | None:
        with self.lock:
            entry = self._entry_for_url(source_url)

            if entry is None or self._is_stale(entry):
                return None

            items = entry.get("items")

            if not isinstance(items, list):
                return None

            entry["last_used_at"] = now_iso()
            entry["hit_count"] = (
                int(entry.get("hit_count") or 0) + 1
            )

            if self.debug:
                print(
                    f"Reusing API cache: {source_url} "
                    f"({len(items)} cached item(s), "
                    f"age={self._age_label(entry)})",
                    file=sys.stderr,
                )

            return copy.deepcopy(items)

    def get_or_load_items(
        self,
        source_url: str,
        loader: Callable[
            [],
            tuple[list[dict[str, Any]], int | None],
        ],
    ) -> list[dict[str, Any]]:
        cached = self.get_items(source_url)

        if cached is not None:
            return cached

        def load_once() -> list[dict[str, Any]]:
            cached_after_wait = self.get_items(source_url)

            if cached_after_wait is not None:
                return cached_after_wait

            items, total_count = loader()
            self.put_items(
                source_url,
                items,
                total_count=total_count,
            )
            return copy.deepcopy(items)

        return copy.deepcopy(
            self._singleflight.run(source_url, load_once)
        )

    def put_items(
        self,
        source_url: str,
        items: list[dict[str, Any]],
        total_count: int | None = None,
    ) -> None:
        with self.lock:
            timestamp = now_iso()
            entries = self.data.setdefault("entries", {})
            entries[self._key_for_url(source_url)] = {
                "source_url": source_url,
                "cached_at": timestamp,
                "last_used_at": timestamp,
                "hit_count": 0,
                "item_count": len(items),
                "total_count": total_count,
                "items": copy.deepcopy(items),
            }
            self.prune_locked()

    def prune(self) -> None:
        with self.lock:
            self.prune_locked()

    def prune_locked(self) -> None:
        entries = self.data.setdefault("entries", {})
        stale_keys = [
            key
            for key, entry in entries.items()
            if (
                not isinstance(entry, dict)
                or self._is_stale(entry)
            )
        ]

        for key in stale_keys:
            entries.pop(key, None)

        if len(entries) <= self.max_entries:
            return

        remove_count = len(entries) - self.max_entries
        remove_keys = sorted(
            entries,
            key=lambda key: str(
                (entries.get(key) or {}).get("last_used_at")
                or (entries.get(key) or {}).get("cached_at")
                or ""
            ),
        )[:remove_count]

        for key in remove_keys:
            entries.pop(key, None)

    def save(self) -> None:
        if not self.path:
            return

        ensure_parent_dir(self.path)

        with self.lock:
            self.prune_locked()
            self.data["updated_at"] = now_iso()
            settings = self.data.setdefault("settings", {})
            settings["max_age_hours"] = self.max_age_hours
            settings["max_entries"] = self.max_entries
            temporary_path = f"{self.path}.tmp"

            with open(
                temporary_path,
                "w",
                encoding="utf-8",
            ) as output_file:
                json.dump(
                    self.data,
                    output_file,
                    indent=2,
                    sort_keys=True,
                )

            os.replace(temporary_path, self.path)
            entry_count = len(
                self.data.get("entries", {})
            )

        print(
            f"Wrote API cache: {self.path} "
            f"({entry_count} entrie(s)).",
            file=sys.stderr,
        )

    def _entry_for_url(
        self,
        source_url: str,
    ) -> dict[str, Any] | None:
        entries = self.data.get("entries", {})

        if not isinstance(entries, dict):
            return None

        entry = entries.get(self._key_for_url(source_url))
        return entry if isinstance(entry, dict) else None

    def _is_stale(self, entry: dict[str, Any]) -> bool:
        if self.max_age_hours < 0:
            return False

        cached_at = parse_iso(
            str(entry.get("cached_at") or "")
        )

        if cached_at is None:
            return True

        age_hours = (
            datetime.now(timezone.utc) - cached_at
        ).total_seconds() / 3600

        return age_hours >= self.max_age_hours

    def _age_label(self, entry: dict[str, Any]) -> str:
        cached_at = parse_iso(
            str(entry.get("cached_at") or "")
        )

        if cached_at is None:
            return "unknown"

        age_seconds = (
            datetime.now(timezone.utc) - cached_at
        ).total_seconds()

        if age_seconds < 60:
            return f"{age_seconds:.0f}s"

        if age_seconds < 3600:
            return f"{age_seconds / 60:.1f}m"

        return f"{age_seconds / 3600:.1f}h"

    @staticmethod
    def _key_for_url(source_url: str) -> str:
        return hashlib.sha256(
            source_url.encode("utf-8")
        ).hexdigest()
