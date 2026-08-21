from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import threading
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from wintermute.concurrency import SingleFlight
from wintermute.paths import ensure_parent_dir


CACHE_SCHEMA_VERSION = 1
DEFAULT_CHECKPOINT_ENTRIES = 25
DEFAULT_CHECKPOINT_SECONDS = 30.0

CHECKPOINT_ENTRIES_ENV = (
    "WINTERMUTE_BLACKDUCK_CACHE_CHECKPOINT_ENTRIES"
)
CHECKPOINT_SECONDS_ENV = (
    "WINTERMUTE_BLACKDUCK_CACHE_CHECKPOINT_SECONDS"
)


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


def environment_int(
    name: str,
    default: int,
) -> int:
    raw = os.getenv(name, "").strip()

    if not raw:
        return default

    try:
        return int(raw)
    except ValueError as error:
        raise ValueError(
            f"{name} must be an integer"
        ) from error


def environment_float(
    name: str,
    default: float,
) -> float:
    raw = os.getenv(name, "").strip()

    if not raw:
        return default

    try:
        return float(raw)
    except ValueError as error:
        raise ValueError(
            f"{name} must be numeric"
        ) from error


class ApiResponseCache:
    def __init__(
        self,
        path: str,
        base_url: str,
        max_age_hours: float,
        max_entries: int,
        refresh: bool = False,
        debug: bool = False,
        checkpoint_entries: int | None = None,
        checkpoint_seconds: float | None = None,
    ) -> None:
        self.path = path
        self.base_url = base_url.rstrip("/")
        self.max_age_hours = max_age_hours
        self.max_entries = max_entries
        self.debug = debug
        self.checkpoint_entries = (
            environment_int(
                CHECKPOINT_ENTRIES_ENV,
                DEFAULT_CHECKPOINT_ENTRIES,
            )
            if checkpoint_entries is None
            else int(checkpoint_entries)
        )
        self.checkpoint_seconds = (
            environment_float(
                CHECKPOINT_SECONDS_ENV,
                DEFAULT_CHECKPOINT_SECONDS,
            )
            if checkpoint_seconds is None
            else float(checkpoint_seconds)
        )

        if self.checkpoint_entries < 1:
            raise ValueError(
                "Cache checkpoint entry count "
                "must be greater than zero"
            )

        if self.checkpoint_seconds <= 0:
            raise ValueError(
                "Cache checkpoint interval "
                "must be greater than zero"
            )

        self.lock = threading.RLock()
        self._lock = self.lock
        self._singleflight: SingleFlight[
            str,
            list[dict[str, Any]],
        ] = SingleFlight()
        self.data: dict[str, Any] = (
            self._fresh_data()
        )
        self._dirty_entries = 0
        self._checkpoint_stop = (
            threading.Event()
        )
        self._checkpoint_thread: (
            threading.Thread | None
        ) = None

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
        checkpoint_entries: int | None = None,
        checkpoint_seconds: float | None = None,
    ) -> ApiResponseCache:
        return cls(
            path=path,
            base_url=base_url,
            max_age_hours=max_age_hours,
            max_entries=max_entries,
            refresh=refresh,
            debug=debug,
            checkpoint_entries=checkpoint_entries,
            checkpoint_seconds=checkpoint_seconds,
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
            f"Loaded API cache from {self.path} "
            f"with {len(entries)} entrie(s).",
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
            self._dirty_entries += 1
            self.prune_locked()

            if (
                self._dirty_entries
                >= self.checkpoint_entries
            ):
                self._checkpoint_locked(
                    reason="entry-count"
                )
            else:
                self._ensure_checkpoint_thread_locked()

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
        self._stop_checkpoint_thread()

        with self.lock:
            self._write_locked(
                reason="final",
                always=True,
            )

    def _ensure_checkpoint_thread_locked(
        self,
    ) -> None:
        if not self.path:
            return

        if (
            self._checkpoint_thread is not None
            and self._checkpoint_thread.is_alive()
        ):
            return

        self._checkpoint_stop.clear()
        self._checkpoint_thread = (
            threading.Thread(
                target=self._checkpoint_loop,
                name=(
                    "wintermute-api-cache-"
                    "checkpoint"
                ),
                daemon=True,
            )
        )
        self._checkpoint_thread.start()

    def _checkpoint_loop(self) -> None:
        while not self._checkpoint_stop.wait(
            self.checkpoint_seconds
        ):
            with self.lock:
                if self._dirty_entries:
                    self._checkpoint_locked(
                        reason="elapsed-time"
                    )

    def _checkpoint_locked(
        self,
        *,
        reason: str,
    ) -> None:
        try:
            self._write_locked(
                reason=reason,
                always=False,
            )
        except OSError as error:
            print(
                "Warning: failed to checkpoint "
                f"API cache {self.path}: {error}",
                file=sys.stderr,
            )

    def _write_locked(
        self,
        *,
        reason: str,
        always: bool,
    ) -> None:
        if not self.path:
            return

        if (
            not always
            and self._dirty_entries == 0
        ):
            return

        ensure_parent_dir(self.path)
        self.prune_locked()
        self.data["updated_at"] = now_iso()
        settings = self.data.setdefault(
            "settings",
            {},
        )
        settings["max_age_hours"] = (
            self.max_age_hours
        )
        settings["max_entries"] = (
            self.max_entries
        )
        settings["checkpoint_entries"] = (
            self.checkpoint_entries
        )
        settings["checkpoint_seconds"] = (
            self.checkpoint_seconds
        )
        temporary_path = (
            f"{self.path}.tmp-"
            f"{os.getpid()}-"
            f"{uuid.uuid4().hex}"
        )

        try:
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
                output_file.flush()
                os.fsync(
                    output_file.fileno()
                )

            os.replace(
                temporary_path,
                self.path,
            )
        finally:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass

        self._dirty_entries = 0
        entry_count = len(
            self.data.get("entries", {})
        )

        if reason == "final":
            print(
                f"Wrote API cache: {self.path} "
                f"({entry_count} entrie(s)).",
                file=sys.stderr,
            )
        elif self.debug:
            print(
                "Checkpointed API cache: "
                f"{self.path} "
                f"({entry_count} entrie(s), "
                f"reason={reason}).",
                file=sys.stderr,
            )

    def _stop_checkpoint_thread(
        self,
    ) -> None:
        self._checkpoint_stop.set()
        thread = self._checkpoint_thread

        if (
            thread is not None
            and thread
            is not threading.current_thread()
        ):
            thread.join(timeout=2.0)

        self._checkpoint_thread = None

    def _entry_for_url(
        self,
        source_url: str,
    ) -> dict[str, Any] | None:
        entries = self.data.get("entries", {})

        if not isinstance(entries, dict):
            return None

        entry = entries.get(
            self._key_for_url(source_url)
        )

        return (
            entry
            if isinstance(entry, dict)
            else None
        )

    def _is_stale(
        self,
        entry: dict[str, Any],
    ) -> bool:
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
