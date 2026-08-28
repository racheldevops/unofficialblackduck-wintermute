from __future__ import annotations

import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from wintermute.blackduck.actions.models import (
    json_copy,
    stable_digest,
)


CACHE_SCHEMA_VERSION = 1


class JsonCache:
    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        namespace: str,
        identity: dict[str, Any],
    ) -> None:
        self.path = Path(path).expanduser()
        self.namespace = str(namespace)
        self.identity = json_copy(identity)
        self.identity_digest = stable_digest(
            self.identity
        )
        self._lock = threading.RLock()
        self._entries: dict[
            str,
            dict[str, Any],
        ] = {}
        self._loaded = False

    def load(self) -> None:
        with self._lock:
            self._entries = {}
            self._loaded = True

            if not self.path.is_file():
                return

            try:
                payload = json.loads(
                    self.path.read_text(
                        encoding="utf-8"
                    )
                )
            except (
                OSError,
                json.JSONDecodeError,
            ):
                return

            if not isinstance(payload, dict):
                return

            if payload.get(
                "schema_version"
            ) != CACHE_SCHEMA_VERSION:
                return

            if payload.get(
                "namespace"
            ) != self.namespace:
                return

            if payload.get(
                "identity_digest"
            ) != self.identity_digest:
                return

            entries = payload.get("entries")

            if isinstance(entries, dict):
                self._entries = entries

    def get(
        self,
        key: str,
        *,
        max_age_seconds: float = -1,
        current_time: float | None = None,
    ) -> Any | None:
        with self._lock:
            self._ensure_loaded()
            entry = self._entries.get(
                stable_digest(str(key))
            )

            if not isinstance(entry, dict):
                return None

            try:
                stored_at = float(
                    entry["stored_at_epoch"]
                )
            except (
                KeyError,
                TypeError,
                ValueError,
            ):
                return None

            now = (
                time.time()
                if current_time is None
                else current_time
            )

            if (
                max_age_seconds >= 0
                and now - stored_at
                >= max_age_seconds
            ):
                return None

            return json_copy(entry.get("value"))

    def set(
        self,
        key: str,
        value: Any,
        *,
        current_time: float | None = None,
    ) -> None:
        with self._lock:
            self._ensure_loaded()
            self._entries[
                stable_digest(str(key))
            ] = {
                "key": str(key),
                "stored_at_epoch": (
                    time.time()
                    if current_time is None
                    else current_time
                ),
                "value": json_copy(value),
            }

    def remove(self, key: str) -> None:
        with self._lock:
            self._ensure_loaded()
            self._entries.pop(
                stable_digest(str(key)),
                None,
            )

    def prune(
        self,
        *,
        max_entries: int,
    ) -> int:
        if max_entries < 1:
            raise ValueError(
                "max_entries must be greater than zero"
            )

        with self._lock:
            self._ensure_loaded()

            if len(self._entries) <= max_entries:
                return 0

            ordered = sorted(
                self._entries.items(),
                key=lambda item: float(
                    item[1].get(
                        "stored_at_epoch",
                        0,
                    )
                ),
            )
            remove_count = (
                len(ordered) - max_entries
            )

            for key, _ in ordered[
                :remove_count
            ]:
                self._entries.pop(key, None)

            return remove_count

    def save(self) -> None:
        with self._lock:
            self._ensure_loaded()
            payload = {
                "schema_version": (
                    CACHE_SCHEMA_VERSION
                ),
                "namespace": self.namespace,
                "identity": self.identity,
                "identity_digest": (
                    self.identity_digest
                ),
                "entries": self._entries,
            }
            data = (
                json.dumps(
                    payload,
                    allow_nan=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            )
            self.path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            temporary = self.path.with_name(
                f"{self.path.name}."
                f"{uuid.uuid4().hex}.tmp"
            )

            try:
                with temporary.open(
                    "w",
                    encoding="utf-8",
                ) as output_file:
                    output_file.write(data)
                    output_file.flush()
                    os.fsync(
                        output_file.fileno()
                    )

                os.replace(
                    temporary,
                    self.path,
                )
            finally:
                temporary.unlink(
                    missing_ok=True
                )

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load()
