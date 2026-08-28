from __future__ import annotations

import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any


CACHE_SCHEMA_VERSION = 1


class GitLabCapabilityCache:
    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        provider_instance: str,
        denied_ttl_seconds: float = 86400,
    ) -> None:
        if denied_ttl_seconds < 0:
            raise ValueError(
                "denied_ttl_seconds cannot be negative"
            )

        self.path = Path(path).expanduser()
        self.provider_instance = str(
            provider_instance
        ).casefold()
        self.denied_ttl_seconds = float(
            denied_ttl_seconds
        )
        self._lock = threading.RLock()
        self._loaded = False
        self._entries: dict[
            str,
            dict[str, Any],
        ] = {}

    def load(self) -> None:
        with self._lock:
            self._loaded = True
            self._entries = {}

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

            if (
                not isinstance(payload, dict)
                or payload.get("schema_version")
                != CACHE_SCHEMA_VERSION
                or str(
                    payload.get(
                        "provider_instance"
                    )
                    or ""
                ).casefold()
                != self.provider_instance
                or not isinstance(
                    payload.get("entries"),
                    dict,
                )
            ):
                return

            self._entries = dict(
                payload["entries"]
            )

    def denied(
        self,
        project_id: str,
        capability: str,
    ) -> str:
        with self._lock:
            self._ensure_loaded()
            entry = self._entries.get(
                self._key(
                    project_id,
                    capability,
                )
            )

            if not isinstance(entry, dict):
                return ""

            try:
                observed = float(
                    entry["observed_at_epoch"]
                )
            except (
                KeyError,
                TypeError,
                ValueError,
            ):
                return ""

            if (
                self.denied_ttl_seconds >= 0
                and time.time() - observed
                >= self.denied_ttl_seconds
            ):
                return ""

            if entry.get("status") != "denied":
                return ""

            return str(
                entry.get("error") or ""
            )

    def record_denied(
        self,
        project_id: str,
        capability: str,
        error: str,
    ) -> None:
        with self._lock:
            self._ensure_loaded()
            self._entries[
                self._key(
                    project_id,
                    capability,
                )
            ] = {
                "project_id": str(project_id),
                "capability": str(capability),
                "status": "denied",
                "error": str(error),
                "observed_at_epoch": time.time(),
            }

    def clear(
        self,
        project_id: str,
        capability: str,
    ) -> None:
        with self._lock:
            self._ensure_loaded()
            self._entries.pop(
                self._key(
                    project_id,
                    capability,
                ),
                None,
            )

    def save(self) -> None:
        with self._lock:
            self._ensure_loaded()
            self.path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            temporary = self.path.with_name(
                f"{self.path.name}."
                f"{uuid.uuid4().hex}.tmp"
            )
            payload = {
                "schema_version": (
                    CACHE_SCHEMA_VERSION
                ),
                "provider_instance": (
                    self.provider_instance
                ),
                "entries": self._entries,
            }

            try:
                with temporary.open(
                    "w",
                    encoding="utf-8",
                ) as output_file:
                    json.dump(
                        payload,
                        output_file,
                        indent=2,
                        sort_keys=True,
                    )
                    output_file.write("\n")
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

    @staticmethod
    def _key(
        project_id: str,
        capability: str,
    ) -> str:
        return (
            f"{str(project_id).strip()}|"
            f"{str(capability).strip()}"
        )
