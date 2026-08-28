from __future__ import annotations

import os
import socket
import time
import uuid
from pathlib import Path

from wintermute.jira.pipeline_lock import (
    DEFAULT_HEARTBEAT_SECONDS,
    PipelineLock,
    archive_lock,
    inspect_lock,
)


class LockUnavailableError(RuntimeError):
    pass


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True

    return True


class FileLock(PipelineLock):
    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        stale_seconds: float = 7200,
        wait_seconds: float = 0,
        poll_seconds: float = 1,
        heartbeat_seconds: float = (
            DEFAULT_HEARTBEAT_SECONDS
        ),
        install_signal_handlers: bool = True,
    ) -> None:
        if stale_seconds <= 0:
            raise ValueError(
                "stale_seconds must be positive"
            )

        if wait_seconds < 0:
            raise ValueError(
                "wait_seconds cannot be negative"
            )

        if poll_seconds <= 0:
            raise ValueError(
                "poll_seconds must be positive"
            )

        self.wait_seconds = float(wait_seconds)
        self.poll_seconds = float(poll_seconds)

        super().__init__(
            Path(path),
            (
                f"file-lock-{os.getpid()}-"
                f"{uuid.uuid4().hex[:12]}"
            ),
            max(60, int(stale_seconds)),
            heartbeat_seconds=(
                heartbeat_seconds
            ),
            install_signal_handlers=(
                install_signal_handlers
            ),
        )

    def lock_held_exception(
        self,
        message: str,
    ) -> BaseException:
        del message

        return LockUnavailableError(
            f"Lock is active: {self.path}"
        )

    def _archive_dead_local_owner(self) -> bool:
        snapshot = inspect_lock(self.path)

        if not snapshot.exists:
            return False

        details = snapshot.details
        hostname = str(
            details.get("hostname")
            or details.get("host")
            or ""
        )

        if hostname != socket.gethostname():
            return False

        try:
            pid = int(details.get("pid"))
        except (
            TypeError,
            ValueError,
        ):
            return False

        if pid < 1 or _process_exists(pid):
            return False

        try:
            self.stale_archive_path = (
                archive_lock(snapshot)
            )
        except FileNotFoundError:
            return True

        return True

    def acquire(self) -> None:
        if self.acquired:
            return

        deadline = (
            time.monotonic()
            + self.wait_seconds
        )

        while True:
            self._archive_dead_local_owner()

            try:
                super().__enter__()
                return
            except LockUnavailableError:
                if time.monotonic() >= deadline:
                    raise

                time.sleep(self.poll_seconds)

    def __enter__(self) -> FileLock:
        self.acquire()
        return self


__all__ = [
    "FileLock",
    "LockUnavailableError",
]
