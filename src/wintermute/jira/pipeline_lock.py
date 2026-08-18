from __future__ import annotations

import argparse
import json
import os
import re
import signal
import socket
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import FrameType
from typing import Any

from wintermute.paths import ensure_parent_dir, output_root


LOCK_SCHEMA_VERSION = 2
DEFAULT_HEARTBEAT_SECONDS = 30.0
DEFAULT_CLEAR_MIN_AGE_SECONDS = 900


def now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def default_lock_path() -> Path:
    return output_root() / "jira" / "pipeline.lock"


def read_descriptor(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []

    while True:
        chunk = os.read(descriptor, 65536)

        if not chunk:
            break

        chunks.append(chunk)

    return b"".join(chunks)


def write_descriptor(
    descriptor: int,
    payload: dict[str, Any],
) -> None:
    encoded = (
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")

    os.lseek(descriptor, 0, os.SEEK_SET)
    os.ftruncate(descriptor, 0)
    offset = 0

    while offset < len(encoded):
        written = os.write(
            descriptor,
            encoded[offset:],
        )

        if written <= 0:
            raise OSError(
                "Failed writing pipeline lock"
            )

        offset += written

    os.fsync(descriptor)


def parse_lock_payload(
    raw: bytes,
) -> dict[str, Any]:
    try:
        payload = json.loads(
            raw.decode("utf-8")
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ):
        return {
            "invalid": True,
            "raw": raw.decode(
                "utf-8",
                errors="replace",
            )[:4000],
        }

    if not isinstance(payload, dict):
        return {
            "invalid": True,
            "raw": repr(payload)[:4000],
        }

    return payload


@dataclass(frozen=True)
class LockSnapshot:
    path: Path
    exists: bool
    details: dict[str, Any]
    age_seconds: float | None
    device: int | None = None
    inode: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "exists": self.exists,
            "age_seconds": (
                round(self.age_seconds, 3)
                if self.age_seconds is not None
                else None
            ),
            "details": self.details,
        }


def inspect_lock(
    path: str | Path,
) -> LockSnapshot:
    lock_path = Path(path)

    try:
        descriptor = os.open(
            lock_path,
            os.O_RDONLY,
        )
    except FileNotFoundError:
        return LockSnapshot(
            path=lock_path,
            exists=False,
            details={},
            age_seconds=None,
        )

    try:
        status = os.fstat(descriptor)
        details = parse_lock_payload(
            read_descriptor(descriptor)
        )
    finally:
        os.close(descriptor)

    raw_timestamp = (
        details.get("heartbeat_at_epoch")
        or details.get("created_at_epoch")
        or status.st_mtime
    )

    try:
        timestamp = float(raw_timestamp)
    except (TypeError, ValueError):
        timestamp = status.st_mtime

    age_seconds = max(
        0.0,
        time.time() - timestamp,
    )

    return LockSnapshot(
        path=lock_path,
        exists=True,
        details=details,
        age_seconds=age_seconds,
        device=status.st_dev,
        inode=status.st_ino,
    )


def same_file(
    snapshot: LockSnapshot,
) -> bool:
    if (
        not snapshot.exists
        or snapshot.device is None
        or snapshot.inode is None
    ):
        return False

    try:
        current = snapshot.path.stat()
    except FileNotFoundError:
        return False

    return (
        current.st_dev == snapshot.device
        and current.st_ino == snapshot.inode
    )


def safe_label(value: str) -> str:
    normalized = re.sub(
        r"[^A-Za-z0-9._-]+",
        "-",
        str(value or ""),
    ).strip("-")

    return normalized[:80] or "unknown"


def archive_path(
    lock_path: Path,
    run_id: str,
) -> Path:
    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")

    return lock_path.with_name(
        f"{lock_path.name}.stale-"
        f"{timestamp}-"
        f"{safe_label(run_id)}-"
        f"{uuid.uuid4().hex[:8]}"
    )


def archive_lock(
    snapshot: LockSnapshot,
) -> Path:
    if not same_file(snapshot):
        raise RuntimeError(
            "Pipeline lock changed while it was "
            "being inspected; refusing to archive it"
        )

    current = inspect_lock(snapshot.path)

    if (
        not current.exists
        or current.device != snapshot.device
        or current.inode != snapshot.inode
    ):
        raise RuntimeError(
            "Pipeline lock changed while it was "
            "being inspected; refusing to archive it"
        )

    run_id = str(
        current.details.get("run_id")
        or "unknown"
    )
    destination = archive_path(
        current.path,
        run_id,
    )
    os.replace(
        current.path,
        destination,
    )

    return destination


def clear_lock(
    path: str | Path,
    *,
    expected_run_id: str,
    expected_token: str = "",
    minimum_age_seconds: int = (
        DEFAULT_CLEAR_MIN_AGE_SECONDS
    ),
    force: bool = False,
) -> Path | None:
    expected_run_id = str(
        expected_run_id or ""
    ).strip()

    if not expected_run_id:
        raise RuntimeError(
            "An expected run ID is required"
        )

    if minimum_age_seconds < 0:
        raise RuntimeError(
            "minimum_age_seconds cannot be negative"
        )

    snapshot = inspect_lock(path)

    if not snapshot.exists:
        return None

    actual_run_id = str(
        snapshot.details.get("run_id") or ""
    )

    if actual_run_id != expected_run_id:
        raise RuntimeError(
            "Pipeline lock run ID does not match: "
            f"expected {expected_run_id!r}, "
            f"found {actual_run_id!r}"
        )

    if expected_token:
        actual_token = str(
            snapshot.details.get("token") or ""
        )

        if actual_token != expected_token:
            raise RuntimeError(
                "Pipeline lock token does not match"
            )

    age_seconds = float(
        snapshot.age_seconds or 0.0
    )

    if (
        not force
        and age_seconds < minimum_age_seconds
    ):
        raise RuntimeError(
            "Pipeline lock heartbeat is too recent "
            f"to clear safely: age={age_seconds:.1f}s, "
            f"minimum={minimum_age_seconds}s"
        )

    return archive_lock(snapshot)


class PipelineLock:
    def __init__(
        self,
        path: Path,
        run_id: str,
        stale_seconds: int,
        *,
        heartbeat_seconds: float = (
            DEFAULT_HEARTBEAT_SECONDS
        ),
        install_signal_handlers: bool = True,
    ) -> None:
        self.path = Path(path)
        self.run_id = str(run_id)
        self.stale_seconds = int(
            stale_seconds
        )
        self.heartbeat_seconds = float(
            heartbeat_seconds
        )
        self.install_signal_handlers = bool(
            install_signal_handlers
        )
        self.token = uuid.uuid4().hex
        self.acquired = False
        self.stale_archive_path: Path | None = None
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: (
            threading.Thread | None
        ) = None
        self._previous_sigterm: (
            signal.Handlers | None
        ) = None
        self._signal_installed = False

    def lock_held_exception(
        self,
        message: str,
    ) -> BaseException:
        return RuntimeError(message)

    def payload(self) -> dict[str, Any]:
        timestamp = time.time()

        return {
            "schema_version": (
                LOCK_SCHEMA_VERSION
            ),
            "run_id": self.run_id,
            "token": self.token,
            "hostname": socket.gethostname(),
            "pod_name": os.getenv(
                "POD_NAME",
                os.getenv("HOSTNAME", ""),
            ),
            "pod_uid": os.getenv(
                "POD_UID",
                "",
            ),
            "pid": os.getpid(),
            "created_at": now_iso(),
            "created_at_epoch": timestamp,
            "heartbeat_at": now_iso(),
            "heartbeat_at_epoch": timestamp,
        }

    def __enter__(self) -> PipelineLock:
        if self.stale_seconds < 60:
            raise ValueError(
                "stale_seconds must be at least 60"
            )

        if self.heartbeat_seconds <= 0:
            raise ValueError(
                "heartbeat_seconds must be positive"
            )

        ensure_parent_dir(self.path)

        while True:
            existing = inspect_lock(self.path)

            if existing.exists:
                age_seconds = float(
                    existing.age_seconds or 0.0
                )

                if age_seconds <= self.stale_seconds:
                    details = json.dumps(
                        existing.details,
                        sort_keys=True,
                    )
                    message = (
                        "Another Jira pipeline run appears "
                        "active. "
                        f"Heartbeat age: {age_seconds:.1f}s. "
                        f"Lock details: {details}"
                    )
                    raise self.lock_held_exception(
                        message
                    )

                try:
                    self.stale_archive_path = (
                        archive_lock(existing)
                    )
                except FileNotFoundError:
                    continue

            descriptor: int | None = None

            try:
                descriptor = os.open(
                    self.path,
                    (
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                    ),
                    0o600,
                )
            except FileExistsError:
                continue

            try:
                write_descriptor(
                    descriptor,
                    self.payload(),
                )
            except BaseException:
                os.close(descriptor)
                descriptor = None
                self.path.unlink(
                    missing_ok=True
                )
                raise
            finally:
                if descriptor is not None:
                    os.close(descriptor)

            self.acquired = True

            try:
                self._install_sigterm_handler()
                self._start_heartbeat()
            except BaseException:
                self.release()
                raise

            return self

    def _start_heartbeat(self) -> None:
        self._heartbeat_stop.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            name="wintermute-pipeline-lock-heartbeat",
            daemon=True,
        )
        self._heartbeat_thread.start()

    def _heartbeat_loop(self) -> None:
        while not self._heartbeat_stop.wait(
            self.heartbeat_seconds
        ):
            if not self.refresh_heartbeat():
                return

    def refresh_heartbeat(self) -> bool:
        if not self.acquired:
            return False

        try:
            descriptor = os.open(
                self.path,
                os.O_RDWR,
            )
        except FileNotFoundError:
            return False

        try:
            details = parse_lock_payload(
                read_descriptor(descriptor)
            )

            if (
                str(details.get("token") or "")
                != self.token
            ):
                return False

            details["heartbeat_at"] = now_iso()
            details["heartbeat_at_epoch"] = (
                time.time()
            )
            write_descriptor(
                descriptor,
                details,
            )
            return True
        except (
            OSError,
            ValueError,
        ):
            return False
        finally:
            os.close(descriptor)

    def _install_sigterm_handler(
        self,
    ) -> None:
        if (
            not self.install_signal_handlers
            or threading.current_thread()
            is not threading.main_thread()
        ):
            return

        self._previous_sigterm = (
            signal.getsignal(signal.SIGTERM)
        )
        signal.signal(
            signal.SIGTERM,
            self._handle_sigterm,
        )
        self._signal_installed = True

    def _restore_sigterm_handler(
        self,
    ) -> None:
        if (
            not self._signal_installed
            or threading.current_thread()
            is not threading.main_thread()
        ):
            return

        previous = self._previous_sigterm

        if previous is not None:
            signal.signal(
                signal.SIGTERM,
                previous,
            )

        self._signal_installed = False
        self._previous_sigterm = None

    def _handle_sigterm(
        self,
        signum: int,
        frame: FrameType | None,
    ) -> None:
        del frame
        self.release(
            join_heartbeat=False,
            restore_signal=False,
        )

        try:
            os.write(
                2,
                (
                    "Received SIGTERM; released "
                    "the Wintermute pipeline lock.\n"
                ).encode("utf-8"),
            )
        finally:
            os._exit(128 + signum)

    def _unlink_owned_lock(self) -> bool:
        try:
            descriptor = os.open(
                self.path,
                os.O_RDONLY,
            )
        except FileNotFoundError:
            return False

        try:
            status = os.fstat(descriptor)
            details = parse_lock_payload(
                read_descriptor(descriptor)
            )

            if (
                str(details.get("token") or "")
                != self.token
            ):
                return False

            try:
                current = self.path.stat()
            except FileNotFoundError:
                return False

            if (
                current.st_dev != status.st_dev
                or current.st_ino != status.st_ino
            ):
                return False

            self.path.unlink()
            return True
        finally:
            os.close(descriptor)

    def release(
        self,
        *,
        join_heartbeat: bool = True,
        restore_signal: bool = True,
    ) -> None:
        self._heartbeat_stop.set()

        thread = self._heartbeat_thread

        if (
            join_heartbeat
            and thread is not None
            and thread is not threading.current_thread()
        ):
            thread.join(timeout=2.0)

        self._heartbeat_thread = None

        if restore_signal:
            self._restore_sigterm_handler()

        if self.acquired:
            self._unlink_owned_lock()

        self.acquired = False

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        exc_traceback: object,
    ) -> None:
        del exc_type, exc_value, exc_traceback
        self.release()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect or safely archive a Wintermute "
            "Jira pipeline lock."
        )
    )
    parser.add_argument(
        "--lock-path",
        default=str(default_lock_path()),
    )
    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )
    commands.add_parser(
        "inspect",
        help="Show the current lock and heartbeat age.",
    )
    clear = commands.add_parser(
        "clear",
        help=(
            "Archive a stale lock after validating "
            "its run ID."
        ),
    )
    clear.add_argument(
        "--expected-run-id",
        required=True,
    )
    clear.add_argument(
        "--expected-token",
        default="",
    )
    clear.add_argument(
        "--min-age-seconds",
        type=int,
        default=(
            DEFAULT_CLEAR_MIN_AGE_SECONDS
        ),
    )
    clear.add_argument(
        "--force",
        action="store_true",
        help=(
            "Archive a recent lock. Use only after "
            "confirming no pipeline Pod is active."
        ),
    )

    return parser


def main() -> int:
    args = build_parser().parse_args()
    lock_path = Path(args.lock_path)

    try:
        if args.command == "inspect":
            snapshot = inspect_lock(
                lock_path
            )
            print(
                json.dumps(
                    snapshot.as_dict(),
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0

        archived = clear_lock(
            lock_path,
            expected_run_id=(
                args.expected_run_id
            ),
            expected_token=args.expected_token,
            minimum_age_seconds=(
                args.min_age_seconds
            ),
            force=args.force,
        )
        print(
            json.dumps(
                {
                    "lock_path": str(lock_path),
                    "status": (
                        "not-found"
                        if archived is None
                        else "archived"
                    ),
                    "archive_path": (
                        str(archived)
                        if archived is not None
                        else ""
                    ),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except (
        OSError,
        RuntimeError,
        ValueError,
    ) as error:
        print(
            f"ERROR: {error}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
