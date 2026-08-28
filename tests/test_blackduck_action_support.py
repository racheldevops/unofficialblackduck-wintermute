from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from wintermute.blackduck.actions.cache import (
    JsonCache,
)
from wintermute.blackduck.actions.executor import (
    ActionReceipt,
    ExecutionResult,
)
from wintermute.blackduck.actions.lock import (
    FileLock,
    LockUnavailableError,
)
from wintermute.blackduck.actions.results import (
    ActionResultError,
    load_verified_execution_result,
    write_execution_result,
)
from wintermute.blackduck.jobs.cip.config import (
    load_cip_configuration,
)


BASE_URL = "https://blackduck.example.invalid"


def test_cache_round_trip_and_identity(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cache.json"
    cache = JsonCache(
        path,
        namespace="cip",
        identity={"revision": "one"},
    )
    cache.set(
        "CVE-2026-0001",
        {"fixed": True},
        current_time=100,
    )
    cache.save()

    loaded = JsonCache(
        path,
        namespace="cip",
        identity={"revision": "one"},
    )

    assert loaded.get(
        "CVE-2026-0001",
        max_age_seconds=10,
        current_time=105,
    ) == {"fixed": True}

    changed = JsonCache(
        path,
        namespace="cip",
        identity={"revision": "two"},
    )

    assert changed.get(
        "CVE-2026-0001"
    ) is None


def test_cache_expiration(
    tmp_path: Path,
) -> None:
    cache = JsonCache(
        tmp_path / "cache.json",
        namespace="cip",
        identity={},
    )
    cache.set(
        "key",
        {"value": 1},
        current_time=100,
    )

    assert cache.get(
        "key",
        max_age_seconds=10,
        current_time=110,
    ) is None


def test_file_lock_excludes_second_owner(
    tmp_path: Path,
) -> None:
    path = tmp_path / "job.lock"
    first = FileLock(path)
    second = FileLock(path)

    first.acquire()

    try:
        with pytest.raises(
            LockUnavailableError
        ):
            second.acquire()
    finally:
        first.release()

    second.acquire()
    second.release()


def test_file_lock_removes_stale_lock(
    tmp_path: Path,
) -> None:
    path = tmp_path / "job.lock"
    path.write_text(
        json.dumps(
            {
                "created_at_epoch": (
                    time.time() - 100
                )
            }
        ),
        encoding="utf-8",
    )
    lock = FileLock(
        path,
        stale_seconds=1,
    )
    lock.acquire()
    lock.release()

    assert not path.exists()


def execution_result() -> ExecutionResult:
    receipt = ActionReceipt(
        action_id="sha256:" + "a" * 64,
        kind="resource.set",
        outcome="planned",
        started_at="2026-08-26T12:00:00Z",
        completed_at="2026-08-26T12:00:01Z",
        reads=1,
        writes=0,
        before={"value": "old"},
        after={},
        detail="",
        error="",
    )

    return ExecutionResult(
        schema_version=1,
        execution_id=(
            "20260826T120001Z-"
            "123456789abc"
        ),
        plan_id="plan",
        plan_digest="sha256:" + "b" * 64,
        producer="test-producer",
        blackduck_base_url=BASE_URL,
        mode="dry-run",
        started_at="2026-08-26T12:00:00Z",
        completed_at="2026-08-26T12:00:01Z",
        reads=1,
        writes=0,
        receipts=(receipt,),
    )


def test_execution_result_round_trip(
    tmp_path: Path,
) -> None:
    result = execution_result()
    path = write_execution_result(
        tmp_path,
        result,
    )

    assert (
        load_verified_execution_result(path)
        == result
    )


def test_modified_execution_result_fails(
    tmp_path: Path,
) -> None:
    path = write_execution_result(
        tmp_path,
        execution_result(),
    )
    result_path = path / "result.json"
    payload: dict[str, Any] = json.loads(
        result_path.read_text(
            encoding="utf-8"
        )
    )
    payload["writes"] = 10
    result_path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    with pytest.raises(
        ActionResultError,
        match="checksum mismatch",
    ):
        load_verified_execution_result(
            path
        )


def test_cip_configuration(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cip.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "blackduck_base_url": (
                    BASE_URL
                ),
                "kernel_repository": {
                    "location": (
                        "https://git.example.invalid/"
                        "cip/linux-cip.git"
                    ),
                    "revision": (
                        "v6.1.173-cip56"
                    ),
                },
                "security_repository": {
                    "location": (
                        "https://git.example.invalid/"
                        "cip/cip-kernel-sec.git"
                    ),
                    "revision": "main",
                },
                "targets": [
                    {
                        "project_version_href": (
                            f"{BASE_URL}/api/projects/p"
                            "/versions/v"
                        ),
                        "component_version_href": (
                            f"{BASE_URL}/api/components/c"
                            "/versions/cv"
                        ),
                        "cip_tag": (
                            "v6.1.173-cip56"
                        ),
                        "cip_branch": (
                            "linux-6.1.y-cip"
                        ),
                    }
                ],
                "remediation": {
                    "desired_status": "PATCHED",
                    "preserve_existing_decisions": (
                        True
                    ),
                },
                "execution": {
                    "read_workers": 2,
                    "evidence_workers": 4,
                    "plan_lifetime_hours": 24,
                    "limits": {
                        "maximum_actions": 10,
                        "maximum_blackduck_reads": (
                            100
                        ),
                        "maximum_blackduck_writes": (
                            10
                        ),
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    configuration = (
        load_cip_configuration(path)
    )

    assert configuration.targets[
        0
    ].cip_tag == "v6.1.173-cip56"
    assert (
        configuration.desired_status
        == "PATCHED"
    )
