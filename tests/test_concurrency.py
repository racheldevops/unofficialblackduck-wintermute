from __future__ import annotations

import threading
import time

import pytest

from wintermute.concurrency import (
    SingleFlight,
    bounded_worker_count,
    ordered_parallel_map,
)


def test_bounded_worker_count_clamps_to_maximum() -> None:
    assert bounded_worker_count(4, maximum=8) == 4
    assert bounded_worker_count(100, maximum=8) == 8


def test_bounded_worker_count_rejects_zero() -> None:
    with pytest.raises(ValueError, match="greater than zero"):
        bounded_worker_count(0)


def test_ordered_parallel_map_preserves_input_order() -> None:
    def operation(value: int) -> int:
        time.sleep((4 - value) * 0.005)
        return value * 10

    assert ordered_parallel_map(
        [1, 2, 3],
        operation,
        workers=3,
    ) == [10, 20, 30]


def test_singleflight_executes_same_key_once() -> None:
    singleflight: SingleFlight[str, str] = SingleFlight()
    call_count = 0
    lock = threading.Lock()
    barrier = threading.Barrier(4)

    def operation(_: int) -> str:
        barrier.wait()

        def load() -> str:
            nonlocal call_count

            with lock:
                call_count += 1

            time.sleep(0.02)
            return "value"

        return singleflight.run("shared-key", load)

    results = ordered_parallel_map(
        range(4),
        operation,
        workers=4,
    )

    assert results == ["value"] * 4
    assert call_count == 1


def test_singleflight_propagates_loader_error() -> None:
    singleflight: SingleFlight[str, str] = SingleFlight()

    with pytest.raises(RuntimeError, match="failed"):
        singleflight.run(
            "key",
            lambda: (_ for _ in ()).throw(
                RuntimeError("failed")
            ),
        )
