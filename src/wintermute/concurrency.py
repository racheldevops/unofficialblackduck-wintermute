from __future__ import annotations

from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor
from threading import Lock
from typing import Generic, TypeVar


DEFAULT_IO_WORKERS = 4
MAX_IO_WORKERS = 8
MAX_COMPONENT_WORKERS = 16

ItemT = TypeVar("ItemT")
ResultT = TypeVar("ResultT")
KeyT = TypeVar("KeyT")


def bounded_worker_count(
    requested: int,
    *,
    maximum: int = MAX_IO_WORKERS,
) -> int:
    requested = int(requested)
    maximum = int(maximum)

    if requested < 1:
        raise ValueError("Worker count must be greater than zero")

    if maximum < 1:
        raise ValueError("Maximum worker count must be greater than zero")

    return min(requested, maximum)


def ordered_parallel_map(
    items: Iterable[ItemT],
    operation: Callable[[ItemT], ResultT],
    *,
    workers: int,
    maximum: int = MAX_IO_WORKERS,
) -> list[ResultT]:
    values = list(items)

    if not values:
        return []

    worker_count = min(
        bounded_worker_count(workers, maximum=maximum),
        len(values),
    )

    if worker_count == 1:
        return [operation(value) for value in values]

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        return list(executor.map(operation, values))


class SingleFlight(Generic[KeyT, ResultT]):
    def __init__(self) -> None:
        self._lock = Lock()
        self._pending: dict[KeyT, Future[ResultT]] = {}

    def run(
        self,
        key: KeyT,
        operation: Callable[[], ResultT],
    ) -> ResultT:
        with self._lock:
            future = self._pending.get(key)
            leader = future is None

            if future is None:
                future = Future()
                self._pending[key] = future

        if not leader:
            return future.result()

        try:
            result = operation()
        except BaseException as error:
            future.set_exception(error)
            raise
        else:
            future.set_result(result)
            return result
        finally:
            with self._lock:
                if self._pending.get(key) is future:
                    self._pending.pop(key, None)
