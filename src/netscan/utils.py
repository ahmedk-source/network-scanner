"""Small, dependency-free helpers shared by the rest of the package."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import Executor, Future
from typing import TypeVar

T = TypeVar("T")
R = TypeVar("R")


def windowed_map(
    executor: Executor,
    function: Callable[[T], R],
    items: Iterable[T],
    *,
    window: int,
) -> Iterator[R]:
    """Apply *function* to every item with at most *window* tasks in flight.

    ``concurrent.futures.Executor.map`` submits the whole input eagerly, which
    is a problem for a /24 host scan where thousands of raw sockets would be
    queued at once.  This helper keeps the queue bounded and yields results in
    submission order.  A slow item can therefore hold back the items behind it,
    which is an accepted trade-off: the window is several times larger than the
    worker count, so the pipeline stays full in practice.
    """
    if window < 1:
        raise ValueError("window must be at least 1")
    pending: deque[Future[R]] = deque()
    for item in items:
        if len(pending) >= window:
            yield pending.popleft().result()
        pending.append(executor.submit(function, item))
    while pending:
        yield pending.popleft().result()
