"""Bounded-concurrency parallel runner preserving input order."""

from __future__ import annotations

import concurrent.futures as cf
from typing import Callable, Iterable, TypeVar

T = TypeVar("T")


class ParallelRunner:
    """Thread-pool map with a hard worker cap.

    Threads (not processes) are deliberate: connectors are IO-bound and we
    must share the InvestigationContext safely; mutation policy is handled by
    callers which submit pure work functions returning outcomes.
    """

    def __init__(self, max_workers: int = 4) -> None:
        self.max_workers = max(1, max_workers)

    def map(self, jobs: Iterable[tuple[T, Callable[[], T]]]) -> list:
        job_list = list(jobs)
        if not job_list:
            return []
        results: list = [None] * len(job_list)
        if self.max_workers == 1 or len(job_list) == 1:
            for i, (_, fn) in enumerate(job_list):
                results[i] = fn()
            return results
        with cf.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(fn): i for i, (_, fn) in enumerate(job_list)}
            for fut in cf.as_completed(futures):
                idx = futures[fut]
                results[idx] = fut.result()
        return results
