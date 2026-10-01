"""Optional non-overlapping leaf-span accumulator used by the timing benchmark.

When disabled (the default) the cost is one attribute test per span.  Spans are
leaf spans: they never nest, so their sum is a decomposition of the measured
time into named components plus a residual.
"""

import time
from contextlib import contextmanager

enabled = False
spans = {}
counts = {}


def reset():
    spans.clear()
    counts.clear()


@contextmanager
def span(name):
    if not enabled:
        yield
        return
    t0 = time.monotonic_ns()
    try:
        yield
    finally:
        dt = time.monotonic_ns() - t0
        spans[name] = spans.get(name, 0) + dt
        counts[name] = counts.get(name, 0) + 1
