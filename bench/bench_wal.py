"""Causal test of the WAL cold-start effect in the creation-cost benchmark.

A new SQLite database in WAL mode appends every commit to a growing WAL file
until the first automatic checkpoint; afterwards the WAL is rewritten in place.
If the slow start is caused by that growth phase, the transaction at which the
durable cost drops must move with PRAGMA wal_autocheckpoint.  This driver runs
the creation-cost transaction on fresh durable stores with several thresholds
and records, per threshold, the first steady-state transaction and the median
cost before and after it.

Usage: python3 bench/bench_wal.py OUTDIR [TRANSACTIONS]
"""

import json
import os
import statistics
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from abd import state  # noqa: E402
from abd.fixture import ASSET, HYBRID, PQC, READY_ENDPOINTS, make_store, make_system  # noqa: E402
import envinfo  # noqa: E402

THRESHOLDS = [250, 1000, 4000]


def first_steady(totals_ms, window=20, factor=0.5):
    """First index after which a window of transactions stays below factor x the opening median."""
    opening = statistics.median(totals_ms[:10])
    for i in range(len(totals_ms) - window):
        if statistics.median(totals_ms[i:i + window]) < factor * opening:
            return i
    return None


def run(threshold, n, workdir):
    orig_init = state.ManagedStateStore.__init__

    def init(self, path, durable=True):
        orig_init(self, path, durable)
        self._conn.execute(f'PRAGMA wal_autocheckpoint={threshold}')
    state.ManagedStateStore.__init__ = init
    try:
        store = make_store(os.path.join(workdir, f'wal-{threshold}.sqlite'))
    finally:
        state.ManagedStateStore.__init__ = orig_init
    system = make_system(store=store)
    totals = []
    for _ in range(n):
        target = HYBRID if system.store.read_asset(ASSET)['config']['profile_id'] != HYBRID else PQC
        t0 = time.monotonic_ns()
        system.run(ASSET, target, endpoints=READY_ENDPOINTS)
        totals.append((time.monotonic_ns() - t0) / 1e6)
    store.close()
    k = first_steady(totals)
    return {'wal_autocheckpoint_pages': threshold, 'transactions': n, 'first_steady_tx': k,
            'median_before_ms': statistics.median(totals[:k]) if k else None,
            'median_after_ms': statistics.median(totals[k:]) if k is not None else None,
            'totals_ms': totals}


def main(outdir, n=620):
    os.makedirs(outdir, exist_ok=True)
    env = envinfo.collect(wait_quiet=True)
    workdir = tempfile.mkdtemp(prefix='abd-wal-', dir=outdir)
    rows = [run(t, n, workdir) for t in THRESHOLDS]
    for r in rows:
        print(f"wal_autocheckpoint={r['wal_autocheckpoint_pages']:>5}: steady from tx {r['first_steady_tx']}, "
              f"median {r['median_before_ms']:.1f} ms -> {r['median_after_ms']:.1f} ms")
    with open(os.path.join(outdir, 'wal_results.json'), 'w') as fh:
        json.dump({'environment': env, 'results': rows}, fh, indent=1)
    for f in os.listdir(workdir):
        os.remove(os.path.join(workdir, f))
    os.rmdir(workdir)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'results', 'v2', 'wal'),
         int(sys.argv[2]) if len(sys.argv) > 2 else 620)
