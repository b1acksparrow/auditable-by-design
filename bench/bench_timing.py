"""Creation-cost decomposition for one complete governed transaction.

Protocol: 300 warm-up + 200 timed repetitions, each repetition one full
transaction (observe, propose, gate, authorize, execute with durable journal
and ML-KEM-768 operation, independent outcome observation, envelope, checkpoint).
Leaf spans are non-overlapping: sign, verify (executor checks the authorization
signature), canonical, hash, hex, kem, sqlite.  The residual is everything
else.  A second, uninstrumented block measures the same operation with spans
disabled.  Per-sample values are retained.

Warm-up length: a freshly created SQLite database in WAL mode appends every
commit to a growing WAL file until the first automatic checkpoint (default
1000 pages, reached after roughly 130 transactions of this fixture); after
that the WAL is rewritten in place.  On the measured ext4/NVMe host whole
transactions in the growth phase are several times slower (the ratio is
reported as cold_start_first_warmup_tx; bench/bench_wal.py tests the cause).  The warm-up
therefore runs past the first checkpoint so that the timed samples describe
the steady state; warm-up totals are retained to report the cold start.
"""

import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from abd import instrument  # noqa: E402
from abd.fixture import ASSET, HYBRID, PQC, READY_ENDPOINTS, make_store, make_system  # noqa: E402
from abd import state as _state  # noqa: E402

WARMUP = 300
TIMED = 200
COLD_START_TX = 100   # warm-up transactions reported as the cold-start regime (all precede the first checkpoint)
SPANS = ['sign', 'verify', 'canonical', 'hash', 'hex', 'kem', 'sqlite']


def _wrap_sqlite():
    """Attribute store transactions to a 'sqlite' leaf span."""
    orig = _state.ManagedStateStore._tx

    def wrapped(self):
        from contextlib import contextmanager

        @contextmanager
        def cm():
            t0 = time.monotonic_ns() if instrument.enabled else 0
            with orig(self) as c:
                yield c
            if instrument.enabled:
                dt = time.monotonic_ns() - t0
                instrument.spans['sqlite'] = instrument.spans.get('sqlite', 0) + dt
                instrument.counts['sqlite'] = instrument.counts.get('sqlite', 0) + 1
        return cm()
    _state.ManagedStateStore._tx = wrapped


def percentile(data, p):
    s = sorted(data)
    k = (len(s) - 1) * p / 100
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (k - f) * (s[c] - s[f])


def one_transaction(system, i):
    # alternate targets so that every transaction is a real configuration change
    target = HYBRID if system.store.read_asset(ASSET)['config']['profile_id'] != HYBRID else PQC
    tx = system.run(ASSET, target, endpoints=READY_ENDPOINTS)
    assert tx.status == 'closed', tx.error
    return tx


def run_block(instrumented: bool, outdir: str, durable: bool = True):
    from abd.state import ManagedStateStore
    name = f'state-{"inst" if instrumented else "uninst"}-{"durable" if durable else "nosync"}.sqlite'
    path = os.path.join(outdir, name)
    if os.path.exists(path):
        os.remove(path)
    store = make_store(path) if durable else None
    if store is None:
        # same fixture content, non-durable store (benchmark-only configuration)
        from abd.fixture import make_store as _ms
        import abd.fixture as fx
        orig = fx.ManagedStateStore
        fx.ManagedStateStore = lambda p: ManagedStateStore(p, durable=False)
        try:
            store = _ms(path)
        finally:
            fx.ManagedStateStore = orig
    system = make_system(store=store)
    wal_autocheckpoint = store._conn.execute('PRAGMA wal_autocheckpoint').fetchone()[0]
    samples, warmup_totals = [], []
    for i in range(WARMUP + TIMED):
        instrument.reset()
        instrument.enabled = instrumented
        t0 = time.monotonic_ns()
        one_transaction(system, i)
        total = time.monotonic_ns() - t0
        instrument.enabled = False
        if i < WARMUP:
            warmup_totals.append(total)
            continue
        s = {'total_ns': total}
        if instrumented:
            for name in SPANS:
                s[name + '_ns'] = instrument.spans.get(name, 0)
                s[name + '_calls'] = instrument.counts.get(name, 0)
            s['residual_ns'] = total - sum(instrument.spans.get(n, 0) for n in SPANS)
        samples.append(s)
    store.close()
    record_bytes = len(json.dumps(system.records[-1]).encode('utf-8'))
    return samples, record_bytes, warmup_totals, wal_autocheckpoint


def summarise(samples, keys):
    out = {}
    for k in keys:
        vals = [s[k + '_ns'] for s in samples]
        out[k] = {'median_ms': statistics.median(vals) / 1e6, 'p95_ms': percentile(vals, 95) / 1e6,
                  'calls_per_tx': samples[0].get(k + '_calls')}
    return out


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    import envinfo
    conditions = envinfo.collect(wait_quiet=True)['run_conditions']
    _wrap_sqlite()
    inst, record_bytes, inst_warm, wal_ckpt = run_block(True, outdir, durable=True)
    uninst, _, uninst_warm, _ = run_block(False, outdir, durable=True)
    inst_nosync, _, nosync_warm, _ = run_block(True, outdir, durable=False)
    keys = SPANS + ['residual', 'total']

    def cold(warm):
        first = warm[:COLD_START_TX]
        return {'transactions': len(first), 'median_ms': statistics.median(first) / 1e6,
                'p95_ms': percentile(first, 95) / 1e6}

    def block(samples):
        summary = summarise(samples, keys)
        med_total = summary['total']['median_ms']
        for k in keys:
            summary[k]['share_of_median_total_pct'] = round(100 * summary[k]['median_ms'] / med_total, 1)
        return summary

    un_vals = [s['total_ns'] for s in uninst]
    result = {
        'protocol': f'{WARMUP} warm-up + {TIMED} timed full transactions per block; blocks run separately',
        'signatures_per_tx': 6,
        'sqlite_commits_per_tx': 3,
        'record_bytes_json': record_bytes,
        'wal_autocheckpoint_pages': wal_ckpt,
        'run_conditions': conditions,
        'instrumented_durable': block(inst),
        'uninstrumented_durable_total': {'median_ms': statistics.median(un_vals) / 1e6,
                                         'p95_ms': percentile(un_vals, 95) / 1e6},
        'instrumented_nosync': block(inst_nosync),
        'cold_start_first_warmup_tx': {'instrumented_durable': cold(inst_warm),
                                       'uninstrumented_durable': cold(uninst_warm),
                                       'instrumented_nosync': cold(nosync_warm)},
        'note': 'sqlite span covers the three durable commits per transaction (prepare, apply, receipted) with '
                'synchronous=FULL in the durable blocks and synchronous=OFF in the nosync block; the durable '
                'instrumented and uninstrumented blocks differ in work performed and their difference is not an '
                'instrumentation-overhead estimate',
    }
    with open(os.path.join(outdir, 'timing_summary.json'), 'w') as fh:
        json.dump(result, fh, indent=2)
    with open(os.path.join(outdir, 'timing_raw_samples.json'), 'w') as fh:
        json.dump({'instrumented_durable': inst, 'uninstrumented_durable': uninst,
                   'instrumented_nosync': inst_nosync,
                   'warmup_totals_ns': {'instrumented_durable': inst_warm, 'uninstrumented_durable': uninst_warm,
                                        'instrumented_nosync': nosync_warm}}, fh)
    print(json.dumps(result, indent=2))
    return result


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'results', 'v2'))
