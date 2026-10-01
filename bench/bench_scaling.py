"""Archive checking at scale with the streaming semantic verifier.

For each size the archive is built once as a JSON Lines file (one record per
line) by the full transaction pipeline, with the retained checkpoint and the
trust configuration written as separate artifacts.  Verification is then timed:

  streaming : reads the file line by line; timer includes file I/O and JSON
              decoding; verifier memory grows linearly with the number of
              transactions (retained identifiers and authorization digests),
              not with record size.
  in_memory : the archive is pre-decoded into a Python list and only the
              verifier is timed (like-for-like with the earlier fixture).
              Omitted at 100,000 to avoid the multi-GiB resident list.

Peak RSS is measured in a *fresh subprocess* that performs one streaming
verification (ru_maxrss of the child), so it is not contaminated by archive
construction.  Per-repetition samples are retained.
"""

import json
import os
import resource
import statistics
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from abd import crypto  # noqa: E402
from abd.fixture import HYBRID, PQC, READY_ENDPOINTS, make_store, make_system  # noqa: E402
from abd.roles import TestClock  # noqa: E402
from abd.transaction import JsonlArchiveWriter  # noqa: E402
from abd.verify import iter_jsonl, verify_archive  # noqa: E402

SIZES = [10, 100, 1_000, 10_000, 100_000]
PROTOCOL = {10: (20, 200), 100: (20, 200), 1_000: (20, 200), 10_000: (5, 20), 100_000: (2, 5)}
IN_MEMORY_MAX = 10_000
ASSETS = 10
DELTA_S = 10**9  # timeliness bound irrelevant for a synthetic clock; checked separately in tests


def percentile(data, p):
    s = sorted(data)
    k = (len(s) - 1) * p / 100
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (k - f) * (s[c] - s[f])


def build(size, outdir):
    path = os.path.join(outdir, f'archive-{size}.jsonl')
    # Construction is outside the timer; a non-durable store keeps build time short.
    import abd.fixture as fx
    from abd.state import ManagedStateStore
    orig = fx.ManagedStateStore
    fx.ManagedStateStore = lambda p: ManagedStateStore(p, durable=False)
    state_path = os.path.join(outdir, f'state-{size}.sqlite')
    for stale in (state_path, state_path + '-wal', state_path + '-shm'):
        if os.path.exists(stale):
            os.remove(stale)
    try:
        store = make_store(state_path, assets=ASSETS)
    finally:
        fx.ManagedStateStore = orig
    writer = JsonlArchiveWriter(path)
    clock = TestClock()
    system = make_system(store=store, clock=clock, sink=writer)
    t0 = time.monotonic()
    for i in range(size):
        asset = f'svc-internal-{(i % ASSETS) + 1:02d}' if i % ASSETS else 'svc-internal-01'
        cur = system.store.read_asset(asset)['config']['profile_id']
        target = HYBRID if cur != HYBRID else PQC
        tx = system.run(asset, target, endpoints=READY_ENDPOINTS)
        assert tx.status == 'closed', tx.error
        clock.advance(1)
    build_s = time.monotonic() - t0
    writer.close()
    store.close()
    meta = {
        'log_id': system.log_id,
        'now': clock.now(),
        'trust': system.trust.to_json(),
        'registry': system.registry.to_json(),
        'checkpoint': system.retained_checkpoint(),
    }
    with open(os.path.join(outdir, f'verifier-inputs-{size}.json'), 'w') as fh:
        json.dump(meta, fh)
    return path, meta, build_s, writer.bytes


def _registry_from_meta(meta):
    from abd.policy import PolicyRegistry, default_policy
    reg = PolicyRegistry()
    for v in meta['registry']['versions']:
        reg.register(default_policy(int(v)), activate=(int(v) == meta['registry']['active_version']))
    return reg


def verify_streaming(path, meta):
    return verify_archive(iter_jsonl(path), crypto.TrustConfig.from_json(meta['trust']), _registry_from_meta(meta),
                          meta['log_id'], meta['checkpoint'], meta['now'], DELTA_S)


def verify_in_memory(records, meta):
    return verify_archive(records, crypto.TrustConfig.from_json(meta['trust']), _registry_from_meta(meta),
                          meta['log_id'], meta['checkpoint'], meta['now'], DELTA_S)


def child_rss_mib(path, inputs_path):
    """Run one streaming verification in a fresh process; the child reports its own peak RSS.

    The child reads VmHWM from /proc/self/status, the high-water mark of its own
    address space.  getrusage() is not used: on Linux the ru_maxrss of a process
    is carried across execve() (the kernel folds the pre-exec address space into
    it), so a child spawned from a large parent inherits the parent's peak, and
    RUSAGE_CHILDREN in the parent has the same defect."""
    code = (
        'import json,sys,resource; sys.path.insert(0,%r); from bench.bench_scaling import verify_streaming; '
        'meta=json.load(open(%r)); r=verify_streaming(%r, meta); assert r.ok, r.failures; '
        'hwm=[l for l in open("/proc/self/status") if l.startswith("VmHWM:")]; '
        'kib=int(hwm[0].split()[1]) if hwm else resource.getrusage(resource.RUSAGE_SELF).ru_maxrss; '
        'print("RESULT", r.records, kib)'
        % (os.path.join(os.path.dirname(__file__), '..'), inputs_path, path)
    )
    t0 = time.monotonic()
    out = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, check=True)
    wall = time.monotonic() - t0
    line = [l for l in out.stdout.splitlines() if l.startswith('RESULT')][-1].split()
    return int(line[2]) / 1024, wall, int(line[1])


def rss_only(outdir):
    """Re-measure fresh-process peak RSS for archives already built; update scaling_results.json."""
    archdir = os.path.join(outdir, 'archives')
    p = os.path.join(outdir, 'scaling_results.json')
    d = json.load(open(p))
    for row in d['results']:
        n = row['transactions']
        rss, wall, cnt = child_rss_mib(os.path.join(archdir, f'archive-{n}.jsonl'),
                                       os.path.join(archdir, f'verifier-inputs-{n}.json'))
        assert cnt == n
        row['fresh_process_streaming'] = {'peak_rss_mib': rss, 'wall_s_including_startup': wall,
                                          'measured_by': 'child /proc/self/status VmHWM'}
        print(f'{n:>8,}: fresh-process peak RSS {rss:.1f} MiB (wall {wall:.1f}s)', flush=True)
    json.dump(d, open(p, 'w'), indent=2)


def timed(fn, warmup, reps):
    for _ in range(warmup):
        r = fn()
        assert r.ok, r.failures
    samples = []
    for _ in range(reps):
        t0 = time.monotonic()
        r = fn()
        samples.append(time.monotonic() - t0)
        assert r.ok, r.failures
    return samples


def main(outdir, sizes=None):
    os.makedirs(outdir, exist_ok=True)
    archdir = os.path.join(outdir, 'archives')
    os.makedirs(archdir, exist_ok=True)
    results = []
    import envinfo
    for size in sizes or SIZES:
        warm, reps = PROTOCOL[size]
        conditions = envinfo.collect(wait_quiet=True)['run_conditions']
        print(f'== {size:,} transactions: building...', flush=True)
        path, meta, build_s, nbytes = build(size, archdir)
        inputs = os.path.join(archdir, f'verifier-inputs-{size}.json')
        print(f'   built in {build_s:.1f}s, {nbytes / 2**20:.2f} MiB; streaming verify x{warm}+{reps}...', flush=True)
        st = timed(lambda: verify_streaming(path, meta), warm, reps)
        row = {
            'transactions': size, 'archive_mib': nbytes / 2**20, 'build_s': build_s,
            'warmup': warm, 'timed': reps, 'run_conditions': conditions,
            'streaming': {'median_s': statistics.median(st), 'p95_s': percentile(st, 95) if reps >= 20 else None,
                          'samples_s': st},
        }
        if size <= IN_MEMORY_MAX:
            records = list(iter_jsonl(path))
            im = timed(lambda: verify_in_memory(records, meta), warm, reps)
            row['in_memory'] = {'median_s': statistics.median(im), 'p95_s': percentile(im, 95) if reps >= 20 else None,
                                'samples_s': im}
            del records
        rss, wall, n = child_rss_mib(path, inputs)
        assert n == size
        # conditions at the end as well, so that a power or load change during the measurement is visible
        row['run_conditions_end'] = envinfo.collect()['run_conditions']
        row['fresh_process_streaming'] = {'peak_rss_mib': rss, 'wall_s_including_startup': wall,
                                          'measured_by': 'child /proc/self/status VmHWM'}
        results.append(row)
        print(f"   streaming median {row['streaming']['median_s']:.4f}s; fresh-process peak RSS {rss:.1f} MiB", flush=True)
        with open(os.path.join(outdir, 'scaling_results.json'), 'w') as fh:
            json.dump({'protocol': PROTOCOL, 'assets': ASSETS, 'results': results}, fh, indent=2)
    return results


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'results', 'v2')
    if '--rss-only' in sys.argv:
        rss_only(out)
    else:
        sizes = [int(s) for s in sys.argv[2:]] or None
        main(out, sizes)
