"""Like-for-like memory comparison with the earlier record-construction prototype's checker.

The earlier prototype reported an 11,499.7 MiB peak for 10^5 transactions, but that figure was the
ru_maxrss of one process that also built the archive and held a full json.dumps serialization of it;
it is not the checker's own memory.  This driver measures the earlier checker the same way as the
streaming verifier (bench/bench_scaling.py): the archive is built by the prototype and written to disk,
then a FRESH process loads it and runs the prototype's full_verify, and reports VmHWM of its own
address space.  The earlier checker is an in-memory design (it verifies a decoded list), so loading
the archive is part of its footprint, just as decoding is part of the streaming verifier's timing.

An address-space limit (default 12 GiB) keeps an oversized run from exhausting the machine; a run that
hits it is recorded as exceeding the limit.

Usage: python3 bench/bench_oldchecker.py OUTDIR [SIZES...]
"""

import json
import os
import resource
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PROTO = os.path.join(HERE, '..', 'prototype')
sys.path.insert(0, PROTO)
sys.path.insert(0, HERE)

import envinfo  # noqa: E402

SIZES = [1_000, 10_000, 100_000]
AS_LIMIT_BYTES = 12 * 2**30

CHILD = r'''
import json, sys, time
sys.path.insert(0, {proto!r})
from benchmark_scaling import full_verify
keys = {{role: {{'public_key': bytes.fromhex(h)}} for role, h in json.load(open({keys!r})).items()}}
t0 = time.monotonic()
with open({archive!r}) as fh:
    archive = [json.loads(line) for line in fh]
ok, msg = full_verify(archive, keys, archive[-1]['checkpoint'])
wall = time.monotonic() - t0
hwm = [l for l in open('/proc/self/status') if l.startswith('VmHWM:')][0].split()[1]
print('RESULT', ok, len(archive), hwm, round(wall, 2), msg)
'''


def build(n, outdir):
    from transaction import create_transaction, generate_role_keys
    keys = generate_role_keys()
    path = os.path.join(outdir, f'old-archive-{n}.jsonl')
    prev = '0' * 96
    t0 = time.monotonic()
    with open(path, 'w') as fh:
        for i in range(n):
            import uuid
            rec = create_transaction(keys, str(uuid.uuid4()), prev, i)
            prev = rec['envelope']['digest']
            fh.write(json.dumps({k: rec[k] for k in ('tx_id', 'source', 'authorization', 'executor', 'outcome',
                                                    'envelope', 'checkpoint')}) + '\n')
    keys_path = os.path.join(outdir, f'old-keys-{n}.json')
    with open(keys_path, 'w') as fh:
        json.dump({role: k['public_key'].hex() for role, k in keys.items()}, fh)
    return path, keys_path, time.monotonic() - t0


def measure(archive, keys_path):
    code = CHILD.format(proto=PROTO, keys=keys_path, archive=archive)

    def limit():
        resource.setrlimit(resource.RLIMIT_AS, (AS_LIMIT_BYTES, AS_LIMIT_BYTES))
    out = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, preexec_fn=limit)
    line = [l for l in out.stdout.splitlines() if l.startswith('RESULT')]
    if out.returncode != 0 or not line:
        return {'completed': False, 'exceeded_limit': 'MemoryError' in out.stderr or out.returncode < 0,
                'returncode': out.returncode, 'stderr_tail': out.stderr[-600:]}
    _, ok, n, hwm_kib, wall, *msg = line[-1].split()
    return {'completed': True, 'verified': ok == 'True', 'records': int(n), 'peak_rss_mib': int(hwm_kib) / 1024,
            'wall_s_load_and_verify': float(wall), 'message': ' '.join(msg)}


def main(outdir, sizes=None):
    os.makedirs(outdir, exist_ok=True)
    rows = []
    for n in sizes or SIZES:
        conditions = envinfo.collect(wait_quiet=True)['run_conditions']
        print(f'== {n:,} transactions (earlier prototype): building...', flush=True)
        archive, keys_path, build_s = build(n, outdir)
        size_mib = os.path.getsize(archive) / 2**20
        res = measure(archive, keys_path)
        res.update({'transactions': n, 'archive_mib': size_mib, 'build_s': build_s, 'run_conditions': conditions,
                    'address_space_limit_gib': AS_LIMIT_BYTES / 2**30})
        rows.append(res)
        print(f"   {size_mib:.0f} MiB; " + (f"fresh-process peak RSS {res['peak_rss_mib']:.1f} MiB, verified "
                                            f"{res['verified']}" if res['completed'] else f"did not complete: {res}"),
              flush=True)
        os.remove(archive)
        os.remove(keys_path)
        with open(os.path.join(outdir, 'oldchecker_results.json'), 'w') as fh:
            json.dump({'method': 'fresh process, VmHWM, includes loading/decoding the archive; earlier '
                                 'prototype full_verify (in-memory design)', 'results': rows}, fh, indent=2)
    return rows


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, '..', 'results', 'v2', 'oldchecker')
    main(out, [int(s) for s in sys.argv[2:]] or None)
